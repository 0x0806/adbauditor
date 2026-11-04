'use strict';
/**
 * Tests a deployed copy of ADB Auditor in headless Chrome and (optionally) captures screenshots of it.
 *
 *   node scripts/site-check.js [--url https://0x0806.github.io/adbauditor/] [--screenshots img/screenshots]
 *
 * Checks: every asset loads, no console errors / CSP violations, manifest + service worker, offline reload,
 * custom 404 page, and a connected smoke test against a fake WebUSB device (nothing real is touched).
 * Screenshots show the live site with clearly fake demo data (a mock phone).
 *
 * Created by Sandeep Wawdane; enhanced by 0x0806.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : def; };
let URL_BASE = opt('url', 'https://0x0806.github.io/adbauditor/').replace(/\/?$/, '/');
const SERVE = args.includes('--serve');     // test the working tree through a local static server instead of a deployed URL
const SHOT_DIR = opt('screenshots', null);
const ROOT = path.resolve(__dirname, '..');

const CHROME = ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable'].find(c => spawnSync('which', [c]).status === 0);
if (!CHROME) { console.log('SKIP: no Chrome/Chromium found'); process.exit(0); }

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (name, ok, extra = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`); if (!ok) failures++; };

async function launch() {
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'absite-'));
    const port = 9800 + Math.floor(Math.random() * 150);
    const proc = spawn(CHROME, ['--headless=new', '--no-sandbox', '--disable-gpu', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--window-size=1440,900', 'about:blank'], { stdio: 'ignore' });
    let targets;
    for (let i = 0; i < 60; i++) {
        try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (targets.find(t => t.type === 'page')) break; } catch (e) { /* not up yet */ }
        await sleep(200);
    }
    const page = targets.find(t => t.type === 'page');
    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise(r => ws.addEventListener('open', r));
    let id = 0; const pending = new Map();
    const events = { responses: [], failed: [], errors: [], logs: [] };
    ws.addEventListener('message', (m) => {
        const msg = JSON.parse(m.data);
        if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); return; }
        if (msg.method === 'Network.responseReceived') events.responses.push({ url: msg.params.response.url, status: msg.params.response.status, type: msg.params.type });
        else if (msg.method === 'Network.loadingFailed') events.failed.push({ id: msg.params.requestId, text: msg.params.errorText, blocked: msg.params.blockedReason });
        else if (msg.method === 'Runtime.exceptionThrown') events.errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
        else if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') events.logs.push(msg.params.entry.text + ' ' + (msg.params.entry.url || ''));
        else if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') events.logs.push(msg.params.args.map(a => a.value || a.description).join(' '));
    });
    const send = (method, params = {}) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
    const evalJs = async (expr) => {
        const r = await Promise.race([send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }),
            new Promise((_, rej) => setTimeout(() => rej(new Error('evalJs timed out: ' + expr.slice(0, 100))), 60000))]);
        if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || 'eval failed');
        return r.result.result.value;
    };
    const waitFor = async (expr, label, ms = 20000) => {
        const end = Date.now() + ms;
        while (Date.now() < end) { try { if (await evalJs(expr)) return true; } catch (e) { /* retry */ } await sleep(150); }
        check('wait: ' + label, false, 'timed out'); return false;
    };
    const cleanup = () => { try { proc.kill('SIGKILL'); } catch (e) { /* gone */ } try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* ignore */ } };
    return { send, evalJs, waitFor, events, cleanup };
}

async function shot(c, name) {
    if (!SHOT_DIR) return;
    await c.evalJs('document.fonts ? document.fonts.ready.then(() => true) : true');
    await c.evalJs(`document.querySelectorAll('.toast').forEach(t => t.remove()); true`);
    await sleep(700);                                   // let transitions settle
    const r = await c.send('Page.captureScreenshot', { format: 'png' });
    fs.mkdirSync(SHOT_DIR, { recursive: true });
    fs.writeFileSync(path.join(SHOT_DIR, name + '.png'), Buffer.from(r.result.data, 'base64'));
    console.log('SHOT  ' + name + '.png');
}

function startLocalServer() {
    const http = require('http');
    const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json', '.css': 'text/css', '.txt': 'text/plain' };
    const srv = http.createServer((req, res) => {
        const u = decodeURIComponent(new URL(req.url, 'http://x').pathname);
        const file = path.join(ROOT, u === '/' ? 'index.html' : u);
        if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
            res.writeHead(404, { 'content-type': 'text/html' });          // like GitHub Pages: serve the custom 404 page
            return res.end(fs.readFileSync(path.join(ROOT, '404.html')));
        }
        res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
        fs.createReadStream(file).pipe(res);
    });
    return new Promise(r => srv.listen(0, '127.0.0.1', () => r(srv)));
}

(async () => {
    if (SERVE) { const srv = await startLocalServer(); URL_BASE = `http://127.0.0.1:${srv.address().port}/`; process.on('exit', () => srv.close()); }
    console.log('Target: ' + URL_BASE + '\n');
    const external = await launch();
    const c = external;
    await c.send('Network.enable'); await c.send('Runtime.enable'); await c.send('Page.enable'); await c.send('Log.enable');
    await c.send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });

    // ===== 1. plain load of the live site (no mock) =====
    await c.send('Page.navigate', { url: URL_BASE });
    await c.waitFor(`document.readyState==='complete' && !!window.app`, 'site loaded');
    await sleep(1500);
    const own = c.events.responses.filter(r => r.url.startsWith(URL_BASE));
    check('index and all scripts returned HTTP 200', own.length > 0 && own.every(r => r.status === 200), JSON.stringify(own.filter(r => r.status !== 200)));
    for (const f of ['js/utils.js', 'js/adb-core.js', 'js/security-auditor.js', 'js/sqlite-reader.js', 'js/apk-analyzer.js', 'js/toolkit.js', 'js/app.js', 'js/tools-ui.js']) {
        check('loads ' + f, own.some(r => r.url.endsWith(f) && r.status === 200));
    }
    check('landing page shows both authors', await c.evalJs(`/Sandeep Wawdane/.test(document.body.innerText) && /0x0806/.test(document.body.innerText)`));
    check('page title is set', await c.evalJs(`/ADB Auditor/.test(document.title)`));
    check('Content-Security-Policy meta present', await c.evalJs(`!!document.querySelector('meta[http-equiv="Content-Security-Policy"]')`));
    check('GitHub link points to the 0x0806 repository', await c.evalJs(`[...document.querySelectorAll('a')].some(a=>a.href==='https://github.com/0x0806/adbauditor')`));
    check('exposes the app API without errors', await c.evalJs(`typeof window.app.connect==='function' && typeof window.__AB==='object'`));
    const csp = c.events.logs.filter(l => /Content Security Policy|Refused to/i.test(l));
    check('no CSP violations', csp.length === 0, csp.join(' | '));
    const noisy = c.events.logs.filter(l => !/favicon/.test(l));
    check('no console errors', noisy.length === 0 && c.events.errors.length === 0, noisy.concat(c.events.errors).join(' | '));
    const failed = c.events.failed.filter(f => !/ERR_ABORTED/.test(f.text));
    check('no failed network requests', failed.length === 0, JSON.stringify(failed));
    check('WebUSB available (no "unsupported" banner)', await c.evalJs(`!document.querySelector('.ab-banner')`));
    await shot(c, 'landing');

    // ===== 2. manifest + service worker + offline =====
    const mf = await c.evalJs(`fetch('manifest.webmanifest').then(r=>r.json()).then(j=>({name:j.name,icon:j.icons&&j.icons[0]&&j.icons[0].src}))`);
    check('web app manifest is valid', mf && mf.name === 'ADB Auditor' && !!mf.icon, JSON.stringify(mf));
    await c.waitFor(`navigator.serviceWorker.getRegistration().then(r=>!!(r&&r.active))`, 'service worker active', 25000);
    check('service worker registered and active', await c.evalJs(`navigator.serviceWorker.getRegistration().then(r=>!!(r&&r.active))`));
    await c.send('Page.reload');
    await c.waitFor(`document.readyState==='complete' && !!navigator.serviceWorker.controller`, 'page controlled by SW', 25000);
    check('precache contains the app shell', await c.evalJs(`caches.keys().then(async ks=>{const k=ks.find(x=>x.startsWith('adbauditor-')); if(!k) return false; const c=await caches.open(k); const reqs=await c.keys(); const names=reqs.map(r=>new URL(r.url).pathname); return ['js/app.js','js/tools-ui.js','js/apk-analyzer.js','index.html'].every(n=>names.some(p=>p.endsWith(n)||p.endsWith('/')))})`));
    await c.send('Network.emulateNetworkConditions', { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 });
    await c.send('Page.reload');
    await c.waitFor(`document.readyState==='complete' && !!window.app`, 'offline reload', 25000);
    check('app works offline (served from the service worker cache)', await c.evalJs(`!!window.app && /ADB Auditor/.test(document.title)`));
    await c.send('Network.emulateNetworkConditions', { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });

    // ===== 3. custom 404 page =====
    const nf = await fetch(URL_BASE + 'definitely-not-here').then(async r => ({ status: r.status, body: await r.text() }));
    check('unknown path returns the custom 404 page', nf.status === 404 && /404/.test(nf.body) && /ADB Auditor/.test(nf.body), nf.status + '');
    check('robots.txt served', (await fetch(URL_BASE + 'robots.txt')).status === 200);

    // ===== 4. connected smoke test against a fake device (the site code, a mock phone) =====
    const mockSrc = fs.readFileSync(path.join(ROOT, 'tests/helpers/mock-device.js'), 'utf8');
    const pageMock = fs.readFileSync(path.join(ROOT, 'tests/e2e/page-mock.js'), 'utf8');
    const { dump } = require(path.join(ROOT, 'tests/fixtures/dumpsys-package'));
    const B = require(path.join(ROOT, 'tests/helpers/apk-builder'));
    const apk = B.buildApk({ manifest: { targetSdk: 28 } }).toString('base64');
    let dbB64 = '';
    const dbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'absitedb-'));
    if (spawnSync('python3', [path.join(ROOT, 'tests/helpers/make-sqlite.py'), dbDir]).status === 0) dbB64 = fs.readFileSync(path.join(dbDir, 'basic.db')).toString('base64');
    fs.rmSync(dbDir, { recursive: true, force: true });
    const boot = `window.__DEMO=true;(function(){var module={exports:{}};${mockSrc};window.__MOCK_MODULE=module.exports;})();window.__FIXTURES={dump:${JSON.stringify(dump())}};window.__APK_B64=${JSON.stringify(apk)};window.__DB_B64=${JSON.stringify(dbB64)};window.__APK_EVIL_B64=${JSON.stringify(apk)};window.__DB_EVIL_B64='';${pageMock}`;
    await c.send('Page.addScriptToEvaluateOnNewDocument', { source: boot });
    await c.send('Page.navigate', { url: URL_BASE });
    await c.waitFor(`document.readyState==='complete' && !!window.app`, 'site reloaded with mock device');
    await c.evalJs(`document.getElementById('connectBtn').click()`);
    await c.waitFor(`document.getElementById('statusText').textContent==='Connected'`, 'connected to the fake device');
    await c.waitFor(`document.querySelectorAll('#statsGrid .stat-card').length===8 && /android/i.test(document.getElementById('statsGrid').innerText)`, 'overview loaded');
    check('hosted app connects to the fake device and shows the overview', await c.evalJs(`/Pixel 9 Pro/.test(document.getElementById('propList').innerText)`));
    await shot(c, 'overview');

    await c.evalJs(`document.querySelector('[data-section=apps]').click()`);
    await c.waitFor(`document.querySelectorAll('#appList .app-item').length===3`, 'apps listed');
    await shot(c, 'apps');

    await c.evalJs(`document.querySelector('[data-section=files]').click()`);
    await c.waitFor(`document.querySelectorAll('#fileList .file-item').length===4`, 'files listed');
    await shot(c, 'files');

    await c.evalJs(`document.querySelector('[data-section=security]').click()`);
    await c.evalJs(`app.switchSecurityTab('fullScan')`);
    await c.waitFor(`document.querySelectorAll('#fullScanSelect option').length>1`, 'scan select');
    await c.evalJs(`document.getElementById('fullScanSelect').value='com.example.app'; app.runFullScan()`);
    await c.waitFor(`!!document.querySelector('#fullScanResults .report-actions')`, 'scan finished', 40000);
    check('full scan runs on the hosted site and produces a risk score', await c.evalJs(`/Risk:/.test(document.getElementById('fullScanResults').innerText)`));
    await c.evalJs(`document.getElementById('fullScanResults').scrollIntoView({block:'start'}); window.scrollBy(0, -120)`);
    await shot(c, 'security-scan');

    await c.evalJs(`document.querySelector('[data-section=tools]').click()`);
    await c.waitFor(`!!document.querySelector('[data-ttab=apk]')`, 'tools');
    await c.evalJs(`document.querySelector('[data-ttab=apk]').click()`);
    await c.waitFor(`document.querySelectorAll('#apkSel option').length>1`, 'apk select');
    await c.evalJs(`document.getElementById('apkSel').value='com.example.app'; document.querySelector('[data-do=apkDevice]').click()`);
    await c.waitFor(`!!document.querySelector('#apkReport .result-box')`, 'apk analysed', 40000);
    check('APK analyzer works on the hosted site', await c.evalJs(`/com\\.example\\.app/.test(document.getElementById('apkReport').innerText)`));
    await shot(c, 'apk-analyzer');

    if (dbB64) {
        await c.evalJs(`document.querySelector('[data-ttab=db]').click()`);
        await c.evalJs(`document.getElementById('dbPath').value='/sdcard/test.db'; document.querySelector('[data-do=dbDevice]').click()`);
        await c.waitFor(`document.querySelectorAll('[data-do=dbTable]').length===2`, 'db opened');
        await c.evalJs(`[...document.querySelectorAll('[data-do=dbTable]')].find(b=>b.dataset.t==='users').click()`);
        check('SQLite viewer works on the hosted site', await c.evalJs(`document.querySelectorAll('#dbView tbody tr').length===12`));
        await shot(c, 'sqlite-viewer');
    }

    await c.evalJs(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true}))`);
    check('command palette opens', await c.evalJs(`document.querySelectorAll('.ab-palette-item').length>5`));
    await shot(c, 'command-palette');
    await c.evalJs(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))`);

    check('no uncaught exceptions during the connected session', c.events.errors.length === 0, c.events.errors.join(' | '));
    const noise = c.events.logs.filter(l => !/favicon|\[ADB ERROR\]/.test(l));
    check('no console errors during the connected session', noise.length === 0, noise.join(' | '));

    c.cleanup();
    console.log(failures ? `\n${failures} check(s) FAILED` : '\nAll site checks passed');
    process.exit(failures ? 1 : 0);
})().catch((e) => { console.error('site-check crashed:', e); process.exit(2); });
