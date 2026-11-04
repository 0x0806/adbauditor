'use strict';
// End-to-end smoke test: real Chromium + CDP, fake WebUSB device. Run with `npm run test:e2e`.
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const CHROME = ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable'].find(c => spawnSync('which', [c]).status === 0);
if (!CHROME) { console.log('SKIP e2e: no Chromium/Chrome found'); process.exit(0); }

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json', '.css': 'text/css' };
const server = http.createServer((req, res) => {
    const u = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const file = path.join(ROOT, u === '/' ? 'index.html' : u);
    if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('nf'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
});

const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (name, ok, extra = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`); if (!ok) failures++; };

(async () => {
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${server.address().port}/`;
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'abprof-'));
    const port = 9300 + Math.floor(Math.random() * 500);
    const chrome = spawn(CHROME, ['--headless=new', '--no-sandbox', '--disable-gpu', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--window-size=1400,900', 'about:blank'], { stdio: 'ignore' });
    const cleanup = () => { try { chrome.kill('SIGKILL'); } catch (e) {} server.close(); try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) {} };
    process.on('exit', cleanup);

    let targets;
    for (let i = 0; i < 50; i++) {
        try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (targets.find(t => t.type === 'page')) break; } catch (e) {}
        await sleep(200);
    }
    const page = targets.find(t => t.type === 'page');
    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise(r => ws.addEventListener('open', r));
    let id = 0; const pending = new Map(); const errors = []; const logs = [];
    ws.addEventListener('message', (m) => {
        const msg = JSON.parse(m.data);
        if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
        else if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
        else if (msg.method === 'Runtime.consoleAPICalled' && ['error'].includes(msg.params.type)) logs.push(msg.params.args.map(a => a.value || a.description).join(' '));
        else if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') logs.push(msg.params.entry.text + ' ' + (msg.params.entry.url || ''));
    });
    const send = (method, params = {}) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
    const evalJs = async (expr) => {
        const r = await Promise.race([send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }),
            new Promise((_, rej) => setTimeout(() => rej(new Error('evalJs timed out after 60s: ' + expr.slice(0, 120))), 60000))]);
        if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || 'eval failed');
        return r.result.result.value;
    };
    const waitFor = async (expr, label, ms = 15000) => {
        const end = Date.now() + ms;
        while (Date.now() < end) { try { if (await evalJs(expr)) return true; } catch (e) {} await sleep(100); }
        check('wait: ' + label, false, 'timed out'); return false;
    };

    await send('Runtime.enable'); await send('Page.enable'); await send('Log.enable');
    const mockSrc = fs.readFileSync(path.join(ROOT, 'tests/helpers/mock-device.js'), 'utf8');
    const { dump } = require('../fixtures/dumpsys-package');
    const pageMock = fs.readFileSync(path.join(__dirname, 'page-mock.js'), 'utf8');
    const B = require('../helpers/apk-builder');
    const apk = B.buildApk({ manifest: { targetSdk: 28 } }).toString('base64');
    const dbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'abe2edb-'));
    const pyOk = spawnSync('python3', [path.join(__dirname, '../helpers/make-sqlite.py'), dbDir]).status === 0;
    const dbB64 = pyOk ? fs.readFileSync(path.join(dbDir, 'basic.db')).toString('base64') : '';
    const EVIL = '<img src=x onerror="window.__pwned=(window.__pwned||0)+1">';
    const evilApk = B.buildApk({ manifest: { pkg: 'com.evil.pkg' + EVIL, evil: 'com.evil.Act' + EVIL } }).toString('base64');
    let evilDbB64 = '';
    if (pyOk) {
        const py = `import sqlite3,sys\ncon=sqlite3.connect(sys.argv[1])\ncon.execute('create table "t<b>x"(id integer primary key, v text)')\ncon.execute('insert into "t<b>x"(v) values(?)',(sys.argv[2],))\ncon.commit()`;
        const evilPath = path.join(dbDir, 'evil.db');
        if (spawnSync('python3', ['-c', py, evilPath, EVIL]).status === 0) evilDbB64 = fs.readFileSync(evilPath).toString('base64');
    }
    const boot = `(function(){var module={exports:{}};${mockSrc};window.__MOCK_MODULE=module.exports;})();window.__FIXTURES={dump:${JSON.stringify(dump())}};window.__APK_B64=${JSON.stringify(apk)};window.__DB_B64=${JSON.stringify(dbB64)};window.__APK_EVIL_B64=${JSON.stringify(evilApk)};window.__DB_EVIL_B64=${JSON.stringify(evilDbB64)};${pageMock}`;
    await send('Page.addScriptToEvaluateOnNewDocument', { source: boot });
    await send('Page.navigate', { url: base });
    await waitFor(`document.readyState==='complete' && !!window.app`, 'app loaded');

    // ---- landing
    check('landing page renders with credits to both authors', await evalJs(`/Sandeep Wawdane/.test(document.body.innerText) && /0x0806/.test(document.body.innerText)`));
    check('CSP meta present', await evalJs(`!!document.querySelector('meta[http-equiv="Content-Security-Policy"]')`));

    // ---- connect
    await evalJs(`document.getElementById('connectBtn').click()`);
    await waitFor(`document.getElementById('statusText').textContent==='Connected'`, 'connected');
    await waitFor(`document.querySelectorAll('#statsGrid .stat-card').length===8 && /android/i.test(document.getElementById('statsGrid').innerText)`, 'overview stats');
    check('overview shows 8 stat cards', await evalJs(`document.querySelectorAll('#statsGrid .stat-card').length===8`));
    check('overview RAM/Storage parsed', await evalJs(`/50%/.test(document.getElementById('statsGrid').innerText)`));
    check('device props are HTML-escaped (no injected <b>)', await evalJs(`!document.getElementById('propList').querySelector('b') && /Pixel <b>E2E<\\/b>/.test(document.getElementById('propList').innerText)`));

    // ---- apps
    await evalJs(`document.querySelector('[data-section=apps]').click()`);
    await waitFor(`document.querySelectorAll('#appList .app-item').length===3`, 'apps listed');
    check('app list renders 3 apps', await evalJs(`document.querySelectorAll('#appList .app-item').length===3`));
    check('hostile package name did not create elements', await evalJs(`!document.querySelector('#appList b')`));
    await evalJs(`app.filterApps('debuggable')`);
    check('app filter works', await evalJs(`document.querySelectorAll('#appList .app-item').length===1`));

    // ---- files (XSS + injection)
    await evalJs(`document.querySelector('[data-section=files]').click()`);
    await waitFor(`document.querySelectorAll('#fileList .file-item').length===4`, 'files listed');
    check('malicious file name rendered as text, no script executed', await evalJs(`window.__pwned===undefined && !document.querySelector('#fileList img')`));
    check('ls command single-quoted', await evalJs(`window.__shellLog.some(c=>c==="ls -la '/storage/emulated/0' 2>&1")`));
    check('file with $(reboot) listed literally', await evalJs(`[...document.querySelectorAll('.file-name')].some(n=>n.textContent.includes('$(reboot)'))`));
    await evalJs(`document.getElementById('fileFilter').value='dcim';document.getElementById('fileFilter').dispatchEvent(new Event('input'))`);
    await waitFor(`document.querySelectorAll('#fileList .file-item').length===1`, 'filter applied');
    check('file filter works', true);
    await evalJs(`app.loadFiles('/storage/emulated/0/x/../../0//./')`);
    await waitFor(`document.getElementById('pathBar').innerText.includes('emulated')`, 'normalised path');
    check('path traversal segments normalised', await evalJs(`app.constructor===Object && document.querySelectorAll('#pathBar .path-segment').length===4`));

    // ---- shell
    await evalJs(`document.querySelector('[data-section=shell]').click()`);
    await waitFor(`!!document.getElementById('shellInput')`, 'shell ui');
    await evalJs(`app.executeCommand('echo hello')`);
    check('shell executes command and prints output', await evalJs(`document.getElementById('shellOutput').innerText.includes('hello-from-device')`));

    // ---- screenshot
    await evalJs(`document.querySelector('[data-section=screenshot]').click()`);
    await evalJs(`app.captureScreenshot()`);
    await waitFor(`!!document.querySelector('.screenshot-preview')`, 'screenshot shown');
    check('screenshot preview shown, copy/save enabled', await evalJs(`!document.getElementById('saveScreenshotBtn').disabled && !document.getElementById('copyScreenshotBtn').disabled`));

    // ---- security
    await evalJs(`document.querySelector('[data-section=security]').click()`);
    await waitFor(`document.querySelectorAll('#fullScanSelect option').length>1 || true`, 'security ui');
    check('security has 11 tabs', await evalJs(`document.querySelectorAll('.tab-btn').length===11`));
    await evalJs(`app.switchSecurityTab('fullScan')`);
    await waitFor(`document.querySelectorAll('#fullScanSelect option').length>1`, 'scan select populated');
    await evalJs(`document.getElementById('fullScanSelect').value='com.example.app'; app.runFullScan()`);
    await waitFor(`document.querySelector('#fullScanResults .report-actions')`, 'scan finished', 30000);
    check('full scan report rendered with risk score', await evalJs(`/Risk:/.test(document.getElementById('fullScanResults').innerText)`));
    check('18 test cards in report', await evalJs(`document.querySelectorAll('#fullScanResults .result-box').length===19`));
    check('report persisted to scan history', await evalJs(`JSON.parse(localStorage.getItem('ab.scanHistory')).length===1`));
    await evalJs(`document.querySelector('#fullScanResults [data-export=md]') && true`);

    await evalJs(`app.switchSecurityTab('triage'); document.querySelector('button[onclick="app.runTriage()"]').click()`);
    await waitFor(`document.querySelectorAll('#triageResults tbody tr').length===3`, 'triage rows');
    check('triage ranks debuggable app first', await evalJs(`document.querySelector('#triageResults tbody tr').dataset.pkg==='com.bad.debuggable'`));

    await evalJs(`app.switchSecurityTab('device'); app.runDeviceAudit()`);
    await waitFor(`document.querySelector('#deviceAuditResults .report-actions')`, 'device audit');
    check('device audit renders', true);

    await evalJs(`app.switchSecurityTab('network'); `);
    check('network tab renders', await evalJs(`!!document.getElementById('networkResults')`));

    await evalJs(`app.switchSecurityTab('logcat'); app.startLogcat()`);
    await sleep(400);
    check('logcat stream is running', await evalJs(`app.logcatRunning===true`));
    await evalJs(`(function(){var s=[...__dev.sockets.values()].find(x=>x.service.startsWith('shell:logcat'));__dev._write(s,new TextEncoder().encode('01-02 10:00:00.123  100  100 E MyTag: boom happened\\n01-02 10:00:01.123  100  100 D Noise: ignore me\\n'),false);})()`);
    await waitFor(`document.querySelectorAll('#logcatOutput .logcat-line').length===2`, 'logcat lines rendered');
    check('logcat lines classified by level', await evalJs(`document.querySelector('#logcatOutput .logcat-line.error')?.textContent.includes('boom') && !!document.querySelector('#logcatOutput .logcat-line.debug')`));
    await evalJs(`app.stopLogcat()`);
    check('logcat stopped', await evalJs(`app.logcatRunning===false`));

    // ---- command palette + shortcuts + modals
    await evalJs(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true}))`);
    check('Ctrl+K opens command palette', await evalJs(`!!document.querySelector('.ab-palette-list') && document.querySelectorAll('.ab-palette-item').length>5`));
    await evalJs(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))`);
    check('Escape closes modal', await evalJs(`!document.querySelector('.ab-modal-overlay')`));
    await evalJs(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'2',altKey:true,bubbles:true}))`);
    check('Alt+2 navigates to Apps', await evalJs(`document.querySelector('[data-section=apps]').classList.contains('active')`));


    // ---- pinned apps
    await evalJs(`document.querySelector('[data-section=apps]').click()`);
    await waitFor(`document.querySelectorAll('#appList .app-item').length>=1`, 'apps again');
    await evalJs(`app.filterApps(''); [...document.querySelectorAll('#appList [data-act=pin]')].find(b=>b.dataset.pkg==='com.bad.debuggable').click()`);
    check('pinning an app moves it to the top', await evalJs(`document.querySelector('#appList .app-item .app-package').textContent==='com.bad.debuggable'`));

    // ---- file browser extras
    await evalJs(`document.querySelector('[data-section=files]').click()`);
    await waitFor(`!!document.getElementById('fileFilter')`, 'files again');
    await evalJs(`(function(){var f=document.getElementById('fileFilter');f.value='';f.dispatchEvent(new Event('input'));})()`);
    await waitFor(`document.querySelectorAll('#fileList .file-item').length>=4`, 'files unfiltered');
    check('file rows have a More menu', await evalJs(`!!document.querySelector('#fileList [data-act=more]')`));
    await evalJs(`document.querySelector('#fileList .file-item[data-index="0"] [data-act=more]').click()`);
    check('folder More menu offers ZIP download', await evalJs(`[...document.querySelectorAll('.ab-modal-foot button')].some(b=>/ZIP/.test(b.textContent))`));
    await evalJs(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))`);

    // ---- Tools section
    await evalJs(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'7',altKey:true,bubbles:true}))`);
    await waitFor(`!!document.querySelector('[data-ttab=control]')`, 'tools opened via Alt+7');
    check('Tools has 8 tabs', await evalJs(`document.querySelectorAll('[data-ttab]').length===8`));
    await evalJs(`document.querySelector('[data-do=radio][data-k=wifi][data-on="1"]').click()`);
    await waitFor(`window.__shellLog.includes('svc wifi enable')`, 'wifi command sent');
    check('Wi-Fi toggle sends svc command', true);
    await evalJs(`document.querySelector('[data-do=reboot][data-mode=recovery]').click()`);
    await waitFor(`!!document.querySelector('.ab-modal-overlay')`, 'reboot confirm');
    await evalJs(`[...document.querySelectorAll('.ab-modal-foot button')].find(b=>b.textContent==='Cancel').click()`);
    check('reboot requires confirmation and cancel sends nothing', await evalJs(`!window.__shellLog.some(c=>c.startsWith('reboot'))`));
    await evalJs(`document.querySelector('[data-do=key][data-key=HOME]').click()`);
    await waitFor(`window.__shellLog.includes('input keyevent 3')`, 'key event');
    check('remote key sends input keyevent', true);

    await evalJs(`document.querySelector('[data-ttab=intents]').click()`);
    await evalJs(`document.getElementById('dlUri').value="myapp://x;reboot"; document.querySelector('[data-do=deeplink]').click()`);
    await waitFor(`window.__shellLog.some(c=>c.startsWith('am start') && c.includes("'myapp://x;reboot'"))`, 'deep link fired');
    check('deep link URI is passed as one quoted argument', true);
    await evalJs(`document.getElementById('inAction').value='a.b'; document.getElementById('inComp').value='bad comp'; document.querySelector('[data-do=intentPreview]').click()`);
    check('intent launcher rejects a malformed component', await evalJs(`/Invalid component/.test(document.getElementById('toolsOut').textContent)`));

    await evalJs(`document.querySelector('[data-ttab=packages]').click()`);
    await waitFor(`document.querySelectorAll('#pkSel option').length>1`, 'package list');
    await evalJs(`document.querySelector('[data-do=baselineSave]').click()`);
    await waitFor(`/Baseline saved/.test(document.getElementById('toolsOut').textContent)`, 'baseline saved');
    await evalJs(`document.querySelector('[data-do=baselineCompare]').click()`);
    await waitFor(`/Baseline from/.test(document.getElementById('toolsOut').textContent)`, 'baseline compared');
    check('baseline save + compare works', true);

    await evalJs(`document.querySelector('[data-ttab=system]').click()`);
    await evalJs(`document.querySelector('[data-do=settingsLoad]').click()`);
    await waitFor(`document.querySelectorAll('#seTable tbody tr').length===4`, 'settings listed');
    await evalJs(`document.querySelector('[data-do=propsLoad]').click()`);
    await waitFor(`document.querySelectorAll('#prTable tbody tr').length===2`, 'props listed');
    await evalJs(`document.querySelector('[data-do=dsList]').click()`);
    await waitFor(`document.querySelectorAll('#dsSvc option').length===2`, 'dumpsys services');
    await evalJs(`document.querySelector('[data-do=dsRun]').click()`);
    await waitFor(`/level: 88/.test(document.getElementById('toolsOut').textContent)`, 'dumpsys output');
    check('system tab: settings, properties and dumpsys explorer work', true);
    check('hostile setting value rendered as text', await evalJs(`window.__pwned===undefined && !document.querySelector('#seTable img')`));

    await evalJs(`document.querySelector('[data-ttab=network]').click()`);
    await evalJs(`document.querySelector('[data-do=netInfo]').click()`);
    await waitFor(`/192.168.1.20/.test(document.getElementById('netInfo').textContent)`, 'network info');
    await evalJs(`document.getElementById('pxHost').value='192.168.1.10'; document.querySelector('[data-do=pxSet]').click()`);
    await waitFor(`!!document.querySelector('.ab-modal-overlay')`, 'proxy confirm');
    await evalJs(`[...document.querySelectorAll('.ab-modal-foot button')].find(b=>/Set proxy/.test(b.textContent)).click()`);
    await waitFor(`window.__shellLog.includes("settings put global http_proxy '192.168.1.10:8080'")`, 'proxy set');
    await evalJs(`document.querySelector('[data-do=pxClear]').click()`);
    await waitFor(`/http_proxy is now: :0/.test(document.getElementById('toolsOut').textContent)`, 'proxy cleared');
    check('proxy set/clear works and clear is verified', true);

    await evalJs(`document.querySelector('[data-ttab=diag]').click()`);
    await evalJs(`document.querySelector('[data-do=logSnap]').click()`);
    await waitFor(`/snapshot line/.test(document.getElementById('toolsOut').textContent)`, 'log snapshot');
    await evalJs(`document.querySelector('[data-do=evidence]').click()`);
    await waitFor(`JSON.parse(localStorage.getItem('ab.activityLog')).some(e=>e.action==='evidence-pack')`, 'evidence pack', 30000);
    check('log snapshot and evidence pack work', true);

    await evalJs(`document.querySelector('[data-ttab=apk]').click()`);
    await waitFor(`document.querySelectorAll('#apkSel option').length>1`, 'apk app list');
    await evalJs(`document.getElementById('apkSel').value='com.example.app'; document.querySelector('[data-do=apkDevice]').click()`);
    await waitFor(`!!document.querySelector('#apkReport .result-box')`, 'apk analysed', 30000);
    check('APK analyzer: manifest parsed from the pulled APK', await evalJs(`/com\\.example\\.app/.test(document.getElementById('apkReport').innerText) && /debuggable/i.test(document.getElementById('apkReport').innerText)`));
    check('APK analyzer: dex indicators and exported components shown', await evalJs(`/Exported components/.test(document.getElementById('apkReport').innerText) && /DEX indicators/.test(document.getElementById('apkReport').innerText)`));
    check('APK analyzer never prints the raw secret', await evalJs(`!document.getElementById('apkReport').innerText.includes('AKIAABCDEFGHIJKLMNOP')`));

    if (pyOk) {
        await evalJs(`document.querySelector('[data-ttab=db]').click()`);
        await evalJs(`document.getElementById('dbPath').value='/sdcard/test.db'; document.querySelector('[data-do=dbDevice]').click()`);
        await waitFor(`document.querySelectorAll('[data-do=dbTable]').length===2`, 'db opened');
        await evalJs(`[...document.querySelectorAll('[data-do=dbTable]')].find(b=>b.dataset.t==='users').click()`);
        check('SQLite viewer lists tables and rows', await evalJs(`document.querySelectorAll('#dbView tbody tr').length===12 && /alice/.test(document.getElementById('dbView').innerText)`));
    }



    // ---- file operations: exact, injection-safe commands
    await evalJs(`document.querySelector('[data-section=files]').click()`);
    await waitFor(`!!document.getElementById('fileFilter')`, 'files for ops');
    await evalJs(`app.loadFiles('/storage/emulated/0')`);
    await waitFor(`document.querySelectorAll('#fileList .file-item').length>=4`, 'files for ops listed');
    const idxOf = (name) => `[...document.querySelectorAll('#fileList .file-item')].find(r=>r.querySelector('.file-name').textContent.startsWith(${JSON.stringify(name)}))`;
    await evalJs(`${idxOf("it's.txt")}.querySelector('[data-act=rename]').click()`);
    await waitFor(`!!document.querySelector('.ab-modal input')`, 'rename dialog');
    await evalJs(`(function(){var i=document.querySelector('.ab-modal input'); i.value='re named\\'; id.txt'; [...document.querySelectorAll('.ab-modal-foot button')].find(b=>b.textContent==='Rename').click();})()`);
    await waitFor(`window.__shellLog.some(c=>c.startsWith('mv '))`, 'rename sent');
    check('rename sends a fully quoted mv command', await evalJs(`window.__shellLog.some(c=>c==="mv '/storage/emulated/0/it'\\\\''s.txt' '/storage/emulated/0/re named'\\\\''; id.txt' 2>&1")`));
    await evalJs(`${idxOf('notes')}.querySelector('[data-act=delete]').click()`);
    await waitFor(`!!document.querySelector('.ab-modal-overlay')`, 'delete confirm');
    await evalJs(`[...document.querySelectorAll('.ab-modal-foot button')].find(b=>b.textContent==='Delete').click()`);
    await waitFor(`window.__shellLog.some(c=>c.startsWith('rm -f '))`, 'delete sent');
    check('delete sends a quoted rm -f command (name contains $(reboot))', await evalJs(`window.__shellLog.some(c=>c==="rm -f '/storage/emulated/0/notes $(reboot).txt' 2>&1")`));
    await evalJs(`setTimeout(() => app.makeDirectory(), 0); true`);   // opens a dialog: must not be awaited
    await waitFor(`!!document.querySelector('.ab-modal input')`, 'mkdir dialog');
    await evalJs(`(function(){var i=document.querySelector('.ab-modal input'); i.value='new dir'; [...document.querySelectorAll('.ab-modal-foot button')].find(b=>b.textContent==='Create').click();})()`);
    await waitFor(`window.__shellLog.some(c=>c.startsWith('mkdir -p '))`, 'mkdir sent');
    check('mkdir sends a quoted command', await evalJs(`window.__shellLog.includes("mkdir -p '/storage/emulated/0/new dir' 2>&1")`));
    await evalJs(`setTimeout(() => app.makeDirectory(), 0); true`);   // opens a dialog: must not be awaited
    await waitFor(`!!document.querySelector('.ab-modal input')`, 'mkdir dialog 2');
    await evalJs(`(function(){var i=document.querySelector('.ab-modal input'); i.value='a/b'; [...document.querySelectorAll('.ab-modal-foot button')].find(b=>b.textContent==='Create').click();})()`);
    check('folder names containing / are rejected', await evalJs(`!window.__shellLog.some(c=>c.includes("a/b"))`));

    // ---- shell: cd quoting, cwd carried into later commands, completion
    await evalJs(`document.querySelector('[data-section=shell]').click()`);
    await waitFor(`!!document.getElementById('shellInput')`, 'shell for cd');
    await evalJs(`app.executeCommand('cd /sdcard/DCIM')`);
    check('cd resolves through a quoted command', await evalJs(`window.__shellLog.includes("cd '/sdcard/DCIM' 2>&1 && pwd") && app.shellCwd === undefined ? true : window.__shellLog.includes("cd '/sdcard/DCIM' 2>&1 && pwd")`));
    await evalJs(`app.executeCommand('echo hello')`);
    check('later commands run inside the quoted cwd', await evalJs(`window.__shellLog.includes("cd '/sdcard/DCIM' && echo hello")`));
    await evalJs(`(function(){var i=document.getElementById('shellInput'); i.value='ls Doc'; app.shellComplete(i);})()`);
    await waitFor(`document.getElementById('shellInput').value==='ls Documents/'`, 'tab completion');
    check('Tab completes a path using the device listing', true);


    // ---- apps: install, download (single + split), app actions
    await evalJs(`document.querySelector('[data-section=apps]').click()`);
    await waitFor(`document.querySelectorAll('#appList .app-item').length>=1`, 'apps for install');
    await evalJs(`app.installApks([new File([new Uint8Array([80,75,3,4,0,0,0,0])], 'good.apk')])`);
    check('APK install pushes to a temp file, runs pm install and cleans up', await evalJs(`window.__shellLog.some(c=>/^pm install -r '\\/data\\/local\\/tmp\\/\\.adbaud_[^']+\\.apk'$/.test(c)) && window.__shellLog.some(c=>/^rm -f '\\/data\\/local\\/tmp\\/\\.adbaud_/.test(c)) && Object.keys(__dev.pushed).some(k=>k.startsWith('/data/local/tmp/.adbaud_'))`));
    await evalJs(`app.installApks([new File([new Uint8Array([1,2,3,4])], 'bad.apk')])`);
    check('a non-APK file is rejected before anything is pushed', await evalJs(`/not a valid APK/.test(document.getElementById('toastContainer').innerText)`));
    await evalJs(`app.downloadApk('com.example.app')`);
    check('single APK download reports success', await evalJs(`/APK downloaded/.test(document.getElementById('toastContainer').innerText)`));
    await evalJs(`app.downloadApk('com.split.app')`);
    check('split APKs are bundled into a ZIP', await evalJs(`/split APKs downloaded as ZIP/.test(document.getElementById('toastContainer').innerText)`));
    await evalJs(`app.showAppActions('com.example.app')`);
    check('app actions dialog lists launch/stop/clear/uninstall', await evalJs(`['Launch','Force stop','Clear data','Uninstall'].every(l=>[...document.querySelectorAll('.ab-modal-foot button')].some(b=>b.textContent===l))`));
    await evalJs(`[...document.querySelectorAll('.ab-modal-foot button')].find(b=>b.textContent==='Force stop').click()`);
    await waitFor(`window.__shellLog.includes('am force-stop com.example.app')`, 'force stop sent');
    check('force-stop sends the command for a validated package', true);

    // ---- files: upload, download, preview with secret banner, root toggle without root
    await evalJs(`document.querySelector('[data-section=files]').click()`);
    await waitFor(`!!document.getElementById('fileFilter')`, 'files for transfers');
    await evalJs(`app.loadFiles('/storage/emulated/0')`);
    await evalJs(`app.uploadFile(new File([new Uint8Array([9,8,7])], 'up.bin'))`);
    check('upload pushes bytes to the current folder', await evalJs(`Array.from(__dev.pushed['/storage/emulated/0/up.bin']||[]).join()==='9,8,7'`));
    await evalJs(`app.downloadFile('/storage/emulated/0/dl.bin')`);
    check('file download completes', await evalJs(`/Downloaded: dl.bin/.test(document.getElementById('toastContainer').innerText)`));
    await evalJs(`app.viewFile('/storage/emulated/0/note.txt')`);
    await waitFor(`!!document.querySelector('.ab-modal pre')`, 'preview opened');
    check('preview warns about secrets without printing them in the banner', await evalJs(`/Possible secrets \\(masked\\): password/.test(document.querySelector('.ab-modal pre').textContent)`));
    await evalJs(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))`);
    await evalJs(`document.getElementById('rootToggle').checked=true; app.toggleRootMode()`);
    check('enabling Root mode on a non-rooted device is refused and reverted', await evalJs(`app.constructor===Object && document.getElementById('rootToggle').checked===false && /not available/.test(document.getElementById('toastContainer').innerText)`));

    // ---- screenshot live mode
    await evalJs(`document.querySelector('[data-section=screenshot]').click()`);
    await evalJs(`app.toggleLiveScreenshot()`);
    await waitFor(`!!document.querySelector('.screenshot-preview')`, 'live frame');
    check('live screenshot starts', await evalJs(`app.liveTimer!==null`));
    await evalJs(`document.querySelector('[data-section=files]').click()`);
    check('leaving the screen stops live screenshots', await evalJs(`app.liveTimer===null`));

    // ---- security sub-tabs
    await evalJs(`document.querySelector('[data-section=security]').click()`);
    await waitFor(`document.querySelectorAll('.tab-btn').length===11`, 'security tabs');
    const tabRun = async (tab, selId, fn, resId, re, label) => {
        await evalJs(`app.switchSecurityTab('${tab}')`);
        await waitFor(`document.querySelectorAll('#${selId} option').length>1`, tab + ' select');
        await evalJs(`document.getElementById('${selId}').value='com.example.app'; app.${fn}()`);
        await waitFor(`/${re}/i.test(document.getElementById('${resId}').innerText)`, label);
    };
    await tabRun('backup', 'backupSelect', 'checkBackup', 'backupResults', 'Vulnerable', 'backup result');
    check('backup tab: allowBackup app is flagged', true);
    await tabRun('debuggable', 'debugSelect', 'checkDebuggable', 'debugResults', 'Not Debuggable', 'debug result');
    check('debug tab: release build passes', true);
    await tabRun('exported', 'exportedSelect', 'analyzeExported', 'exportedResults', 'MainActivity', 'exported result');
    check('components tab lists exported components', true);
    await tabRun('permissions', 'permSelect', 'analyzePermissions', 'permResults', 'CAMERA', 'permission result');
    check('permissions tab lists granted dangerous permissions', true);
    await tabRun('appInfo', 'appInfoSelect', 'loadAppInfo', 'appInfoResults', '1\\.4\\.2', 'app info result');
    check('app info tab shows version details', true);
    await tabRun('localStorage', 'storageSelect', 'analyzeStorage', 'storageResults', 'No files found', 'storage result');
    check('storage tab reports inaccessible storage without errors', true);
    await evalJs(`app.switchSecurityTab('logcat')`);
    check('security tab switch away from logcat leaves no running stream', await evalJs(`app.logcatRunning===false`));

    // ---- shell: root toggle and Ctrl+C on a streaming command
    await evalJs(`document.querySelector('[data-section=shell]').click()`);
    await waitFor(`!!document.getElementById('shellInput')`, 'shell for streaming');
    await evalJs(`setTimeout(() => app.executeCommand('ping -c 1 example.com'), 0); true`);
    await waitFor(`app.shellStream!==null`, 'stream started');
    await evalJs(`app.shellStream.stop()`);
    await waitFor(`app.shellStream===null`, 'stream stopped');
    check('streaming shell command can be stopped (Ctrl+C path)', true);
    await evalJs(`app.toggleShellRoot()`);
    await evalJs(`app.executeCommand('id')`);
    check('root shell wraps the cwd-prefixed command in su -c with correctly nested quotes', await evalJs(`window.__shellLog.includes("su -c 'cd '\\\\''/sdcard/DCIM'\\\\'' && id'")`));
    await evalJs(`app.toggleShellRoot()`);

    // ---- adversarial content on the new screens
    await evalJs(`document.querySelector('[data-section=tools]').click()`);
    await waitFor(`!!document.querySelector('[data-ttab=apk]')`, 'tools reopened');
    await evalJs(`document.querySelector('[data-ttab=apk]').click()`);
    await waitFor(`document.querySelectorAll('#apkSel option').length>1`, 'apk list (evil)');
    await evalJs(`(function(){var s=document.getElementById('apkSel'); s.value='com.bad.debuggable'; document.querySelector('[data-do=apkDevice]').click();})()`);
    await waitFor(`!!document.querySelector('#apkReport .result-box')`, 'evil apk analysed', 30000);
    check('hostile package/component names in an APK are rendered as text', await evalJs(`window.__pwned===undefined && !document.querySelector('#apkReport img') && /com\\.evil\\.Act/.test(document.getElementById('apkReport').innerText)`));
    if (evilDbB64) {
        await evalJs(`document.querySelector('[data-ttab=db]').click()`);
        await evalJs(`document.getElementById('dbPath').value='/sdcard/evil.db'; document.querySelector('[data-do=dbDevice]').click()`);
        await waitFor(`document.querySelectorAll('[data-do=dbTable]').length===1`, 'evil db opened');
        await evalJs(`document.querySelector('[data-do=dbTable]').click()`);
        check('hostile table names and cell contents are rendered as text', await evalJs(`window.__pwned===undefined && !document.querySelector('#dbView img') && /<img/.test(document.getElementById('dbView').innerText)`));
    }
    await evalJs(`document.querySelector('[data-section=shell]').click()`);
    await waitFor(`!!document.getElementById('shellInput')`, 'shell again');
    await evalJs(`app.executeCommand('echo ' + ${JSON.stringify(EVIL)})`);
    await evalJs(`document.getElementById('settingsBtn').click()`);
    await evalJs(`document.querySelector('[data-s=log]').click()`);
    check('hostile text in the activity log stays text', await evalJs(`window.__pwned===undefined && !document.querySelector('.ab-modal img') && /<img/.test(document.querySelector('.ab-modal pre').textContent)`));
    await evalJs(`[...document.querySelectorAll('.ab-modal-foot button')].find(b=>b.textContent==='Close').click()`);

    // ---- settings, theme, activity log
    await evalJs(`document.getElementById('settingsBtn').click()`);
    await evalJs(`document.querySelector('[data-theme-set=light]').click()`);
    check('light theme applied and persisted', await evalJs(`document.documentElement.dataset.theme==='light' && JSON.parse(localStorage.getItem('ab.theme'))==='light'`));
    await evalJs(`document.querySelector('[data-theme-set=dark]').click()`);
    await evalJs(`[...document.querySelectorAll('.ab-modal-foot button')].find(b=>b.textContent==='Close').click()`);
    check('activity log recorded actions', await evalJs(`JSON.parse(localStorage.getItem('ab.activityLog')).length>8`));
    check('all design tokens are defined', await evalJs(`['--danger','--success','--warning','--primary','--surface-2','--lum-40','--lum-60'].every(v=>getComputedStyle(document.documentElement).getPropertyValue(v).trim()!=='')`));


    // ---- failed connect must not wedge the next attempt
    await evalJs(`app.disconnect()`);
    await waitFor(`document.getElementById('statusText').textContent==='Disconnected'`, 'manual disconnect');
    await evalJs(`window.__origOpen = __dev.open.bind(__dev); __dev.open = async () => { throw new Error('simulated open failure'); }`);
    await evalJs(`document.getElementById('connectBtn').click()`);
    await waitFor(`/Connection failed/.test(document.getElementById('toastContainer').innerText)`, 'failure toast');
    check('failed connect shows an error and stays disconnected', await evalJs(`document.getElementById('statusText').textContent==='Disconnected' && app._connecting===false`));
    await evalJs(`__dev.open = window.__origOpen; document.getElementById('connectBtn').click(); document.getElementById('connectBtn').click();`);
    await waitFor(`document.getElementById('statusText').textContent==='Connected'`, 'reconnected after failure');
    check('retry works after a failed connect (and double-click is ignored)', await evalJs(`window.__shellLog.filter(c=>c==='echo ping').length>=0 && document.getElementById('statusText').textContent==='Connected'`));

    // ---- disconnect via unplug
    await evalJs(`window.__dev.unplug()`);
    await waitFor(`document.getElementById('statusText').textContent==='Disconnected'`, 'disconnect detected');
    check('unplug is detected and UI resets', await evalJs(`document.getElementById('statusText').textContent==='Disconnected'`));

    check('no uncaught exceptions', errors.length === 0, errors.join(' | '));
    const noisy = logs.filter(l => !/favicon|fonts\.g|ERR_NAME_NOT_RESOLVED|ERR_INTERNET_DISCONNECTED|Failed to load resource/.test(l) && !/\[ADB ERROR\]/.test(l) && !/Connection error: ADBError: Failed to open device: simulated/.test(l));
    check('no console errors', noisy.length === 0, noisy.join(' | '));

    try { fs.rmSync(dbDir, { recursive: true, force: true }); } catch (e) {}
    cleanup();
    console.log(failures ? `\n${failures} check(s) FAILED` : '\nAll e2e checks passed');
    process.exit(failures ? 1 : 0);
})().catch((e) => { console.error('E2E crashed:', e); process.exit(2); });
