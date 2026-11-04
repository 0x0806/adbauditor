/**
 * ADB Auditor - "Tools" section: device control, intents, packages, system, network, diagnostics,
 * APK static analyzer, SQLite viewer, settings/theme/activity log.
 *
 * @author Sandeep Wawdane (original creator of ADB Auditor)
 * @contributor 0x0806 (tools UI)
 * @license See LICENSE (CC BY-NC-ND 4.0, (c) Sandeep Wawdane)
 */
(function() {
    'use strict';

    function init() {
        const AB = window.__AB;
        const U = window.ABUtils;
        const esc = U.escapeHtml;
        const $ = (id) => document.getElementById(id);
        const adb = () => AB.getAdb();
        const kit = () => new window.DeviceToolkit(adb());
        const toast = AB.showToast;

        /* ---------- theme + settings ---------- */

        const media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;
        function applyTheme(choice) {
            const t = choice === 'system' ? (media && media.matches ? 'light' : 'dark') : choice;
            document.documentElement.dataset.theme = t;
            const meta = document.querySelector('meta[name="theme-color"]');
            if (meta) meta.content = t === 'light' ? '#eef0f6' : '#0a0a0f';
        }
        applyTheme(AB.store.get('theme', 'dark'));
        if (media && media.addEventListener) media.addEventListener('change', () => { if (AB.store.get('theme', 'dark') === 'system') applyTheme('system'); });
        function setTheme(choice) { AB.store.set('theme', choice); applyTheme(choice); toast('Theme: ' + choice, 'info'); }

        function showActivityLog() {
            const text = AB.activity.toText() || '(no activity recorded yet)';
            const m = AB.openModal({ title: 'Activity log (this browser only)', body: (() => { const pre = document.createElement('pre'); pre.className = 'ab-pre'; pre.textContent = text; return pre; })(), wide: true, buttons: [
                { label: 'Export', onClick: () => { U.downloadBlob(new Blob([text], { type: 'text/plain' }), `activity_${U.timestampForFile()}.log`); return false; } },
                { label: 'Clear', danger: true, onClick: () => { AB.activity.clear(); toast('Activity log cleared', 'info'); } },
                { label: 'Close', primary: true }] });
            return m;
        }

        async function forgetKey() {
            if (!(await AB.askConfirm('Delete the ADB authorization key stored in this browser? Every device will ask you to authorize this computer again.', { title: 'Forget ADB key', confirmText: 'Forget key', danger: true }))) return;
            await new Promise((resolve) => { const r = indexedDB.deleteDatabase('ADBauditorDB'); r.onsuccess = r.onerror = r.onblocked = () => resolve(); });
            AB.activity.add('forget-key');
            toast('ADB key deleted', 'success');
        }

        async function clearData() {
            if (!(await AB.askConfirm('Remove scan history, shell history, activity log, pinned apps and package baselines stored in this browser?', { title: 'Clear saved data', confirmText: 'Clear', danger: true }))) return;
            try { Object.keys(localStorage).filter(k => k.startsWith('ab.') && k !== 'ab.theme').forEach(k => localStorage.removeItem(k)); } catch (e) { /* ignore */ }
            AB.activity.entries = [];
            toast('Saved data cleared', 'success');
        }

        function showSettings() {
            const wrap = document.createElement('div');
            wrap.innerHTML = `<div style="display:grid;gap:12px">
                <div><strong>Theme</strong><div style="display:flex;gap:8px;margin-top:6px">${['dark', 'light', 'system'].map(t => `<button class="btn btn-ghost" data-theme-set="${t}">${t[0].toUpperCase() + t.slice(1)}</button>`).join('')}</div></div>
                <div><strong>Activity log</strong><div style="color:var(--lum-50);font-size:12px;margin:4px 0">Local record of connects, scans, file operations and shell commands - useful as an evidence trail. Never uploaded.</div>
                    <button class="btn btn-ghost" data-s="log">View / export</button></div>
                <div><strong>Privacy</strong><div style="display:flex;gap:8px;margin-top:6px;flex-wrap:wrap"><button class="btn btn-ghost" data-s="clear">Clear saved data</button><button class="btn btn-danger" data-s="key">Forget ADB key</button></div></div>
            </div>`;
            const m = AB.openModal({ title: 'Settings', body: wrap, buttons: [{ label: 'Close', primary: true }] });
            wrap.addEventListener('click', (e) => {
                const t = e.target.closest('[data-theme-set]'); if (t) { setTheme(t.dataset.themeSet); return; }
                const s = e.target.closest('[data-s]');
                if (!s) return;
                m.close();
                ({ log: showActivityLog, clear: clearData, key: forgetKey })[s.dataset.s]();
            });
        }

        const header = document.querySelector('.header');
        const connectBtn = $('connectBtn');
        if (header && connectBtn && !$('settingsBtn')) {
            const b = document.createElement('button');
            b.className = 'btn btn-ghost'; b.id = 'settingsBtn'; b.title = 'Settings'; b.setAttribute('aria-label', 'Settings');
            b.innerHTML = '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/></svg>';
            b.addEventListener('click', showSettings);
            header.insertBefore(b, connectBtn);
        }

        /* ---------- shared UI helpers ---------- */

        const TABS = [['control', 'Control'], ['intents', 'Intents'], ['packages', 'Packages'], ['system', 'System'], ['network', 'Network'], ['diag', 'Diagnostics'], ['apk', 'APK Analyzer'], ['db', 'Database']];
        let currentTab = 'control';
        const resultBox = (id = 'toolsOut') => `<pre class="ab-pre tools-out" id="${id}" aria-live="polite"></pre>`;
        const setOut = (text, id = 'toolsOut') => { const o = $(id); if (o) o.textContent = text; };
        const field = (label, id, attrs = '') => `<label class="tools-field"><span>${esc(label)}</span><input class="text-input" id="${id}" ${attrs}></label>`;
        const section = (title, body, desc = '') => `<div class="result-box tools-card"><div class="result-header"><strong>${esc(title)}</strong></div>${desc ? `<p class="panel-desc" style="margin:6px 0">${esc(desc)}</p>` : ''}${body}</div>`;
        const btn = (label, act, extra = '', cls = 'btn btn-ghost btn-sm') => `<button class="${cls}" data-do="${act}" ${extra}>${esc(label)}</button>`;

        /** Run a toolkit action with loading state, activity log and result output. */
        async function run(label, fn, { confirm, danger = false, out = true } = {}) {
            if (confirm && !(await AB.askConfirm(confirm, { title: label, confirmText: label, danger }))) return;
            try {
                const res = await fn();
                AB.activity.add('tool', label);
                const text = typeof res === 'string' ? res : (res === undefined ? '' : JSON.stringify(res, null, 2));
                if (out) setOut(text || '(no output)');
                toast(label + ': done', 'success');
                return res;
            } catch (e) {
                if (out) setOut('Error: ' + e.message);
                toast(label + ' failed: ' + e.message, 'error');
            }
        }
        const val = (id) => ($(id) ? $(id).value.trim() : '');

        /* ---------- tab renderers ---------- */

        const render = {
            control() {
                return section('Power', ['system', 'recovery', 'bootloader'].map(m => btn('Reboot ' + m, 'reboot', `data-mode="${m}"`)).join(' '), 'Restarts the device. The USB connection will drop.') +
                    section('Radios', [['Wi-Fi', 'wifi'], ['Bluetooth', 'bt'], ['Mobile data', 'data'], ['Airplane mode', 'air']].map(([l, k]) => `<span class="tools-pair">${esc(l)} ${btn('On', 'radio', `data-k="${k}" data-on="1"`)} ${btn('Off', 'radio', `data-k="${k}" data-on="0"`)}</span>`).join(' ')) +
                    section('Remote keys', Object.keys({ HOME: 1, BACK: 1, APP_SWITCH: 1, MENU: 1, POWER: 1, WAKEUP: 1, VOLUME_UP: 1, VOLUME_DOWN: 1, ENTER: 1, DPAD_UP: 1, DPAD_DOWN: 1, DPAD_LEFT: 1, DPAD_RIGHT: 1 }).map(k => btn(k.replace('_', ' '), 'key', `data-key="${k}"`)).join(' ')) +
                    section('Touch & text', `<div class="tools-row">${field('x', 'tapX', 'type="number" value="540" min="0"')}${field('y', 'tapY', 'type="number" value="1200" min="0"')}${btn('Tap', 'tap')}</div>
                        <div class="tools-row">${field('x1', 'swX1', 'type="number" value="540"')}${field('y1', 'swY1', 'type="number" value="1600"')}${field('x2', 'swX2', 'type="number" value="540"')}${field('y2', 'swY2', 'type="number" value="600"')}${btn('Swipe', 'swipe')}</div>
                        <div class="tools-row">${field('Text (ASCII)', 'typeText', 'maxlength="500"')}${btn('Type', 'type')}</div>`) +
                    section('Display & browser', `<div class="tools-row"><label class="tools-field"><span>Brightness <output id="brOut">128</output></span><input type="range" id="brightness" min="0" max="255" value="128"></label>${btn('Apply', 'brightness')}</div>
                        <div class="tools-row">${field('Open URL', 'openUrl', 'placeholder="https://example.com"')}${btn('Open', 'open')}</div>`) + resultBox();
            },
            intents() {
                return section('Intent launcher', `<p class="panel-desc">For testing exported components of apps you are authorised to assess. Extras: one per line as <code>type:key=value</code> (string, int, bool, long, float, uri).</p>
                    <div class="tools-row"><label class="tools-field"><span>Kind</span><select id="inKind"><option value="activity">Activity (am start)</option><option value="service">Service (am startservice)</option><option value="broadcast">Broadcast (am broadcast)</option></select></label>
                    ${field('Action', 'inAction', 'placeholder="android.intent.action.VIEW"')}${field('Component', 'inComp', 'placeholder="com.example/.MainActivity"')}</div>
                    <div class="tools-row">${field('Data URI', 'inData')}${field('MIME type', 'inMime')}${field('Package', 'inPkg')}${field('Categories (comma)', 'inCats')}</div>
                    <label class="tools-field"><span>Extras</span><textarea class="text-input" id="inExtras" rows="3" placeholder="string:token=abc&#10;int:count=3"></textarea></label>
                    <div class="tools-row">${btn('Preview command', 'intentPreview')} ${btn('Send intent', 'intentSend', '', 'btn btn-primary btn-sm')}</div>`) +
                    section('Deep link tester', `<div class="tools-row">${field('URI', 'dlUri', 'placeholder="myapp://open?id=1"')}${field('Restrict to package (optional)', 'dlPkg')}${btn('Fire', 'deeplink', '', 'btn btn-primary btn-sm')}</div>`, 'Sends a VIEW intent with the BROWSABLE category - the same path a web page or another app would use.') +
                    section('Content provider query', `<div class="tools-row">${field('URI', 'cpUri', 'placeholder="content://com.example.provider/items"')}${field('Projection', 'cpProj', 'placeholder="_id:name"')}${field('Where', 'cpWhere')}${field('Sort', 'cpSort')}${btn('Query', 'provider', '', 'btn btn-primary btn-sm')}</div>`) + resultBox();
            },
            packages() {
                return section('Permissions & state', `<div class="tools-row"><label class="tools-field"><span>Application</span><select id="pkSel"><option value="">Loading apps...</option></select></label>
                    <label class="tools-field"><span>Permission</span><select id="pkPerm">${Object.keys(window.SecurityAuditor.DANGEROUS_PERMS).map(p => `<option>${esc(p)}</option>`).join('')}</select></label></div>
                    <div class="tools-row">${btn('Grant', 'grant')} ${btn('Revoke', 'revoke', '', 'btn btn-danger btn-sm')} ${btn('AppOps', 'appops')} ${btn('Force stop', 'kill')} ${btn('Disable', 'disable', '', 'btn btn-danger btn-sm')} ${btn('Enable', 'enable')}</div>`) +
                    section('Baseline & drift', `<p class="panel-desc">Save the list of installed apps (with versions and installers), then compare later to spot newly installed, removed, updated or re-sourced apps.</p>
                    <label class="toggle-label" style="display:flex;gap:6px;align-items:center;margin-bottom:8px"><input type="checkbox" id="bsSystem"> include system apps</label>
                    <div class="tools-row">${btn('Save baseline', 'baselineSave')} ${btn('Compare with baseline', 'baselineCompare', '', 'btn btn-primary btn-sm')} <span id="bsInfo" style="color:var(--lum-50);font-size:12px"></span></div>`) + resultBox();
            },
            system() {
                return section('Settings', `<div class="tools-row"><label class="tools-field"><span>Namespace</span><select id="seNs"><option>global</option><option>secure</option><option>system</option></select></label>${field('Filter', 'seFilter')}${btn('Load', 'settingsLoad', '', 'btn btn-primary btn-sm')}</div><div id="seTable"></div>`) +
                    section('System properties', `<div class="tools-row">${field('Filter', 'prFilter')}${btn('Load', 'propsLoad', '', 'btn btn-primary btn-sm')} ${btn('Export JSON', 'propsExport')}</div><div id="prTable"></div>`) +
                    section('Dumpsys explorer', `<div class="tools-row"><label class="tools-field"><span>Service</span><select id="dsSvc"><option value="">(load services)</option></select></label>${field('Search in output', 'dsFind')}${btn('Load services', 'dsList')} ${btn('Run', 'dsRun', '', 'btn btn-primary btn-sm')}</div>`) + resultBox();
            },
            network() {
                return section('Network info', `${btn('Refresh', 'netInfo', '', 'btn btn-primary btn-sm')}<div id="netInfo" style="margin-top:8px"></div>`) +
                    section('HTTP proxy', `<p class="panel-desc">Route the device's HTTP(S) traffic through a proxy you control (for example an interception proxy on your test machine). Clearing restores direct traffic.</p>
                    <div class="tools-row">${field('Host', 'pxHost', 'placeholder="192.168.1.10"')}${field('Port', 'pxPort', 'type="number" value="8080" min="1" max="65535"')}${btn('Set proxy', 'pxSet', '', 'btn btn-primary btn-sm')} ${btn('Clear proxy', 'pxClear', '', 'btn btn-danger btn-sm')}</div>`) + resultBox();
            },
            diag() {
                return section('Log snapshot', `<div class="tools-row"><label class="tools-field"><span>Buffer</span><select id="lgBuf"><option>main</option><option>system</option><option>crash</option><option>events</option><option>radio</option><option>all</option></select></label>${field('Lines', 'lgLines', 'type="number" value="2000" min="1" max="200000"')}${btn('Capture', 'logSnap', '', 'btn btn-primary btn-sm')} ${btn('Save', 'logSave')}</div>`) +
                    section('Process & storage', `<div class="tools-row">${btn('Top snapshot', 'top')} ${btn('Storage (df)', 'storage')} ${field('Kill PID', 'killPid', 'type="number" min="2"')}${btn('Kill', 'killpid', '', 'btn btn-danger btn-sm')}</div>`) +
                    section('Screen recording', `<div class="tools-row">${field('Seconds (max 180)', 'recSecs', 'type="number" value="10" min="1" max="180"')}${btn('Record & download', 'record', '', 'btn btn-primary btn-sm')}</div>`) +
                    section('Evidence pack', `<p class="panel-desc">Bundle device info, installed apps, network info, recent scan reports, the activity log and a log snapshot into one ZIP.</p>${btn('Build evidence pack', 'evidence', '', 'btn btn-primary btn-sm')}`) + resultBox();
            },
            apk() {
                return section('APK static analyzer', `<p class="panel-desc">Offline analysis: manifest security findings, signing certificates, DEX strings (URLs, secrets, risky APIs), frameworks and tracker SDKs. Nothing leaves your browser.</p>
                    <div class="tools-row"><label class="tools-field"><span>Installed app</span><select id="apkSel"><option value="">Loading apps...</option></select></label>${btn('Pull & analyze', 'apkDevice', '', 'btn btn-primary btn-sm')}
                    <label class="btn btn-ghost btn-sm" style="cursor:pointer">Analyze local file<input type="file" id="apkLocal" accept=".apk,.zip" style="display:none"></label></div>
                    <div class="drop-zone" id="apkDrop" style="margin-top:8px"><p>Drop an APK here</p></div><div id="apkReport"></div>`);
            },
            db() {
                return section('SQLite viewer', `<p class="panel-desc">Open an app database from the device (root needed for /data/data) or a local file. A <code>-wal</code> file next to the database is merged automatically so recent rows are not missed.</p>
                    <div class="tools-row">${field('Device path', 'dbPath', 'placeholder="/data/data/com.example/databases/app.db" style="min-width:320px"')}${btn('Open from device', 'dbDevice', '', 'btn btn-primary btn-sm')}
                    <label class="btn btn-ghost btn-sm" style="cursor:pointer">Open local file(s)<input type="file" id="dbLocal" multiple style="display:none"></label></div>
                    <p style="color:var(--lum-50);font-size:12px">Local: select the .db and optionally its -wal file together.</p><div id="dbView"></div>`);
            }
        };

        const template = `<div class="page"><div class="page-header"><h1 class="page-title">Tools</h1></div>
            <div class="tab-bar" role="tablist" aria-label="Tools">${TABS.map(([k, l]) => `<button class="tab-btn${k === 'control' ? ' active' : ''}" data-ttab="${k}" role="tab">${l}</button>`).join('')}</div>
            <div id="toolsContent"></div></div>`;

        /* ---------- app picker ---------- */

        async function fillPackages(selectId) {
            const sel = $(selectId);
            if (!sel) return;
            try {
                const pkgs = await adb().listPackages(false);
                sel.innerHTML = '<option value="">Select application...</option>' + pkgs.map(p => `<option value="${esc(p)}">${esc(p)}</option>`).join('');
            } catch (e) { sel.innerHTML = '<option value="">Failed to load apps</option>'; }
        }
        const pkgValue = () => { const p = val('pkSel'); if (!p) throw new Error('Select an application first'); return p; };

        /* ---------- actions ---------- */

        const A = {
            reboot: (b) => run('Reboot ' + b.dataset.mode, () => kit().reboot(b.dataset.mode), { confirm: `Reboot the device into ${b.dataset.mode} mode?`, danger: true }),
            radio: (b) => {
                const on = b.dataset.on === '1', k = b.dataset.k;
                const fn = { wifi: 'setWifi', bt: 'setBluetooth', data: 'setMobileData', air: 'setAirplane' }[k];
                return run(`${k} ${on ? 'on' : 'off'}`, () => kit()[fn](on));
            },
            key: (b) => run('Key ' + b.dataset.key, () => kit().keyEvent(b.dataset.key), { out: false }),
            tap: () => run('Tap', () => kit().tap(val('tapX'), val('tapY')), { out: false }),
            swipe: () => run('Swipe', () => kit().swipe(val('swX1'), val('swY1'), val('swX2'), val('swY2')), { out: false }),
            type: () => run('Type text', () => kit().typeText($('typeText').value), { out: false }),
            brightness: () => run('Brightness', () => kit().setBrightness(val('brightness')), { out: false }),
            open: () => run('Open URL', () => kit().openUrl(val('openUrl'))),
            intentSpec() {
                const extras = val('inExtras').split('\n').map(l => l.trim()).filter(Boolean).map(l => {
                    const m = /^(\w+):([^=]+)=(.*)$/.exec(l);
                    if (!m) throw new Error('Bad extra line: ' + l);
                    return { type: m[1], key: m[2].trim(), value: m[3] };
                });
                return { kind: val('inKind'), action: val('inAction') || undefined, component: val('inComp') || undefined, data: val('inData') || undefined,
                    mimeType: val('inMime') || undefined, package: val('inPkg') || undefined, categories: val('inCats').split(',').map(s => s.trim()).filter(Boolean), extras };
            },
            intentPreview() { try { setOut(kit().buildIntentCommand(A.intentSpec())); } catch (e) { setOut('Error: ' + e.message); } },
            intentSend() { let spec; try { spec = A.intentSpec(); kit().buildIntentCommand(spec); } catch (e) { setOut('Error: ' + e.message); toast(e.message, 'error'); return; } return run('Send intent', () => kit().sendIntent(spec), { confirm: 'Send this intent to the device?\n\n' + kit().buildIntentCommand(spec) }); },
            deeplink: () => run('Deep link', () => kit().sendIntent({ kind: 'activity', action: 'android.intent.action.VIEW', data: val('dlUri'), package: val('dlPkg') || undefined, categories: ['android.intent.category.BROWSABLE'] })),
            provider: () => run('Provider query', () => kit().queryProvider(val('cpUri'), { projection: val('cpProj') || undefined, where: val('cpWhere') || undefined, sort: val('cpSort') || undefined })),
            grant: () => run('Grant permission', () => kit().grantPermission(pkgValue(), val('pkPerm'))),
            revoke: () => { const p = pkgValue(); return run('Revoke permission', () => kit().revokePermission(p, val('pkPerm')), { confirm: `Revoke ${val('pkPerm')} from ${p}?`, danger: true }); },
            appops: () => run('AppOps', () => kit().appOps(pkgValue())),
            kill: () => run('Force stop', () => kit().killPackage(pkgValue())),
            disable: () => { const p = pkgValue(); return run('Disable app', () => kit().setAppEnabled(p, false), { confirm: `Disable ${p} for the current user?`, danger: true }); },
            enable: () => run('Enable app', () => kit().setAppEnabled(pkgValue(), true)),
            async baselineSave() {
                await run('Save baseline', async () => {
                    const snap = await kit().packageSnapshot($('bsSystem').checked);
                    AB.store.set('pkgBaseline', { at: new Date().toISOString(), system: $('bsSystem').checked, list: snap });
                    $('bsInfo').textContent = `Saved ${snap.length} apps at ${new Date().toLocaleString()}`;
                    return `Baseline saved: ${snap.length} packages`;
                });
            },
            async baselineCompare() {
                const base = AB.store.get('pkgBaseline', null);
                if (!base) { toast('Save a baseline first', 'warning'); return; }
                await run('Compare baseline', async () => {
                    const now = await kit().packageSnapshot(base.system);
                    const d = window.DeviceToolkit.diffSnapshots(base.list, now);
                    const lines = [`Baseline from ${base.at}`, `Added (${d.added.length}):`, ...d.added.map(p => `  + ${p.pkg} v${p.versionCode} [${p.installer}]`),
                        `Removed (${d.removed.length}):`, ...d.removed.map(p => `  - ${p.pkg}`), `Updated (${d.updated.length}):`, ...d.updated.map(p => `  ~ ${p.pkg} ${p.from} -> ${p.to}`),
                        `Installer changed (${d.installerChanged.length}):`, ...d.installerChanged.map(p => `  ! ${p.pkg} ${p.from} -> ${p.to}`)];
                    return lines.join('\n');
                });
            },
            async settingsLoad() {
                const ns = val('seNs'); const box = $('seTable');
                box.innerHTML = '<p>Loading...</p>';
                try {
                    const rows = await kit().listSettings(ns);
                    const f = val('seFilter').toLowerCase();
                    const shown = rows.filter(r => !f || r.key.toLowerCase().includes(f) || r.value.toLowerCase().includes(f));
                    box.innerHTML = `<table class="ab-table"><thead><tr><th>Key</th><th>Value</th><th></th></tr></thead><tbody>${shown.map(r => `<tr><td class="mono">${esc(r.key)}</td><td class="mono" style="white-space:normal;word-break:break-all">${esc(r.value)}</td><td>${btn('Edit', 'settingEdit', `data-ns="${esc(ns)}" data-key="${esc(r.key)}" data-value="${esc(r.value)}"`)} ${btn('Delete', 'settingDelete', `data-ns="${esc(ns)}" data-key="${esc(r.key)}"`, 'btn btn-danger btn-sm')}</td></tr>`).join('')}</tbody></table><p style="color:var(--lum-50);font-size:12px">${shown.length} of ${rows.length}</p>`;
                } catch (e) { box.innerHTML = `<p style="color:var(--danger)">${esc(e.message)}</p>`; }
            },
            async settingEdit(b) {
                const v = await AB.askInput(`New value for ${b.dataset.ns}/${b.dataset.key}`, { title: 'Edit setting', value: b.dataset.value, confirmText: 'Save' });
                if (v === null) return;
                if (!(await AB.askConfirm(`Set ${b.dataset.ns} ${b.dataset.key} = ${v}?`, { title: 'Change setting', confirmText: 'Change', danger: true }))) return;
                await run('Edit setting', () => kit().putSetting(b.dataset.ns, b.dataset.key, v));
                A.settingsLoad();
            },
            async settingDelete(b) {
                if (!(await AB.askConfirm(`Delete setting ${b.dataset.ns}/${b.dataset.key}?`, { title: 'Delete setting', confirmText: 'Delete', danger: true }))) return;
                await run('Delete setting', () => kit().deleteSetting(b.dataset.ns, b.dataset.key));
                A.settingsLoad();
            },
            _props: [],
            async propsLoad() {
                const box = $('prTable'); box.innerHTML = '<p>Loading...</p>';
                try {
                    A._props = await kit().listProps();
                    const f = val('prFilter').toLowerCase();
                    const shown = A._props.filter(r => !f || r.key.toLowerCase().includes(f) || r.value.toLowerCase().includes(f));
                    box.innerHTML = `<table class="ab-table"><tbody>${shown.map(r => `<tr><td class="mono">${esc(r.key)}</td><td class="mono" style="white-space:normal;word-break:break-all">${esc(r.value)}</td></tr>`).join('')}</tbody></table><p style="color:var(--lum-50);font-size:12px">${shown.length} of ${A._props.length}</p>`;
                } catch (e) { box.innerHTML = `<p style="color:var(--danger)">${esc(e.message)}</p>`; }
            },
            propsExport() {
                if (!A._props.length) { toast('Load properties first', 'warning'); return; }
                U.downloadBlob(new Blob([JSON.stringify(Object.fromEntries(A._props.map(p => [p.key, p.value])), null, 2)], { type: 'application/json' }), `properties_${U.timestampForFile()}.json`);
            },
            async dsList() {
                await run('List services', async () => {
                    const svcs = await kit().listDumpsysServices();
                    $('dsSvc').innerHTML = svcs.map(s => `<option>${esc(s)}</option>`).join('');
                    return `${svcs.length} services`;
                });
            },
            async dsRun() {
                const svc = val('dsSvc'); if (!svc) { toast('Load and choose a service first', 'warning'); return; }
                const find = val('dsFind').toLowerCase();
                await run('dumpsys ' + svc, async () => {
                    const out = await kit().dumpsys(svc);
                    return find ? out.split('\n').filter(l => l.toLowerCase().includes(find)).join('\n') || '(no matching lines)' : out;
                });
            },
            async netInfo() {
                const box = $('netInfo'); box.innerHTML = 'Loading...';
                try {
                    const n = await kit().networkInfo();
                    box.innerHTML = `<table class="ab-table"><tbody>
                        <tr><td>Addresses</td><td class="mono" style="white-space:normal">${n.addresses.map(a => esc(a.iface + ' ' + a.address)).join('<br>') || '-'}</td></tr>
                        <tr><td>Routes</td><td class="mono" style="white-space:normal">${n.routes.map(esc).join('<br>') || '-'}</td></tr>
                        <tr><td>DNS</td><td class="mono">${n.dns.map(esc).join(', ') || '-'}</td></tr>
                        <tr><td>HTTP proxy</td><td class="mono">${n.proxy ? '<span class="badge warning">' + esc(n.proxy) + '</span>' : 'none'}</td></tr>
                        <tr><td>Private DNS</td><td class="mono">${esc(n.privateDns.mode || '-')} ${esc(n.privateDns.host || '')}</td></tr></tbody></table>`;
                } catch (e) { box.textContent = 'Error: ' + e.message; }
            },
            pxSet: () => run('Set proxy', () => kit().setProxy(val('pxHost'), val('pxPort')), { confirm: `Route device traffic through ${val('pxHost')}:${val('pxPort')}?` }),
            pxClear: () => run('Clear proxy', async () => { const r = await kit().clearProxy(); return `http_proxy is now: ${r || '(unset)'}`; }),
            _log: '',
            async logSnap() { await run('Log snapshot', async () => { A._log = await kit().logSnapshot(val('lgBuf'), val('lgLines')); return A._log.length > 400000 ? A._log.slice(-400000) : A._log; }); },
            logSave() { if (!A._log) { toast('Capture a log first', 'warning'); return; } U.downloadBlob(new Blob([A._log], { type: 'text/plain' }), `logcat_${val('lgBuf')}_${U.timestampForFile()}.txt`); },
            top: () => run('Top', () => kit().topSnapshot()),
            storage: () => run('Storage', async () => (await kit().storageSummary()).map(r => `${r.mount.padEnd(28)} ${r.size.padStart(7)} used ${r.used.padStart(7)} free ${r.avail.padStart(7)} ${r.usePct}`).join('\n')),
            killpid: () => run('Kill process', () => kit().killPid(val('killPid')), { confirm: `Send SIGTERM to PID ${val('killPid')}?`, danger: true }),
            async record() {
                AB.showLoading('Recording screen...', `${val('recSecs')} seconds - interact with the device`);
                try {
                    const bytes = await kit().screenRecord(val('recSecs'));
                    U.downloadBlob(new Blob([bytes], { type: 'video/mp4' }), `screenrecord_${U.timestampForFile()}.mp4`);
                    AB.activity.add('screen-record', val('recSecs') + 's');
                    toast(`Recording saved (${AB.formatSize(bytes.length)})`, 'success');
                } catch (e) { toast('Recording failed: ' + e.message, 'error'); } finally { AB.hideLoading(); }
            },
            async evidence() {
                AB.showLoading('Building evidence pack...', 'Collecting device data');
                try {
                    const t = kit(), files = [], now = new Date();
                    const add = (name, data) => files.push({ name, data: typeof data === 'string' ? data : JSON.stringify(data, null, 2), date: now });
                    const props = await adb().getDeviceProps();
                    add('device.json', props);
                    add('properties.json', Object.fromEntries((await t.listProps()).map(p => [p.key, p.value])));
                    add('packages.json', await t.packageSnapshot(true));
                    add('network.json', await t.networkInfo());
                    add('logcat_main.txt', await t.logSnapshot('main', 2000));
                    add('activity.log', AB.activity.toText());
                    add('scan_history.json', AB.store.get('scanHistory', []));
                    const rep = AB.app.lastReport;
                    if (rep) { add('last_scan.json', rep); add('last_scan.md', U.reportToMarkdown(rep, { device: props.model })); }
                    if (AB.state.screenshotBlob) files.push({ name: 'screenshot.png', data: new Uint8Array(await AB.state.screenshotBlob.arrayBuffer()), date: now });
                    add('README.txt', `Evidence pack generated ${now.toISOString()} by ADB Auditor (created by Sandeep Wawdane, enhanced by 0x0806).\nDevice: ${props.brand} ${props.model}, Android ${props.androidVersion}.\nAll data was collected locally in the browser.`);
                    U.downloadBlob(new Blob([U.buildZip(files)], { type: 'application/zip' }), `evidence_${U.safeFileName(props.model)}_${U.timestampForFile()}.zip`);
                    AB.activity.add('evidence-pack', `${files.length} files`);
                    toast(`Evidence pack saved (${files.length} files)`, 'success');
                } catch (e) { toast('Evidence pack failed: ' + e.message, 'error'); } finally { AB.hideLoading(); }
            },
            async apkDevice() {
                const pkg = val('apkSel'); if (!pkg) { toast('Select an application', 'warning'); return; }
                AB.showLoading('Pulling APK...', pkg);
                try {
                    const path = (await adb().getApkPaths(pkg))[0];
                    const bytes = await adb().pullFile(path, (n, total) => AB.showLoading('Pulling APK...', total ? `${AB.formatSize(n)} / ${AB.formatSize(total)}` : AB.formatSize(n)));
                    AB.showLoading('Analyzing...', `${AB.formatSize(bytes.length)}`);
                    await analyze(bytes, pkg + '.apk');
                } catch (e) { toast('Analysis failed: ' + e.message, 'error'); } finally { AB.hideLoading(); }
            }
        };

        /* ---------- APK report rendering ---------- */

        let lastApk = null;
        async function analyze(bytes, name) {
            const report = await window.ApkAnalyzer.analyzeApk(bytes);
            lastApk = { report, name };
            AB.activity.add('apk-analysis', `${name} sha256=${report.hashes.sha256.slice(0, 16)}`);
            const box = $('apkReport');
            if (box) box.innerHTML = renderApk(report, name);
        }

        const sevColor = (s) => ({ critical: 'var(--danger)', high: 'var(--danger)', medium: 'var(--warning)' })[s] || 'var(--lum-60)';
        function renderApk(r, name) {
            const m = r.manifest || {};
            const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
            r.findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
            let h = `<div class="result-box" style="margin-top:12px"><div class="result-header"><strong>${esc(m.package || name)}</strong><span style="margin-left:auto;color:var(--lum-40);font-size:12px">${esc(AB.formatSize(r.size))} &middot; ${r.fileCount} files &middot; ${r.durationMs} ms</span></div>
                <table class="ab-table"><tbody>
                <tr><td>Version</td><td>${esc(m.versionName ?? '?')} (${esc(m.versionCode ?? '?')})</td></tr>
                <tr><td>SDK</td><td>min ${esc(m.minSdk ?? '?')} / target ${esc(m.targetSdk ?? '?')}</td></tr>
                <tr><td>SHA-256</td><td class="mono" style="white-space:normal;word-break:break-all">${esc(r.hashes.sha256)}</td></tr>
                <tr><td>Signing</td><td>${r.signing.schemes.length ? 'v' + r.signing.schemes.join(', v') : '<span class="badge fail">none found</span>'}</td></tr>
                <tr><td>Frameworks</td><td>${esc(r.frameworks.join(', ') || 'native / Java')}</td></tr>
                <tr><td>Native ABIs</td><td>${esc(r.nativeLibs.abis.join(', ') || '-')}</td></tr></tbody></table>
                <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">${Object.entries(counts).filter(([, n]) => n).map(([s, n]) => `<span class="badge ${s === 'critical' || s === 'high' ? 'fail' : s === 'medium' ? 'warning' : ''}">${n} ${s}</span>`).join('')}
                ${btn('Export JSON', 'apkJson')} ${btn('Export Markdown', 'apkMd')}</div></div>`;
            h += `<div class="result-box" style="margin-top:8px"><div class="result-header"><strong>Findings (${r.findings.length})</strong></div>${r.findings.map(f => `<div style="padding:5px 0;font-size:12px;color:${sevColor(f.severity)}">&bull; <b>[${esc(f.severity)}]</b> ${esc(f.title)}${f.detail ? ` <span style="color:var(--lum-50)">- ${esc(f.detail)}</span>` : ''}${f.recommendation ? `<div style="margin-left:12px;color:var(--lum-50)">Fix: ${esc(f.recommendation)}</div>` : ''}</div>`).join('') || '<p style="color:var(--lum-50)">No findings</p>'}</div>`;
            if (r.signing.certs.length || r.signing.notes.length) {
                h += `<div class="result-box" style="margin-top:8px"><div class="result-header"><strong>Signing certificates</strong></div>${r.signing.certs.map(c => `<table class="ab-table"><tbody><tr><td>Subject</td><td class="mono" style="white-space:normal">${esc(c.subject)}</td></tr><tr><td>Issuer</td><td class="mono" style="white-space:normal">${esc(c.issuer)}</td></tr><tr><td>Valid</td><td>${esc(c.notBefore || '?')} &rarr; ${esc(c.notAfter || '?')}</td></tr><tr><td>Algorithm</td><td>${esc(c.signatureAlgorithm)}, ${esc(c.publicKey)}</td></tr><tr><td>SHA-256</td><td class="mono" style="white-space:normal;word-break:break-all">${esc(c.sha256)}</td></tr></tbody></table>`).join('')}${r.signing.notes.map(n => `<p style="color:var(--lum-50);font-size:12px">${esc(n)}</p>`).join('')}</div>`;
            }
            if (m.components) {
                const exp = m.components.filter(c => c.exported === true && c.enabled);
                h += `<div class="result-box" style="margin-top:8px;overflow-x:auto"><div class="result-header"><strong>Exported components (${exp.length} of ${m.components.length})</strong></div><table class="ab-table"><thead><tr><th>Type</th><th>Name</th><th>Permission</th><th>Filters</th></tr></thead><tbody>${exp.map(c => `<tr><td>${esc(c.kind)}</td><td class="mono">${esc(c.name)}</td><td class="mono">${esc(c.permission || c.readPermission || '-')}</td><td>${c.intentFilters.length}${c.exportedExplicit ? '' : ' (implicit)'}</td></tr>`).join('')}</tbody></table></div>`;
                h += `<div class="result-box" style="margin-top:8px"><div class="result-header"><strong>Permissions (${m.permissions.length})</strong></div><div class="perm-list" style="margin-top:8px">${m.permissions.map(p => `<span class="perm-tag" ${window.SecurityAuditor.DANGEROUS_PERMS[p] ? 'style="border-color:var(--warning)"' : ''}>${esc(p.replace('android.permission.', ''))}</span>`).join('')}</div></div>`;
            }
            if (r.dex) {
                h += `<div class="result-box" style="margin-top:8px"><div class="result-header"><strong>DEX indicators</strong><span style="margin-left:auto;color:var(--lum-40);font-size:12px">${r.dex.stringCount} strings in ${r.dexCount} dex file(s)</span></div>
                    ${r.dex.trackers.length ? `<p style="font-size:12px;margin-top:6px"><b>Possible tracker/analytics SDKs (heuristic):</b> ${esc(r.dex.trackers.join(', '))}</p>` : ''}
                    ${r.dex.ips.length ? `<p style="font-size:12px;margin-top:6px"><b>IP addresses:</b> <span class="mono">${esc(r.dex.ips.join(', '))}</span></p>` : ''}
                    <details style="margin-top:8px"><summary style="cursor:pointer;font-size:12px">URLs (${r.dex.urls.length})</summary><pre class="ab-pre" style="margin-top:6px">${esc(r.dex.urls.join('\n'))}</pre></details></div>`;
            }
            if (r.warnings.length) h += `<p style="color:var(--warning);font-size:12px;margin-top:8px">${r.warnings.map(esc).join('<br>')}</p>`;
            return h;
        }
        A.apkJson = () => lastApk && U.downloadBlob(new Blob([JSON.stringify({ generator: 'ADB Auditor (created by Sandeep Wawdane, enhanced by 0x0806)', ...lastApk.report }, null, 2)], { type: 'application/json' }), `apk_${U.safeFileName(lastApk.report.manifest?.package || lastApk.name)}_${U.timestampForFile()}.json`);
        A.apkMd = () => lastApk && U.downloadBlob(new Blob([window.ApkAnalyzer.apkReportToMarkdown(lastApk.report, lastApk.name)], { type: 'text/markdown' }), `apk_${U.safeFileName(lastApk.report.manifest?.package || lastApk.name)}_${U.timestampForFile()}.md`);

        /* ---------- SQLite viewer ---------- */

        let db = null, dbName = '', dbTable = '', dbPage = 0;
        const PAGE = 100;
        function showDb(bytes, wal, name) {
            db = new window.SqliteDb(bytes, wal);
            dbName = name; dbTable = ''; dbPage = 0;
            renderDb();
        }
        function renderDb() {
            const box = $('dbView'); if (!box || !db) return;
            const tables = db.tables();
            const walNote = db.walFrames ? `<span class="badge success">WAL merged (${db.walFrames} commits)</span>` : '<span class="badge warning">no WAL applied - recent rows may be missing</span>';
            let h = `<div class="result-box" style="margin-top:12px"><div class="result-header"><strong>${esc(dbName)}</strong><span style="margin-left:auto">${walNote}</span></div>
                <div style="color:var(--lum-50);font-size:12px;margin:6px 0">page size ${db.pageSize}, ${db.pageCount} pages, ${['', 'UTF-8', 'UTF-16le', 'UTF-16be'][db.encoding] || '?'}, ${tables.length} tables</div>
                <div style="display:flex;gap:6px;flex-wrap:wrap">${tables.map(t => `<button class="btn btn-sm ${t.name === dbTable ? 'btn-primary' : 'btn-ghost'}" data-do="dbTable" data-t="${esc(t.name)}">${esc(t.name)}</button>`).join('')}</div></div>`;
            if (dbTable) {
                try {
                    const res = db.rows(dbTable, { limit: PAGE, offset: dbPage * PAGE });
                    const total = db.count(dbTable);
                    h += `<div class="result-box" style="margin-top:8px;overflow-x:auto"><div class="result-header"><strong>${esc(dbTable)}</strong><span style="color:var(--lum-40);font-size:12px;margin-left:8px">${total ?? '?'} rows</span>
                        <span style="margin-left:auto;display:flex;gap:6px">${btn('Prev', 'dbPrev')} ${btn('Next', 'dbNext')} ${btn('Export CSV', 'dbCsv')} ${btn('Schema', 'dbSchema')}</span></div>
                        ${res.note ? `<p style="color:var(--warning);font-size:12px">${esc(res.note)}</p>` : ''}
                        <table class="ab-table"><thead><tr>${res.columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${res.rows.map(r => `<tr>${r.map(c => `<td class="mono" style="white-space:normal;word-break:break-all;max-width:360px">${esc(window.SqliteDb.formatCell(c))}</td>`).join('')}</tr>`).join('')}</tbody></table>
                        <p style="color:var(--lum-50);font-size:12px">page ${dbPage + 1}${total ? ' of ' + Math.max(1, Math.ceil(total / PAGE)) : ''}</p></div>`;
                } catch (e) { h += `<p style="color:var(--danger)">${esc(e.message)}</p>`; }
            }
            box.innerHTML = h;
        }
        A.dbTable = (b) => { dbTable = b.dataset.t; dbPage = 0; renderDb(); };
        A.dbPrev = () => { if (dbPage > 0) { dbPage--; renderDb(); } };
        A.dbNext = () => { try { if (db.rows(dbTable, { limit: 1, offset: (dbPage + 1) * PAGE }).rows.length) { dbPage++; renderDb(); } } catch (e) { toast(e.message, 'error'); } };
        A.dbSchema = () => { const t = db.tables().find(x => x.name === dbTable); AB.showTextModal('Schema: ' + dbTable, '', t && t.sql); };
        A.dbCsv = () => {
            try {
                const res = db.rows(dbTable, { limit: 100000 });
                const cell = (v) => { const s = v === null ? '' : window.SqliteDb.formatCell(v, 1e6); return '"' + (/^[=+\-@]/.test(s) ? "'" + s : s).replace(/"/g, '""') + '"'; };
                U.downloadBlob(new Blob([[res.columns.map(cell).join(','), ...res.rows.map(r => r.map(cell).join(','))].join('\r\n')], { type: 'text/csv' }), `${U.safeFileName(dbName)}_${U.safeFileName(dbTable)}.csv`);
                AB.activity.add('db-export', `${dbName}/${dbTable}`);
            } catch (e) { toast(e.message, 'error'); }
        };
        A.dbDevice = async () => { const p = val('dbPath'); if (p) await openDatabase(p); else toast('Enter a device path', 'warning'); };

        async function openDatabase(path) {
            AB.showLoading('Opening database...', path);
            try {
                const root = !(path.startsWith('/sdcard/') || path.startsWith('/storage/'));
                const bytes = await AB.readDeviceFile(path, null, root);
                let wal = null;
                try { wal = await AB.readDeviceFile(path + '-wal', null, root); } catch (e) { /* no WAL */ }
                AB.activity.add('db-open', path);
                if (currentTab !== 'db' || !$('dbView')) { AB.navigate('tools'); showTab('db'); }
                const inp = $('dbPath'); if (inp) inp.value = path;
                showDb(bytes, wal, path.split('/').pop());
            } catch (e) { toast('Cannot open database: ' + e.message, 'error'); } finally { AB.hideLoading(); }
        }
        window.__AB.openDatabase = openDatabase;
        window.__AB.analyzeDevicePath = async (path) => {
            AB.showLoading('Pulling APK...', path);
            try {
                const bytes = await AB.readDeviceFile(path, (n, total) => AB.showLoading('Pulling APK...', total ? `${AB.formatSize(n)} / ${AB.formatSize(total)}` : AB.formatSize(n)));
                AB.navigate('tools'); showTab('apk');
                AB.showLoading('Analyzing...', AB.formatSize(bytes.length));
                await analyze(bytes, path.split('/').pop());
            } catch (e) { toast('Analysis failed: ' + e.message, 'error'); } finally { AB.hideLoading(); }
        };

        /* ---------- tab plumbing ---------- */

        function showTab(tab) {
            currentTab = tab;
            const c = $('toolsContent'); if (!c) return;
            document.querySelectorAll('[data-ttab]').forEach(b => { b.classList.toggle('active', b.dataset.ttab === tab); b.setAttribute('aria-selected', String(b.dataset.ttab === tab)); });
            c.innerHTML = render[tab]();
            if (tab === 'packages') fillPackages('pkSel');
            if (tab === 'apk') {
                fillPackages('apkSel');
                const pick = async (file) => {
                    AB.showLoading('Analyzing...', file.name);
                    try { await analyze(new Uint8Array(await file.arrayBuffer()), file.name); } catch (e) { toast('Analysis failed: ' + e.message, 'error'); } finally { AB.hideLoading(); }
                };
                $('apkLocal').addEventListener('change', (e) => { const f = e.target.files[0]; e.target.value = ''; if (f) pick(f); });
                const dz = $('apkDrop');
                dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag-over'); });
                dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
                dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('drag-over'); const f = e.dataTransfer.files[0]; if (f) pick(f); });
            }
            if (tab === 'db') {
                $('dbLocal').addEventListener('change', async (e) => {
                    const files = Array.from(e.target.files); e.target.value = '';
                    const main = files.find(f => !/-wal$/.test(f.name)); const wal = files.find(f => /-wal$/.test(f.name));
                    if (!main) return;
                    try { showDb(new Uint8Array(await main.arrayBuffer()), wal ? new Uint8Array(await wal.arrayBuffer()) : null, main.name); } catch (err) { toast(err.message, 'error'); }
                });
            }
            if (tab === 'control') $('brightness').addEventListener('input', (e) => { $('brOut').textContent = e.target.value; });
        }
        A.showTab = showTab;

        function onClick(e) {
            const t = e.target.closest('[data-ttab]');
            if (t) { showTab(t.dataset.ttab); return; }
            const d = e.target.closest('[data-do]');
            if (d && A[d.dataset.do]) A[d.dataset.do](d);
        }
        // the content area is re-rendered on navigation, so bind once via delegation on the stable container
        let bound = false;
        function bind() { if (bound) return; bound = true; document.getElementById('contentArea').addEventListener('click', onClick); }

        AB.registerSection('tools', template, () => { bind(); showTab(currentTab); });

        AB.registerCommand({ name: 'Open settings', run: showSettings });
        AB.registerCommand({ name: 'View activity log', run: showActivityLog });
        AB.registerCommand({ name: 'Theme: toggle dark / light', run: () => setTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light') });
        for (const [k, l] of TABS) AB.registerCommand({ name: 'Tools: ' + l, needsDevice: true, run: () => { AB.navigate('tools'); showTab(k); } });
        AB.registerCommand({ name: 'Tools: build evidence pack', needsDevice: true, run: () => { AB.navigate('tools'); showTab('diag'); setTimeout(() => A.evidence(), 50); } });

        window.__AB.toolsActions = A;   // exposed for tests
    }

    if (window.__AB) init(); else window.addEventListener('ab-ready', init, { once: true });
})();
