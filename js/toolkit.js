/**
 * ADB Auditor - device toolkit: validated, injection-safe wrappers around common `adb shell` operations
 * used during authorised testing (radios, input, intents, content providers, permissions, settings, proxy...).
 * Every user-supplied value is validated and single-quoted; state-changing calls are meant to be confirmed in the UI.
 *
 * @author Sandeep Wawdane (original creator of ADB Auditor)
 * @contributor 0x0806 (device toolkit)
 * @license See LICENSE (CC BY-NC-ND 4.0, (c) Sandeep Wawdane)
 */
(function(global) {
    'use strict';

    const U = global.ABUtils;
    const q = U.shQuote;

    const KEYS = { HOME: 3, BACK: 4, CALL: 5, ENDCALL: 6, VOLUME_UP: 24, VOLUME_DOWN: 25, POWER: 26, CAMERA: 27, TAB: 61, SPACE: 62, ENTER: 66, DEL: 67, MENU: 82,
        SEARCH: 84, MEDIA_PLAY_PAUSE: 85, MUTE: 91, PAGE_UP: 92, PAGE_DOWN: 93, WAKEUP: 224, SLEEP: 223, APP_SWITCH: 187, NOTIFICATION: 83, DPAD_UP: 19, DPAD_DOWN: 20,
        DPAD_LEFT: 21, DPAD_RIGHT: 22, DPAD_CENTER: 23 };
    const REBOOT_MODES = { system: 'reboot', recovery: 'reboot recovery', bootloader: 'reboot bootloader' };
    const LOG_BUFFERS = ['main', 'system', 'crash', 'events', 'radio', 'all'];
    const SETTING_NS = ['system', 'secure', 'global'];

    const fail = (msg) => { throw new Error(msg); };
    const int = (v, name, min = -1e9, max = 1e9) => {
        const n = Number(v);
        if (!Number.isInteger(n) || n < min || n > max) fail(`${name} must be an integer between ${min} and ${max}`);
        return n;
    };
    const pkgName = (p) => { if (!U.isValidPackageName(p)) fail('Invalid package name'); return p; };
    const ident = (v, name) => { if (!/^[A-Za-z0-9_.]+$/.test(String(v || ''))) fail(`Invalid ${name}`); return v; };

    class DeviceToolkit {
        constructor(adb) { this.adb = adb; }

        sh(cmd, timeout) { return this.adb.shell(cmd, timeout); }

        /* ---------- power / radios ---------- */

        async reboot(mode = 'system') {
            if (!REBOOT_MODES[mode]) fail('Unknown reboot mode');
            return this.sh(REBOOT_MODES[mode], 5000).catch(e => { if (e.type === 'CONNECTION_LOST' || e.type === 'TIMEOUT') return ''; throw e; });
        }
        setWifi(on) { return this.sh(`svc wifi ${on ? 'enable' : 'disable'}`); }
        setBluetooth(on) { return this.sh(`svc bluetooth ${on ? 'enable' : 'disable'}`); }
        setMobileData(on) { return this.sh(`svc data ${on ? 'enable' : 'disable'}`); }
        setAirplane(on) { return this.sh(`cmd connectivity airplane-mode ${on ? 'enable' : 'disable'}`); }
        setBrightness(level) { return this.sh(`settings put system screen_brightness ${int(level, 'brightness', 0, 255)}`); }

        /* ---------- input injection ---------- */

        keyEvent(name) {
            const code = KEYS[String(name).toUpperCase().replace(/^KEYCODE_/, '')];
            if (code === undefined) fail('Unknown key: ' + name);
            return this.sh(`input keyevent ${code}`);
        }
        tap(x, y) { return this.sh(`input tap ${int(x, 'x', 0, 20000)} ${int(y, 'y', 0, 20000)}`); }
        swipe(x1, y1, x2, y2, ms = 300) {
            return this.sh(`input swipe ${[x1, y1, x2, y2].map((v, i) => int(v, 'coordinate', 0, 20000)).join(' ')} ${int(ms, 'duration', 1, 10000)}`);
        }
        typeText(text) {
            const s = String(text);
            if (!s.length || s.length > 500) fail('Text must be 1-500 characters');
            if (/[^\x20-\x7e]/.test(s)) fail('Only printable ASCII can be typed with `input text`');
            return this.sh(`input text ${q(s.replace(/ /g, '%s'))}`);
        }
        openUrl(url) {
            const u = String(url).trim();
            if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/\S+$/.test(u) || u.length > 2000) fail('Invalid URL (must look like scheme://...)');
            return this.sh(`am start -a android.intent.action.VIEW -d ${q(u)}`);
        }

        /* ---------- intents ---------- */

        /**
         * Build an `am` command from structured input. Every token is quoted separately.
         * spec: { kind: 'activity'|'service'|'broadcast', action?, component?, data?, mimeType?, categories?, extras?: [{type,key,value}], package? }
         */
        buildIntentCommand(spec) {
            const verb = { activity: 'start', service: 'startservice', broadcast: 'broadcast' }[spec.kind];
            if (!verb) fail('Unknown intent kind');
            const parts = ['am', verb];
            if (spec.action) parts.push('-a', q(ident(spec.action, 'action')));
            if (spec.component) {
                if (!/^[A-Za-z0-9_.]+\/[A-Za-z0-9_.$]+$/.test(spec.component)) fail('Invalid component (expected package/Class)');
                parts.push('-n', q(spec.component));
            }
            if (spec.data) parts.push('-d', q(String(spec.data)));
            if (spec.mimeType) { if (!/^[\w.+-]+\/[\w.+*-]+$/.test(spec.mimeType)) fail('Invalid MIME type'); parts.push('-t', q(spec.mimeType)); }
            for (const c of spec.categories || []) parts.push('-c', q(ident(c, 'category')));
            if (spec.package) parts.push('-p', q(pkgName(spec.package)));
            const flag = { string: '--es', int: '--ei', bool: '--ez', long: '--el', float: '--ef', uri: '--eu' };
            for (const e of spec.extras || []) {
                if (!flag[e.type]) fail('Unknown extra type: ' + e.type);
                ident(e.key, 'extra key');
                let val = e.value;
                if (e.type === 'int' || e.type === 'long') val = String(int(val, 'extra value', -9007199254740991, 9007199254740991));
                else if (e.type === 'float') { if (!isFinite(Number(val))) fail('Invalid float'); val = String(Number(val)); }
                else if (e.type === 'bool') { if (!/^(true|false)$/.test(String(val))) fail('Bool extra must be true or false'); val = String(val); }
                parts.push(flag[e.type], q(e.key), q(String(val)));
            }
            if (!spec.action && !spec.component && !spec.data) fail('Provide an action, component or data URI');
            return parts.join(' ');
        }
        sendIntent(spec) { return this.sh(this.buildIntentCommand(spec), 20000); }

        /* ---------- content providers ---------- */

        buildProviderQuery(uri, { projection, where, sort } = {}) {
            const u = String(uri).trim();
            if (!/^content:\/\/[\w.\-@:/%+=,;~$&*()'!]+$/.test(u)) fail('URI must start with content://');
            const parts = ['content', 'query', '--uri', q(u)];
            if (projection) { if (!/^[\w:, .*]+$/.test(projection)) fail('Invalid projection'); parts.push('--projection', q(projection)); }
            if (where) parts.push('--where', q(where));
            if (sort) { if (!/^[\w, ]+$/.test(sort)) fail('Invalid sort'); parts.push('--sort', q(sort)); }
            return parts.join(' ');
        }
        queryProvider(uri, opts) { return this.sh(this.buildProviderQuery(uri, opts), 30000); }

        /* ---------- packages / permissions ---------- */

        grantPermission(pkg, perm) { return this.sh(`pm grant ${pkgName(pkg)} ${q(ident(perm, 'permission'))}`); }
        revokePermission(pkg, perm) { return this.sh(`pm revoke ${pkgName(pkg)} ${q(ident(perm, 'permission'))}`); }
        setAppEnabled(pkg, enabled) { return this.sh(enabled ? `pm enable ${pkgName(pkg)}` : `pm disable-user --user 0 ${pkgName(pkg)}`); }
        appOps(pkg) { return this.sh(`appops get ${pkgName(pkg)}`); }
        killPackage(pkg) { return this.sh(`am force-stop ${pkgName(pkg)}`); }
        killPid(pid) { return this.sh(`kill ${int(pid, 'pid', 2, 4194304)}`); }

        /** Installed packages with version and installer, as [{ pkg, versionCode, installer }]. */
        async packageSnapshot(includeSystem = false) {
            const out = await this.sh(`pm list packages ${includeSystem ? '' : '-3 '}-i --show-versioncode`, 60000);
            const list = [];
            for (const line of out.split('\n')) {
                const m = /^package:(\S+)(.*)$/.exec(line.trim());
                if (!m) continue;
                const rest = m[2];
                list.push({ pkg: m[1], versionCode: (/versionCode:(\d+)/.exec(rest) || [])[1] || null, installer: (/installer=(\S+)/.exec(rest) || [])[1] || null });
            }
            return list.sort((a, b) => a.pkg.localeCompare(b.pkg));
        }

        static diffSnapshots(oldList, newList) {
            const o = new Map(oldList.map(p => [p.pkg, p])), n = new Map(newList.map(p => [p.pkg, p]));
            const added = [], removed = [], updated = [], installerChanged = [];
            for (const [k, v] of n) {
                const prev = o.get(k);
                if (!prev) added.push(v);
                else {
                    if (prev.versionCode !== v.versionCode) updated.push({ pkg: k, from: prev.versionCode, to: v.versionCode });
                    if (prev.installer !== v.installer) installerChanged.push({ pkg: k, from: prev.installer, to: v.installer });
                }
            }
            for (const [k, v] of o) if (!n.has(k)) removed.push(v);
            return { added, removed, updated, installerChanged };
        }

        /* ---------- settings / properties / services ---------- */

        _ns(ns) { if (!SETTING_NS.includes(ns)) fail('Unknown settings namespace'); return ns; }
        async listSettings(ns) {
            const out = await this.sh(`settings list ${this._ns(ns)}`, 30000);
            return out.split('\n').map(l => { const i = l.indexOf('='); return i > 0 ? { key: l.slice(0, i), value: l.slice(i + 1) } : null; }).filter(Boolean);
        }
        getSetting(ns, key) { return this.sh(`settings get ${this._ns(ns)} ${q(this._key(key))}`); }
        putSetting(ns, key, value) { return this.sh(`settings put ${this._ns(ns)} ${q(this._key(key))} ${q(String(value))}`); }
        deleteSetting(ns, key) { return this.sh(`settings delete ${this._ns(ns)} ${q(this._key(key))}`); }
        _key(k) { if (!/^[A-Za-z0-9_.:-]+$/.test(String(k || ''))) fail('Invalid setting key'); return k; }

        async listProps() {
            const out = await this.sh('getprop', 30000);
            const props = [];
            for (const line of out.split('\n')) {
                const m = /^\[([^\]]+)\]: \[(.*)\]$/.exec(line.trim());
                if (m) props.push({ key: m[1], value: m[2] });
            }
            return props.sort((a, b) => a.key.localeCompare(b.key));
        }

        async listDumpsysServices() {
            const out = await this.sh('dumpsys -l', 15000);
            return out.split('\n').map(s => s.trim()).filter(s => /^[A-Za-z0-9_.:-]+$/.test(s)).sort();
        }
        dumpsys(service, args = '') {
            if (!/^[A-Za-z0-9_.:-]+$/.test(service)) fail('Invalid service name');
            if (args && !/^[\w\- .:=,]*$/.test(args)) fail('Invalid dumpsys arguments');
            return this.sh(`dumpsys ${q(service)}${args ? ' ' + args.split(/\s+/).filter(Boolean).map(q).join(' ') : ''}`, 60000);
        }

        /* ---------- diagnostics ---------- */

        logSnapshot(buffer = 'main', lines = 3000) {
            if (!LOG_BUFFERS.includes(buffer)) fail('Unknown log buffer');
            return this.sh(`logcat -b ${buffer} -d -v threadtime -t ${int(lines, 'lines', 1, 200000)}`, 60000);
        }
        topSnapshot(count = 25) { return this.sh(`top -b -n 1 -m ${int(count, 'count', 1, 200)}`, 20000); }

        async storageSummary() {
            const out = await this.sh('df -h 2>/dev/null', 15000);
            const rows = [];
            for (const line of out.split('\n').slice(1)) {
                const c = line.trim().split(/\s+/);
                if (c.length >= 6 && /^\//.test(c[c.length - 1])) rows.push({ filesystem: c[0], size: c[1], used: c[2], avail: c[3], usePct: c[4], mount: c[5] });
            }
            return rows;
        }

        async networkInfo() {
            const out = await this.sh('echo @@ADDR; ip -o addr 2>/dev/null; echo @@ROUTE; ip route 2>/dev/null; echo @@DNS; getprop net.dns1; getprop net.dns2; echo @@PROXY; settings get global http_proxy; echo @@PRIVDNS; settings get global private_dns_mode; settings get global private_dns_specifier', 20000);
            const sec = {}; let cur = null;
            for (const line of out.split('\n')) { const m = /^@@(\w+)$/.exec(line.trim()); if (m) { cur = m[1]; sec[cur] = []; } else if (cur && line.trim()) sec[cur].push(line.trim()); }
            const addresses = (sec.ADDR || []).map(l => { const m = /^\d+:\s+(\S+)\s+(inet6?)\s+(\S+)/.exec(l); return m ? { iface: m[1], family: m[2], address: m[3] } : null; }).filter(Boolean);
            const proxy = (sec.PROXY || [''])[0];
            return {
                addresses, routes: sec.ROUTE || [], dns: (sec.DNS || []).filter(Boolean),
                proxy: !proxy || proxy === 'null' || proxy === ':0' ? null : proxy,
                privateDns: { mode: (sec.PRIVDNS || [])[0] || null, host: (sec.PRIVDNS || [])[1] && (sec.PRIVDNS || [])[1] !== 'null' ? sec.PRIVDNS[1] : null }
            };
        }

        /** Set the global HTTP proxy (e.g. to route traffic through an interception proxy you control). */
        setProxy(host, port) {
            const h = String(host).trim();
            const okHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(h) ? h.split('.').every(x => +x <= 255) : /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(h);
            if (!okHost) fail('Invalid proxy host');
            return this.sh(`settings put global http_proxy ${q(h + ':' + int(port, 'port', 1, 65535))}`);
        }
        /** Remove the global proxy. ":0" is Android's documented "no proxy" value; the key is deleted afterwards. */
        async clearProxy() {
            await this.sh(`settings put global http_proxy ${q(':0')}`);
            await this.sh('settings delete global global_http_proxy_host; settings delete global global_http_proxy_port; settings delete global global_http_proxy_exclusion_list');
            return this.sh('settings get global http_proxy');
        }

        /** Record the screen (max 180 s on Android) and return the MP4 bytes. */
        async screenRecord(seconds = 10, onProgress = null) {
            const secs = int(seconds, 'seconds', 1, 180);
            const tmp = `/data/local/tmp/.adbaud_rec_${Date.now()}.mp4`;
            try {
                await this.sh(`screenrecord --time-limit ${secs} ${q(tmp)}`, (secs + 30) * 1000);
                return await this.adb.pullFile(tmp, onProgress);
            } finally {
                this.sh(`rm -f ${q(tmp)}`).catch(() => {});
            }
        }
    }

    DeviceToolkit.KEYS = KEYS;
    global.DeviceToolkit = DeviceToolkit;
})(typeof window !== 'undefined' ? window : globalThis);
