/**
 * ADB Auditor - offline APK static analyzer (runs entirely in the browser, no device needed).
 * ZIP reader, binary AndroidManifest decoder, DEX string scanner, signing-block / certificate parsing.
 *
 * @author Sandeep Wawdane (original creator of ADB Auditor)
 * @contributor 0x0806 (APK static analysis)
 * @license See LICENSE (CC BY-NC-ND 4.0, (c) Sandeep Wawdane)
 */
(function(global) {
    'use strict';

    const U = global.ABUtils;

    /* ---------- ZIP ---------- */

    class ZipReader {
        constructor(bytes) {
            this.bytes = bytes;
            this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
            this.entries = new Map();
            this._parse();
        }

        _parse() {
            const v = this.view, len = this.bytes.length;
            let eocd = -1;
            for (let i = len - 22; i >= Math.max(0, len - 22 - 65535); i--) {
                if (v.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
            }
            if (eocd < 0) throw new Error('Not a ZIP/APK file (end of central directory not found)');
            const count = v.getUint16(eocd + 10, true);
            this.centralSize = v.getUint32(eocd + 12, true);
            this.centralOffset = v.getUint32(eocd + 16, true);
            if (count === 0xffff || this.centralOffset === 0xffffffff) throw new Error('ZIP64 archives are not supported');
            let p = this.centralOffset;
            const dec = new TextDecoder();
            for (let i = 0; i < count; i++) {
                if (p + 46 > len || v.getUint32(p, true) !== 0x02014b50) throw new Error('Corrupt ZIP central directory');
                const nameLen = v.getUint16(p + 28, true), extraLen = v.getUint16(p + 30, true), commentLen = v.getUint16(p + 32, true);
                const name = dec.decode(this.bytes.subarray(p + 46, p + 46 + nameLen));
                this.entries.set(name, {
                    name, method: v.getUint16(p + 10, true), crc: v.getUint32(p + 16, true),
                    compressedSize: v.getUint32(p + 20, true), size: v.getUint32(p + 24, true),
                    localOffset: v.getUint32(p + 42, true)
                });
                p += 46 + nameLen + extraLen + commentLen;
            }
        }

        names() { return Array.from(this.entries.keys()); }
        has(name) { return this.entries.has(name); }

        async read(name) {
            const e = this.entries.get(name);
            if (!e) throw new Error('No such entry: ' + name);
            const v = this.view, o = e.localOffset;
            if (v.getUint32(o, true) !== 0x04034b50) throw new Error('Corrupt local header for ' + name);
            // the local header carries its own name/extra lengths, which may differ from the central directory's
            const start = o + 30 + v.getUint16(o + 26, true) + v.getUint16(o + 28, true);
            const raw = this.bytes.subarray(start, start + e.compressedSize);
            if (e.method === 0) return raw;
            if (e.method !== 8) throw new Error(`Unsupported compression method ${e.method} for ${name}`);
            return inflateRaw(raw, e.size);
        }
    }

    async function inflateRaw(raw, expectedSize) {
        const stream = new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
        const out = new Uint8Array(await new Response(stream).arrayBuffer());
        if (expectedSize && out.length !== expectedSize) throw new Error('Decompressed size mismatch');
        return out;
    }

    /* ---------- Binary AndroidManifest (AXML) ---------- */

    // Resource IDs of android.R.attr.* (taken from the platform android.jar) - robust against stripped attribute names.
    const ATTR_BY_ID = {
        0x1010003: 'name', 0x1010010: 'exported', 0x1010006: 'permission', 0x101000f: 'debuggable', 0x1010280: 'allowBackup',
        0x10104ec: 'usesCleartextTraffic', 0x1010527: 'networkSecurityConfig', 0x101020c: 'minSdkVersion', 0x1010270: 'targetSdkVersion',
        0x101021b: 'versionCode', 0x101021c: 'versionName', 0x1010027: 'scheme', 0x1010028: 'host', 0x1010029: 'port', 0x101002a: 'path',
        0x101002b: 'pathPrefix', 0x101002c: 'pathPattern', 0x1010026: 'mimeType', 0x10104ee: 'autoVerify', 0x1010018: 'authorities',
        0x101001b: 'grantUriPermissions', 0x1010007: 'readPermission', 0x1010008: 'writePermission', 0x1010272: 'testOnly',
        0x1010603: 'requestLegacyExternalStorage', 0x10104eb: 'fullBackupContent', 0x101063e: 'dataExtractionRules', 0x101000e: 'enabled',
        0x1010011: 'process', 0x1010001: 'label', 0x1010024: 'value', 0x1010025: 'resource', 0x1010271: 'maxSdkVersion',
        0x10104ea: 'extractNativeLibs', 0x1010012: 'taskAffinity', 0x101001d: 'launchMode', 0x1010505: 'directBootAware',
        0x101000c: 'hasCode', 0x10103a9: 'isolatedProcess', 0x1010599: 'foregroundServiceType', 0x1010204: 'allowTaskReparenting',
        0x1010017: 'excludeFromRecents', 0x1010005: 'allowClearUserData', 0x1010644: 'usesPermissionFlags'
    };

    function readStringPool(view, bytes, base) {
        const stringCount = view.getUint32(base + 8, true);
        const flags = view.getUint32(base + 16, true);
        const stringsStart = view.getUint32(base + 20, true);
        const utf8 = (flags & 0x100) !== 0;
        const offsets = [];
        for (let i = 0; i < stringCount; i++) offsets.push(view.getUint32(base + 28 + i * 4, true));
        const out = [];
        const dec8 = new TextDecoder('utf-8');
        for (const off of offsets) {
            let p = base + stringsStart + off;
            if (utf8) {
                let n = bytes[p++]; if (n & 0x80) n = ((n & 0x7f) << 8) | bytes[p++];      // utf16 length (skipped)
                let m = bytes[p++]; if (m & 0x80) m = ((m & 0x7f) << 8) | bytes[p++];      // utf8 byte length
                out.push(dec8.decode(bytes.subarray(p, p + m)));
            } else {
                let n = view.getUint16(p, true); p += 2;
                if (n & 0x8000) { n = ((n & 0x7fff) << 16) | view.getUint16(p, true); p += 2; }
                let s = '';
                for (let i = 0; i < n; i++) s += String.fromCharCode(view.getUint16(p + i * 2, true));
                out.push(s);
            }
        }
        return out;
    }

    /** Decode a binary XML document to { name, attrs, children }. attrs[name] = { value, type, ref }. */
    function decodeAxml(bytes) {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        if (view.getUint16(0, true) !== 0x0003) throw new Error('Not a binary XML document');
        const total = Math.min(view.getUint32(4, true), bytes.length);
        let pool = [], resIds = [], root = null;
        const stack = [];
        let p = view.getUint16(2, true);
        while (p + 8 <= total) {
            const type = view.getUint16(p, true), size = view.getUint32(p + 4, true);
            if (size < 8) break;
            if (type === 0x0001) pool = readStringPool(view, bytes, p);
            else if (type === 0x0180) { for (let i = 8; i < size; i += 4) resIds.push(view.getUint32(p + i, true)); }
            else if (type === 0x0102) {
                const nameIdx = view.getUint32(p + 20, true);
                const attrCount = view.getUint16(p + 28, true);
                const node = { name: pool[nameIdx] || '', attrs: {}, children: [] };
                for (let i = 0; i < attrCount; i++) {
                    const a = p + 36 + i * 20;
                    const aNameIdx = view.getUint32(a + 4, true), rawIdx = view.getUint32(a + 8, true);
                    const dataType = view.getUint8(a + 15), data = view.getUint32(a + 16, true);
                    const id = resIds[aNameIdx];
                    const attrName = (id !== undefined && ATTR_BY_ID[id]) || pool[aNameIdx] || ('attr_0x' + (id || 0).toString(16));
                    let value, ref = false;
                    if (rawIdx !== 0xffffffff) value = pool[rawIdx];
                    else if (dataType === 0x03) value = pool[data];
                    else if (dataType === 0x12) value = data !== 0;
                    else if (dataType === 0x10) value = data | 0;
                    else if (dataType === 0x11) value = data;
                    else if (dataType === 0x01 || dataType === 0x02) { value = '@0x' + data.toString(16); ref = true; }
                    else value = data;
                    node.attrs[attrName] = { value, type: dataType, ref };
                }
                if (stack.length) stack[stack.length - 1].children.push(node); else root = node;
                stack.push(node);
            } else if (type === 0x0103) stack.pop();
            p += size;
        }
        if (!root) throw new Error('Empty binary XML document');
        return root;
    }

    /* ---------- Manifest summary + findings ---------- */

    const attr = (node, name) => (node.attrs[name] ? node.attrs[name].value : undefined);
    const attrRef = (node, name) => !!(node.attrs[name] && node.attrs[name].ref);
    const findAll = (node, name, out = []) => { if (node.name === name) out.push(node); node.children.forEach(c => findAll(c, name, out)); return out; };

    const DANGEROUS = global.SecurityAuditor ? global.SecurityAuditor.DANGEROUS_PERMS : null;

    function summarizeManifest(root) {
        const s = { package: attr(root, 'package'), versionName: attr(root, 'versionName'), versionCode: attr(root, 'versionCode') };
        const sdk = findAll(root, 'uses-sdk')[0];
        s.minSdk = sdk ? attr(sdk, 'minSdkVersion') : undefined;
        s.targetSdk = sdk ? attr(sdk, 'targetSdkVersion') : undefined;
        s.permissions = findAll(root, 'uses-permission').concat(findAll(root, 'uses-permission-sdk-23')).map(n => attr(n, 'name')).filter(Boolean);
        s.customPermissions = findAll(root, 'permission').map(n => attr(n, 'name')).filter(Boolean);
        const app = findAll(root, 'application')[0] || { attrs: {}, children: [] };
        const flag = (n) => (app.attrs[n] ? (app.attrs[n].ref ? 'unknown' : !!app.attrs[n].value) : undefined);
        s.application = {
            debuggable: flag('debuggable'), allowBackup: flag('allowBackup'), usesCleartextTraffic: flag('usesCleartextTraffic'),
            testOnly: flag('testOnly'), requestLegacyExternalStorage: flag('requestLegacyExternalStorage'),
            hasNetworkSecurityConfig: !!app.attrs.networkSecurityConfig, hasFullBackupContent: !!app.attrs.fullBackupContent,
            hasDataExtractionRules: !!app.attrs.dataExtractionRules, extractNativeLibs: flag('extractNativeLibs')
        };
        const target = parseInt(s.targetSdk, 10);
        s.components = [];
        for (const kind of ['activity', 'activity-alias', 'service', 'receiver', 'provider']) {
            for (const n of findAll(app, kind)) {
                const filters = n.children.filter(c => c.name === 'intent-filter').map(f => ({
                    actions: f.children.filter(c => c.name === 'action').map(c => attr(c, 'name')),
                    categories: f.children.filter(c => c.name === 'category').map(c => attr(c, 'name')),
                    data: f.children.filter(c => c.name === 'data').map(c => ({
                        scheme: attr(c, 'scheme'), host: attr(c, 'host'), path: attr(c, 'path'), pathPrefix: attr(c, 'pathPrefix'),
                        pathPattern: attr(c, 'pathPattern'), mimeType: attr(c, 'mimeType')
                    })),
                    autoVerify: attr(f, 'autoVerify') === true
                }));
                let exported = attr(n, 'exported'), exportedExplicit = true;
                if (attrRef(n, 'exported')) exported = 'unknown';
                else if (exported === undefined) {
                    exportedExplicit = false;
                    exported = kind === 'provider' ? !(target >= 17) : filters.length > 0;     // implicit rules
                }
                s.components.push({
                    kind, name: attr(n, 'name'), exported, exportedExplicit, enabled: attr(n, 'enabled') !== false,
                    permission: attr(n, 'permission'), readPermission: attr(n, 'readPermission'), writePermission: attr(n, 'writePermission'),
                    authorities: attr(n, 'authorities'), grantUriPermissions: attr(n, 'grantUriPermissions') === true, intentFilters: filters
                });
            }
        }
        return s;
    }

    function manifestFindings(s) {
        const f = [];
        const add = (severity, id, title, detail, recommendation) => f.push({ severity, id, title, detail, recommendation });
        const a = s.application;
        if (a.debuggable === true) add('critical', 'debuggable', 'Application is debuggable', 'android:debuggable="true"', 'Build release variants with debuggable=false');
        if (a.testOnly === true) add('medium', 'testOnly', 'Test-only application', 'android:testOnly="true"', 'Do not ship test-only builds');
        if (a.allowBackup !== false) add('medium', 'allowBackup', 'Backup is allowed', a.allowBackup === undefined ? 'allowBackup not set (defaults to true)' : 'android:allowBackup="true"', 'Set allowBackup="false" or define backup rules');
        if (a.usesCleartextTraffic === true) add('medium', 'cleartext', 'Cleartext traffic permitted', 'android:usesCleartextTraffic="true"', 'Use HTTPS only');
        else if (a.usesCleartextTraffic === undefined && !a.hasNetworkSecurityConfig && parseInt(s.targetSdk, 10) < 28) add('medium', 'cleartext-default', 'Cleartext allowed by default', `targetSdk ${s.targetSdk} < 28`, 'Raise targetSdk and add a network security config');
        if (a.requestLegacyExternalStorage === true) add('low', 'legacy-storage', 'Legacy external storage requested', 'requestLegacyExternalStorage=true', 'Migrate to scoped storage');
        if (parseInt(s.minSdk, 10) < 21) add('high', 'minSdk', 'Very old minSdkVersion', `minSdk ${s.minSdk}`, 'Raise minSdkVersion to at least 21');
        if (parseInt(s.targetSdk, 10) < 30) add('medium', 'targetSdk', 'Outdated targetSdkVersion', `targetSdk ${s.targetSdk}`, 'Target a recent API level');
        for (const c of s.components) {
            if (!c.enabled || c.exported !== true) continue;
            const guarded = c.permission || (c.kind === 'provider' && (c.readPermission || c.writePermission));
            if (c.kind === 'provider') {
                add(guarded ? 'low' : 'high', 'provider-exported', `Exported content provider ${c.name}`, guarded ? 'protected by a permission' : 'no permission required', 'Set exported=false or require permissions; validate selection/path arguments');
                if (c.grantUriPermissions) add('medium', 'grant-uri', `Provider ${c.name} grants URI permissions`, 'grantUriPermissions=true', 'Scope with <grant-uri-permission> paths');
            } else if (c.kind !== 'activity' && c.kind !== 'activity-alias' && !guarded) {
                add('medium', c.kind + '-exported', `Exported ${c.kind} ${c.name}`, c.exportedExplicit ? 'exported=true, no permission' : 'implicitly exported via intent-filter', 'Set exported=false or add a signature permission');
            }
        }
        for (const c of s.components) {
            for (const flt of c.intentFilters) {
                const browsable = flt.categories.includes('android.intent.category.BROWSABLE');
                const schemes = flt.data.map(d => d.scheme).filter(Boolean);
                const custom = schemes.filter(x => !/^https?$/i.test(x));
                if (browsable && custom.length) add('low', 'custom-scheme', `Custom URL scheme ${custom[0]}:// on ${c.name}`, 'any app or web page can invoke it', 'Validate all deep-link input; prefer verified App Links');
                if (browsable && schemes.some(x => /^https?$/i.test(x)) && !flt.autoVerify) add('low', 'unverified-link', `HTTP(S) link on ${c.name} without autoVerify`, 'App Links not verified', 'Add android:autoVerify="true" and publish assetlinks.json');
            }
        }
        const danger = s.permissions.filter(p => DANGEROUS && DANGEROUS[p]);
        if (danger.length) add('info', 'dangerous-permissions', `${danger.length} dangerous permission(s) requested`, danger.map(p => p.replace('android.permission.', '')).join(', '), 'Request only what is needed');
        return f;
    }

    /* ---------- DEX ---------- */

    function readDexStrings(dex, limit = 400000) {
        const v = new DataView(dex.buffer, dex.byteOffset, dex.byteLength);
        if (dex.length < 0x70 || dex[0] !== 0x64 || dex[1] !== 0x65 || dex[2] !== 0x78) throw new Error('Not a DEX file');
        const count = Math.min(v.getUint32(0x38, true), limit), idsOff = v.getUint32(0x3c, true);
        const dec = new TextDecoder();
        const out = [];
        for (let i = 0; i < count; i++) {
            let p = v.getUint32(idsOff + i * 4, true);
            while (dex[p] & 0x80) p++;   // skip ULEB128 utf16 length
            p++;
            let e = p;
            while (e < dex.length && dex[e] !== 0) e++;
            if (e - p <= 4096) out.push(dec.decode(dex.subarray(p, e)));
        }
        return out;
    }

    const DEX_SECRETS = [
        ['aws_access_key', /\bAKIA[0-9A-Z]{16}\b/], ['google_api_key', /\bAIza[0-9A-Za-z_-]{35}\b/], ['private_key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
        ['slack_token', /\bxox[abprs]-[0-9A-Za-z-]{10,}/], ['github_token', /\bgh[pousr]_[A-Za-z0-9]{30,}\b/], ['stripe_live_key', /\b[sr]k_live_[0-9A-Za-z]{16,}\b/],
        ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/], ['firebase_url', /https:\/\/[a-z0-9-]+\.firebaseio\.com/]
    ];
    const mask = (s) => (s.length <= 8 ? '***' : s.slice(0, 4) + '***(' + s.length + ' chars)');

    const API_HINTS = [
        ['Runtime exec', /Ljava\/lang\/Runtime;/, 'medium', 'Process execution APIs referenced (heuristic)'],
        ['Dynamic code loading', /dalvik\/system\/DexClassLoader/, 'medium', 'DexClassLoader referenced - code may be loaded at runtime (heuristic)'],
        ['Allow-all hostname verifier', /ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier/, 'high', 'Hostname verification may be disabled'],
        ['Custom TrustManager', /javax\/net\/ssl\/X509TrustManager/, 'low', 'Custom X509TrustManager - verify it validates certificates (heuristic)'],
        ['WebView JavaScript', /setJavaScriptEnabled/, 'low', 'WebView JavaScript enabled somewhere'],
        ['JavaScript bridge', /addJavascriptInterface/, 'medium', 'JavaScript bridge exposed to web content'],
        ['WebView file access', /setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs/, 'high', 'WebView allows file URL cross-origin access'],
        ['World-readable files', /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/, 'high', 'World-accessible file modes referenced'],
        ['Weak hash', /^(MD5|MD2|SHA-?1)$/i, 'low', 'Weak hash algorithm name present (heuristic)'],
        ['Weak cipher', /^(DES|DESede|RC4|RC2|Blowfish)(\/|$)|AES\/ECB/i, 'medium', 'Weak cipher or ECB mode name present (heuristic)'],
        ['SQL raw query', /rawQuery|execSQL/, 'info', 'Raw SQL APIs used - check for injection (heuristic)'],
        ['Clipboard access', /Landroid\/content\/ClipboardManager;/, 'info', 'Clipboard APIs referenced']
    ];

    const TRACKERS = [
        ['Firebase Analytics', 'Lcom/google/firebase/analytics'], ['Google Ads', 'Lcom/google/android/gms/ads'], ['Facebook SDK', 'Lcom/facebook/'],
        ['AppsFlyer', 'Lcom/appsflyer'], ['Adjust', 'Lcom/adjust/sdk'], ['Flurry', 'Lcom/flurry'], ['Mixpanel', 'Lcom/mixpanel'], ['Branch', 'Lio/branch'],
        ['Crashlytics', 'Lcom/google/firebase/crashlytics'], ['Amplitude', 'Lcom/amplitude'], ['Segment', 'Lcom/segment/analytics'], ['OneSignal', 'Lcom/onesignal'],
        ['AppLovin', 'Lcom/applovin'], ['Unity Ads', 'Lcom/unity3d/ads'], ['Vungle', 'Lcom/vungle'], ['IronSource', 'Lcom/ironsource'], ['Chartboost', 'Lcom/chartboost'],
        ['Bugsnag', 'Lcom/bugsnag'], ['Sentry', 'Lio/sentry'], ['AppCenter', 'Lcom/microsoft/appcenter'], ['New Relic', 'Lcom/newrelic'], ['Kochava', 'Lcom/kochava'],
        ['Braze', 'Lcom/braze'], ['CleverTap', 'Lcom/clevertap'], ['MoEngage', 'Lcom/moengage'], ['Urban Airship', 'Lcom/urbanairship']
    ];

    function scanDexStrings(strings) {
        const urls = new Set(), ips = new Set(), secrets = [], apis = [], trackers = new Set();
        const hay = strings.join('\n');
        for (const s of strings) {
            if (s.length < 7) continue;
            const m = s.match(/https?:\/\/[^\s"'<>\\]{4,200}/);
            if (m) urls.add(m[0]);
            if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(s) && !/^(0\.0\.0\.0|127\.0\.0\.1)/.test(s) && s.split(/[.:]/).slice(0, 4).every(x => +x <= 255)) ips.add(s);
            for (const [type, re] of DEX_SECRETS) { const mm = re.exec(s); if (mm) secrets.push({ type, sample: mask(mm[0]) }); }
        }
        for (const [label, re, severity, note] of API_HINTS) {
            const hit = re.source.startsWith('^') ? strings.some(s => re.test(s)) : re.test(hay);
            if (hit) apis.push({ label, severity, note });
        }
        for (const [label, prefix] of TRACKERS) if (hay.includes(prefix)) trackers.add(label);
        return { urls: [...urls].sort().slice(0, 300), ips: [...ips].sort(), secrets: dedupe(secrets), apis, trackers: [...trackers] };
    }
    const dedupe = (arr) => { const seen = new Set(); return arr.filter(x => { const k = x.type + x.sample; if (seen.has(k)) return false; seen.add(k); return true; }); };

    /* ---------- Certificates ---------- */

    function derRead(buf, pos) {
        let len = buf[pos + 1], p = pos + 2;
        if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[p++]; }
        return { tag: buf[pos], start: p, end: p + len, next: p + len };
    }
    const OID_NAMES = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST' };
    const SIG_ALGS = { '1.2.840.113549.1.1.4': 'MD5withRSA', '1.2.840.113549.1.1.5': 'SHA1withRSA', '1.2.840.113549.1.1.11': 'SHA256withRSA', '1.2.840.113549.1.1.12': 'SHA384withRSA',
        '1.2.840.113549.1.1.13': 'SHA512withRSA', '1.2.840.10045.4.3.2': 'SHA256withECDSA', '1.2.840.10045.4.3.3': 'SHA384withECDSA', '1.2.840.10040.4.3': 'SHA1withDSA', '2.16.840.1.101.3.4.3.2': 'SHA256withDSA', '1.2.840.113549.1.1.10': 'RSASSA-PSS' };
    function oidString(buf, n) {
        const b = buf.subarray(n.start, n.end);
        const parts = [Math.floor(b[0] / 40), b[0] % 40];
        let v = 0;
        for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i] & 0x7f); if (!(b[i] & 0x80)) { parts.push(v); v = 0; } }
        return parts.join('.');
    }
    function parseName(buf, n) {
        const out = [];
        let p = n.start;
        while (p < n.end) {
            const set = derRead(buf, p);
            const seq = derRead(buf, set.start);
            const oid = derRead(buf, seq.start);
            const val = derRead(buf, oid.next);
            out.push((OID_NAMES[oidString(buf, oid)] || oidString(buf, oid)) + '=' + new TextDecoder().decode(buf.subarray(val.start, val.end)));
            p = set.next;
        }
        return out.join(', ');
    }
    function parseTime(buf, n) {
        const s = new TextDecoder().decode(buf.subarray(n.start, n.end));
        const m = n.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z/.exec(s);
        if (!m) return null;
        const year = n.tag === 0x17 ? (+m[1] >= 50 ? 1900 + +m[1] : 2000 + +m[1]) : +m[1];
        return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0))).toISOString();
    }

    async function parseCertificate(der) {
        const cert = derRead(der, 0);
        const tbs = derRead(der, cert.start);
        let p = tbs.start;
        let n = derRead(der, p);
        if (n.tag === 0xa0) { p = n.next; n = derRead(der, p); }          // explicit version
        p = n.next;                                                          // serial
        const sigAlg = derRead(der, p); p = sigAlg.next;
        const issuer = derRead(der, p); p = issuer.next;
        const validity = derRead(der, p); p = validity.next;
        const subject = derRead(der, p); p = subject.next;
        const spki = derRead(der, p);
        const nb = derRead(der, validity.start), na = derRead(der, nb.next);
        const algOid = oidString(der, derRead(der, sigAlg.start));
        // public key
        const spkiAlg = derRead(der, spki.start);
        const keyOid = oidString(der, derRead(der, spkiAlg.start));
        let keyInfo = keyOid === '1.2.840.113549.1.1.1' ? 'RSA' : keyOid === '1.2.840.10045.2.1' ? 'EC' : keyOid;
        if (keyInfo === 'RSA') {
            const bits = derRead(der, spkiAlg.next);
            const rsaSeq = derRead(der, bits.start + 1);
            const mod = derRead(der, rsaSeq.start);
            let m = mod.start; while (der[m] === 0 && m < mod.end - 1) m++;
            const first = der[m];
            keyInfo = 'RSA-' + ((mod.end - m - 1) * 8 + (32 - Math.clz32(first)));
        }
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', der.slice(0, cert.end)));
        const subjectStr = parseName(der, subject), issuerStr = parseName(der, issuer);
        return {
            subject: subjectStr, issuer: issuerStr, notBefore: parseTime(der, nb), notAfter: parseTime(der, na),
            signatureAlgorithm: SIG_ALGS[algOid] || algOid, publicKey: keyInfo, selfSigned: subjectStr === issuerStr,
            sha256: Array.from(digest, b => b.toString(16).padStart(2, '0')).join(':'),
            debug: /Android Debug/i.test(subjectStr)
        };
    }

    /** Pull X.509 certificate DER blobs out of a PKCS#7 SignedData (META-INF/*.RSA|DSA|EC). */
    function certsFromPkcs7(der) {
        const root = derRead(der, 0);
        const ctx0 = derRead(der, derRead(der, root.start).next);       // [0] EXPLICIT content
        const signed = derRead(der, ctx0.start);
        let p = signed.start;
        for (let i = 0; i < 3; i++) p = derRead(der, p).next;           // version, digestAlgorithms, contentInfo
        const certs = derRead(der, p);
        if (certs.tag !== 0xa0) return [];
        const out = [];
        for (let q = certs.start; q < certs.end;) { const c = derRead(der, q); out.push(der.slice(q, c.next)); q = c.next; }
        return out;
    }

    /** APK Signing Block (v2/v3/v3.1): which schemes are present and the signer certificates. */
    function parseSigningBlock(bytes, centralOffset) {
        const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        const res = { present: false, schemes: [], certs: [] };
        if (centralOffset < 32) return res;
        const magic = new TextDecoder().decode(bytes.subarray(centralOffset - 16, centralOffset));
        if (magic !== 'APK Sig Block 42') return res;
        const size = Number(v.getBigUint64(centralOffset - 24, true));
        let p = centralOffset - size - 8 + 8;                              // start of first pair (after leading size field)
        const end = centralOffset - 24;
        res.present = true;
        while (p + 12 <= end) {
            const pairLen = Number(v.getBigUint64(p, true));
            const id = v.getUint32(p + 8, true);
            const valStart = p + 12, valEnd = p + 8 + pairLen;
            const scheme = { 0x7109871a: 2, 0xf05368c0: 3, 0x1b93ad61: 3.1 }[id];
            if (scheme) {
                res.schemes.push(scheme);
                try {
                    // signers sequence -> signer -> signed data -> certificates sequence -> certificate
                    let q = valStart + 4;                                   // skip signers length
                    const signerEnd = q + 4 + v.getUint32(q, true); q += 4;
                    const signedLen = v.getUint32(q, true); q += 4;         // signed data
                    const sdEnd = q + signedLen;
                    q += 4 + v.getUint32(q, true);                          // skip digests
                    const certsLen = v.getUint32(q, true); q += 4;
                    const certsEnd = q + certsLen;
                    while (q < certsEnd && q < sdEnd && q < signerEnd) { const cl = v.getUint32(q, true); res.certs.push(bytes.slice(q + 4, q + 4 + cl)); q += 4 + cl; }
                } catch (e) { /* leave certs empty */ }
            }
            p = valEnd;
            if (pairLen <= 0) break;
        }
        return res;
    }

    /* ---------- Orchestration ---------- */

    const FRAMEWORKS = [
        ['Flutter', /(^|\/)libflutter\.so$|flutter_assets\//], ['React Native', /libreactnativejni\.so|index\.android\.bundle|libhermes\.so/], ['Xamarin / .NET MAUI', /libmonodroid\.so|assemblies\/.*\.dll/],
        ['Unity', /libunity\.so|libil2cpp\.so/], ['Cordova / Ionic', /assets\/www\/cordova\.js|assets\/www\/index\.html/], ['Kotlin Multiplatform / Kotlin', /(^|\/)kotlin\//], ['Godot', /libgodot_android\.so/]
    ];

    async function hashBytes(bytes) {
        const out = {};
        for (const [label, algo] of [['sha256', 'SHA-256'], ['sha1', 'SHA-1']]) {
            out[label] = Array.from(new Uint8Array(await crypto.subtle.digest(algo, bytes)), b => b.toString(16).padStart(2, '0')).join('');
        }
        return out;
    }

    /** Full static analysis of an APK. Resolves to a report object (never throws for a partly broken APK). */
    async function analyzeApk(bytes, opts = {}) {
        const started = Date.now();
        const zip = new ZipReader(bytes);
        const names = zip.names();
        const report = { kind: 'apk-static', size: bytes.length, fileCount: names.length, hashes: await hashBytes(bytes), warnings: [] };

        try {
            const manifest = decodeAxml(await zip.read('AndroidManifest.xml'));
            report.manifest = summarizeManifest(manifest);
            report.manifestFindings = manifestFindings(report.manifest);
        } catch (e) { report.warnings.push('Manifest: ' + e.message); report.manifestFindings = []; }

        const dexNames = names.filter(n => /^classes\d*\.dex$/.test(n));
        report.dexCount = dexNames.length;
        if (opts.skipDex !== true) {
            const all = [];
            for (const n of dexNames) {
                try { all.push(...readDexStrings(await zip.read(n))); } catch (e) { report.warnings.push(`${n}: ${e.message}`); }
            }
            report.dex = Object.assign({ stringCount: all.length }, scanDexStrings(all));
        }

        const libs = names.filter(n => /^lib\/[^/]+\/.+\.so$/.test(n));
        report.nativeLibs = { abis: [...new Set(libs.map(n => n.split('/')[1]))], libs: [...new Set(libs.map(n => n.split('/').pop()))].sort() };
        report.frameworks = FRAMEWORKS.filter(([, re]) => names.some(n => re.test(n))).map(([l]) => l);
        report.embeddedCode = names.filter(n => /^assets\/.+\.(dex|jar|apk|so)$/i.test(n) || /^res\/raw\/.+\.(dex|jar|apk)$/i.test(n));

        // signing
        const sig = { v1: names.some(n => /^META-INF\/[^/]+\.(SF)$/i.test(n)), schemes: [], certs: [], notes: [] };
        const certDer = [];
        for (const n of names.filter(n => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(n))) {
            try { certDer.push(...certsFromPkcs7(await zip.read(n))); } catch (e) { sig.notes.push(`${n}: ${e.message}`); }
        }
        const block = parseSigningBlock(bytes, zip.centralOffset);
        sig.schemes = [...(sig.v1 ? [1] : []), ...block.schemes];
        certDer.push(...block.certs);
        const seen = new Set();
        for (const der of certDer) {
            try {
                const c = await parseCertificate(der);
                if (!seen.has(c.sha256)) { seen.add(c.sha256); sig.certs.push(c); }
            } catch (e) { sig.notes.push('Certificate: ' + e.message); }
        }
        if (!sig.schemes.length) sig.notes.push('No signature found (v1, v2 or v3) - APK appears unsigned');
        else if (!sig.certs.length) sig.notes.push('Signature scheme(s) present but no certificate could be parsed');
        sig.findings = [];
        if (sig.v1 && !block.present) sig.findings.push({ severity: 'low', title: 'v1 (JAR) signing only', detail: 'Vulnerable to Janus (CVE-2017-13156) on Android 5.0-8.0', recommendation: 'Sign with v2/v3' });
        for (const c of sig.certs) {
            if (c.debug) sig.findings.push({ severity: 'high', title: 'Signed with an Android debug certificate', detail: c.subject, recommendation: 'Sign release builds with a private release key' });
            if (/MD5|SHA1/.test(c.signatureAlgorithm)) sig.findings.push({ severity: 'medium', title: 'Weak certificate signature algorithm', detail: c.signatureAlgorithm, recommendation: 'Use SHA-256 or stronger' });
            const rsaBits = /^RSA-(\d+)/.exec(c.publicKey);
            if (rsaBits && +rsaBits[1] < 2048) sig.findings.push({ severity: 'medium', title: 'Short RSA key', detail: c.publicKey, recommendation: 'Use at least 2048-bit RSA' });
        }
        report.signing = sig;
        report.durationMs = Date.now() - started;
        report.findings = [...(report.manifestFindings || []), ...sig.findings.map(x => ({ ...x, id: 'signing' }))]
            .concat((report.dex ? report.dex.apis : []).map(a => ({ severity: a.severity, id: 'api', title: a.label, detail: a.note + ' (heuristic)', recommendation: '' })))
            .concat((report.dex ? report.dex.secrets : []).map(s => ({ severity: 'high', id: 'secret', title: `Possible hardcoded ${s.type}`, detail: s.sample, recommendation: 'Remove secrets from the app; use server-side secrets or the Keystore' })))
            .concat(report.embeddedCode.length ? [{ severity: 'low', id: 'embedded', title: 'Embedded executable code in assets/raw', detail: report.embeddedCode.slice(0, 5).join(', '), recommendation: 'Review what is loaded at runtime' }] : []);
        return report;
    }

    function apkReportToMarkdown(r, name = 'APK') {
        const m = r.manifest || {};
        const L = [`# APK Static Analysis - ${m.package || name}`, '', `- **Version:** ${m.versionName || '?'} (${m.versionCode ?? '?'})`, `- **SDK:** min ${m.minSdk ?? '?'}, target ${m.targetSdk ?? '?'}`,
            `- **SHA-256:** ${r.hashes.sha256}`, `- **Signing:** ${(r.signing.schemes.length ? 'v' + r.signing.schemes.join(', v') : 'none')}`, `- **Frameworks:** ${r.frameworks.join(', ') || 'native/Java'}`, '', '## Findings'];
        for (const f of r.findings) L.push(`- **[${f.severity}]** ${f.title}${f.detail ? ' - ' + f.detail : ''}${f.recommendation ? ' _(' + f.recommendation + ')_' : ''}`);
        if (r.dex) {
            L.push('', '## Network indicators (from DEX strings)', ...r.dex.urls.slice(0, 50).map(u => '- ' + u));
            if (r.dex.trackers.length) L.push('', '## Possible tracker/analytics SDKs (heuristic)', r.dex.trackers.join(', '));
        }
        L.push('', '---', 'Generated by ADB Auditor - created by Sandeep Wawdane, enhanced by 0x0806.');
        return L.join('\n');
    }

    global.ApkAnalyzer = { ZipReader, decodeAxml, summarizeManifest, manifestFindings, readDexStrings, scanDexStrings, parseCertificate, certsFromPkcs7, parseSigningBlock, analyzeApk, apkReportToMarkdown, ATTR_BY_ID };
})(typeof window !== 'undefined' ? window : globalThis);
