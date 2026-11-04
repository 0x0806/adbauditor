/**
 * ADB Auditor - security checks (OWASP MASVS / MASTG inspired).
 *
 * @preserve
 * @author Sandeep Wawdane (original creator of ADB Auditor)
 * @contributor 0x0806 (accuracy fixes, injection-safe commands, new checks, triage)
 * @license See LICENSE (CC BY-NC-ND 4.0, (c) Sandeep Wawdane)
 */
(function(global) {
    'use strict';

    const MODULE_KEY = 'dGhlY3liZXJzYW5kZWVw';   // original-author watermark - do not remove

    const U = global.ABUtils;
    const { shQuote, suWrap, isValidPackageName, parseLsLine, normalizeSeverity, maxSeverity } = U;

    const SENSITIVE_EXT = /\.(db|sqlite3?|json|xml|log|key|pem|p12|pfx|jks|keystore|bak|txt|csv|properties)$/i;

    const luhn = (digits) => {
        let sum = 0, alt = false;
        for (let i = digits.length - 1; i >= 0; i--) {
            let n = digits.charCodeAt(i) - 48;
            if (alt) { n *= 2; if (n > 9) n -= 9; }
            sum += n; alt = !alt;
        }
        return sum % 10 === 0;
    };
    const mask = (s) => (s.length <= 6 ? '***' : s.slice(0, 3) + '***(' + s.length + ' chars)');

    /** Patterns scanned for in logs / prefs. `validate` lowers false positives. */
    const SECRET_PATTERNS = [
        { type: 'password', severity: 'high', re: /passw(?:or)?d["']?\s*[=:]\s*["']?[^\s"'&,;]{3,}/gi },
        { type: 'token', severity: 'high', re: /(?:access_|auth_|refresh_|session_|id_)?token["']?\s*[=:]\s*["']?[A-Za-z0-9_\-.=]{10,}/gi },
        { type: 'api_key', severity: 'high', re: /api[_-]?key["']?\s*[=:]\s*["']?[A-Za-z0-9_\-.]{8,}/gi },
        { type: 'bearer_token', severity: 'high', re: /bearer\s+[A-Za-z0-9_\-.=]{10,}/gi },
        { type: 'jwt', severity: 'high', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g },
        { type: 'aws_access_key', severity: 'critical', re: /\bAKIA[0-9A-Z]{16}\b/g },
        { type: 'google_api_key', severity: 'high', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
        { type: 'private_key', severity: 'critical', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
        { type: 'secret', severity: 'high', re: /(?:client_)?secret["']?\s*[=:]\s*["']?[A-Za-z0-9_\-.]{6,}/gi },
        { type: 'credit_card', severity: 'critical', re: /\b(?:\d[ -]?){13,19}\b/g, validate: m => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d); } },
        { type: 'email', severity: 'low', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g }
    ];

    /** Turn SharedPreferences XML into `key=value` lines so the secret patterns can see them. */
    function prefsToText(xml) {
        const lines = [];
        const re = /<(?:string|int|long|boolean|float)\s+name="([^"]*)"(?:\s+value="([^"]*)")?\s*(?:\/>|>([^<]*)<)/g;
        let m;
        while ((m = re.exec(xml))) lines.push(m[1] + '=' + (m[2] !== undefined ? m[2] : (m[3] || '')));
        return lines.join('\n') || xml;
    }

    /** Scan text, returning [{type, severity, count, sample}] - raw values are never returned, only masked samples. */
    function scanForSecrets(text) {
        const out = [];
        for (const p of SECRET_PATTERNS) {
            const all = (String(text).match(p.re) || []).filter(m => !p.validate || p.validate(m));
            if (all.length) out.push({ type: p.type, severity: p.severity, count: all.length, sample: mask(all[0].trim()) });
        }
        return out;
    }

    const DANGEROUS_PERMS = {
        'android.permission.READ_EXTERNAL_STORAGE': { desc: 'Read files on external storage', group: 'Storage' },
        'android.permission.WRITE_EXTERNAL_STORAGE': { desc: 'Write files on external storage', group: 'Storage' },
        'android.permission.MANAGE_EXTERNAL_STORAGE': { desc: 'Access all files on device', group: 'Storage' },
        'android.permission.READ_MEDIA_IMAGES': { desc: 'Read images', group: 'Storage' },
        'android.permission.READ_MEDIA_VIDEO': { desc: 'Read videos', group: 'Storage' },
        'android.permission.READ_MEDIA_AUDIO': { desc: 'Read audio files', group: 'Storage' },
        'android.permission.CAMERA': { desc: 'Take photos and record videos', group: 'Camera' },
        'android.permission.RECORD_AUDIO': { desc: 'Record audio via microphone', group: 'Microphone' },
        'android.permission.ACCESS_FINE_LOCATION': { desc: 'Access precise GPS location', group: 'Location' },
        'android.permission.ACCESS_COARSE_LOCATION': { desc: 'Access approximate location', group: 'Location' },
        'android.permission.ACCESS_BACKGROUND_LOCATION': { desc: 'Access location in background', group: 'Location' },
        'android.permission.READ_CONTACTS': { desc: 'Read contact information', group: 'Contacts' },
        'android.permission.WRITE_CONTACTS': { desc: 'Modify contact information', group: 'Contacts' },
        'android.permission.GET_ACCOUNTS': { desc: 'List accounts on device', group: 'Contacts' },
        'android.permission.READ_PHONE_STATE': { desc: 'Read phone status and identity', group: 'Phone' },
        'android.permission.CALL_PHONE': { desc: 'Make phone calls directly', group: 'Phone' },
        'android.permission.READ_CALL_LOG': { desc: 'Read call history', group: 'Phone' },
        'android.permission.WRITE_CALL_LOG': { desc: 'Modify call history', group: 'Phone' },
        'android.permission.READ_SMS': { desc: 'Read SMS messages', group: 'SMS' },
        'android.permission.SEND_SMS': { desc: 'Send SMS messages', group: 'SMS' },
        'android.permission.RECEIVE_SMS': { desc: 'Receive SMS messages', group: 'SMS' },
        'android.permission.READ_CALENDAR': { desc: 'Read calendar events', group: 'Calendar' },
        'android.permission.WRITE_CALENDAR': { desc: 'Modify calendar events', group: 'Calendar' },
        'android.permission.BODY_SENSORS': { desc: 'Access body sensors like heart rate', group: 'Sensors' },
        'android.permission.ACTIVITY_RECOGNITION': { desc: 'Recognize physical activity', group: 'Sensors' },
        'android.permission.SYSTEM_ALERT_WINDOW': { desc: 'Draw over other apps (overlay attacks)', group: 'Special' },
        'android.permission.REQUEST_INSTALL_PACKAGES': { desc: 'Install other packages', group: 'Special' },
        'android.permission.QUERY_ALL_PACKAGES': { desc: 'See all installed apps', group: 'Special' },
        'android.permission.BIND_ACCESSIBILITY_SERVICE': { desc: 'Accessibility service (can read the screen)', group: 'Special' }
    };

    function newResult(id, category, title, description) {
        return { id, category, title, description, findings: [], severity: 'info', status: 'pass' };
    }
    function escalate(results, severity) {
        results.severity = maxSeverity(results.severity, severity);
    }

    class SecurityAuditor {
        constructor(adb) {
            this.adb = adb;
            this._dumpCache = new Map();
            this._root = null;
        }

        /* ---------- helpers ---------- */

        assertPackage(packageName) {
            if (!isValidPackageName(packageName)) throw new Error('Invalid package name');
        }

        sh(cmd, timeout) {
            return this.adb.shell(cmd, timeout);
        }

        /** `dumpsys package <pkg>` (cached for the lifetime of one audit). */
        async getPackageDump(packageName) {
            this.assertPackage(packageName);
            if (!this._dumpCache.has(packageName)) {
                this._dumpCache.set(packageName, await this.sh(`dumpsys package ${packageName}`, 60000));
            }
            return this._dumpCache.get(packageName);
        }

        clearCache() { this._dumpCache.clear(); }

        /** True when `su` works (cached). Uses a short timeout - some su managers wait for an on-device prompt. */
        async hasRoot() {
            if (this._root !== null) return this._root;
            try {
                this._root = /uid=0/.test(await this.sh(suWrap('id') + ' 2>&1', 8000));
            } catch (e) {
                this._root = false;
            }
            return this._root;
        }

        /**
         * Run a command inside an app's data dir: `run-as` (debuggable apps) first, then root.
         * Returns { out, via } or { out: null, via: null } when neither works.
         */
        async asApp(packageName, cmd) {
            this.assertPackage(packageName);
            // run-as execs directly (no shell), so wrap in sh -c to get globs and pipes
            const out = await this.sh(`run-as ${packageName} sh -c ${shQuote(cmd)} 2>&1`);
            if (!/run-as:|not debuggable|is unknown|Operation not permitted|Permission denied/i.test(out)) {
                return { out, via: 'run-as' };
            }
            if (await this.hasRoot()) {
                const rootOut = await this.sh(suWrap(`cd /data/data/${packageName} && ${cmd}`) + ' 2>&1');
                return { out: rootOut, via: 'root' };
            }
            return { out: null, via: null };
        }

        /** List a directory below the app's data dir. Returns parsed entries or null if inaccessible. */
        async listAppDir(packageName, relDir) {
            const { out } = await this.asApp(packageName, `ls -la ${shQuote(relDir)}`);
            if (out === null || /No such file|not found|Permission denied/i.test(out)) return null;
            return out.split('\n').map(parseLsLine).filter(Boolean);
        }

        /* ---------- MASVS-STORAGE ---------- */

        async testLocalStorage(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0001', 'MASVS-STORAGE', 'Local Storage for Sensitive Data',
                'Checks app storage directories for potentially sensitive data');
            try {
                const dirs = [['shared_prefs', 'shared_prefs', 'SharedPreferences file found - verify no sensitive data is stored in plaintext'],
                              ['databases', 'database', 'SQLite database found - verify encryption and no plaintext secrets']];
                let accessible = false;
                for (const [dir, type, note] of dirs) {
                    const entries = await this.listAppDir(packageName, dir);
                    if (!entries) continue;
                    accessible = true;
                    for (const e of entries.filter(x => !x.isDir && !/-(journal|wal|shm)$/.test(x.name))) {
                        results.findings.push({ type, file: e.name, size: e.size, note });
                    }
                }
                const files = await this.listAppDir(packageName, 'files');
                if (files) {
                    accessible = true;
                    if (files.length) results.findings.push({ type: 'files_directory', count: files.length, note: 'Files directory contains data - manual review recommended' });
                }

                // world-readable files inside private storage
                const wr = await this.asApp(packageName, `find . -type f -perm -o+r 2>/dev/null | head -50`);
                if (wr.out && wr.out.trim() && !/No such file|not found/.test(wr.out)) {
                    const list = wr.out.split('\n').map(s => s.trim()).filter(s => s.startsWith('./'));
                    if (list.length) {
                        results.findings.push({ type: 'world_readable_files', files: list, severity: 'high',
                            note: `${list.length} world-readable file(s) in private storage`,
                            recommendation: 'Use MODE_PRIVATE and remove world-readable permissions' });
                        escalate(results, 'high'); results.status = 'fail';
                    }
                }

                const ext = await this.sh(`ls -la ${shQuote(`/sdcard/Android/data/${packageName}/`)} 2>/dev/null || echo NONE`);
                if (!/NONE|No such file|Permission denied/.test(ext) && ext.trim()) {
                    const entries = ext.split('\n').map(parseLsLine).filter(Boolean);
                    const risky = entries.filter(e => !e.isDir && SENSITIVE_EXT.test(e.name));
                    results.findings.push({ type: 'external_storage', severity: 'medium',
                        note: `App uses external storage (${entries.length} entries${risky.length ? ', ' + risky.length + ' potentially sensitive' : ''}) - readable by other apps with storage access`,
                        recommendation: 'Keep sensitive data in internal storage' });
                    escalate(results, 'medium');
                }

                if (!accessible) {
                    results.findings.push({ type: 'inaccessible', note: 'App private storage is not accessible (app is not debuggable and device is not rooted) - internal storage could not be reviewed' });
                }
                if (results.status !== 'fail' && results.findings.some(f => f.type !== 'inaccessible')) results.status = 'review';
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        async testBackupEnabled(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0002', 'MASVS-STORAGE', 'Backup Configuration',
                'Checks if app allows backup which could expose sensitive data');
            try {
                const dump = await this.getPackageDump(packageName);
                const flags = U.parsePackageFlags(dump);
                if (flags.size === 0) {
                    results.status = 'error'; results.error = 'Could not read package flags (is the package installed?)';
                } else if (flags.has('ALLOW_BACKUP')) {
                    results.findings.push({ type: 'backup_enabled', severity: 'medium',
                        note: 'App allows backup (android:allowBackup=true) - app data can be extracted with `adb backup` or cloud backup',
                        recommendation: 'Set android:allowBackup="false" or exclude sensitive data via backup rules' });
                    escalate(results, 'medium'); results.status = 'fail';
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        async testLogcat(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0003', 'MASVS-STORAGE', 'Sensitive Data in Logs',
                'Analyzes app logs for potential sensitive data leakage (does not clear the device log buffer)');
            try {
                const pidOut = (await this.sh(`pidof ${packageName} 2>/dev/null`)).trim();
                const pid = pidOut.split(/\s+/)[0];
                let logs = '';
                if (/^\d+$/.test(pid)) logs = await this.sh(`logcat -d -v threadtime --pid=${pid} -t 3000 2>&1`);
                if (!logs || /Unrecognized Option|invalid option/i.test(logs)) {
                    logs = await this.sh(`logcat -d -v threadtime -t 5000 | grep -F ${shQuote(packageName)} | tail -500`);
                }
                const found = scanForSecrets(logs);
                for (const f of found) {
                    results.findings.push({ type: 'sensitive_log', dataType: f.type, count: f.count, sample: f.sample,
                        severity: f.severity, note: `Found ${f.count} potential ${f.type} value(s) in logs (e.g. ${f.sample})`,
                        recommendation: 'Remove sensitive values from log statements in release builds' });
                    if (f.severity !== 'low') { results.status = 'fail'; }
                    escalate(results, f.severity);
                }
                if (results.status === 'pass' && found.length) results.status = 'review';
                if (!found.length && logs.length > 100) {
                    results.findings.push({ type: 'verbose_logging', note: 'App produces logs - no secrets matched, but review for sensitive data' });
                    results.status = 'review';
                }
                if (!logs) results.findings.push({ type: 'no_logs', note: 'No log lines available for this app (not running?). Start the app and re-run.' });
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        /** Experimental: reports whether a clipboard service call returns content. */
        async testClipboard() {
            const results = newResult('MASTG-TEST-0004', 'MASVS-STORAGE', 'Clipboard Data Exposure',
                'Checks clipboard for sensitive data that could be accessed by other apps (best effort)');
            try {
                const clipboard = await this.sh('service call clipboard 2 s16 com.android.shell 2>/dev/null');
                if (clipboard && clipboard.length > 50) {
                    results.findings.push({ type: 'clipboard_data', note: 'Clipboard contains data - verify sensitive data is not being copied' });
                    results.status = 'review';
                }
            } catch (e) {
                results.findings.push({ type: 'clipboard_check_failed', note: 'Could not check clipboard (may require root)' });
            }
            return results;
        }

        /** Sensitive data stored in SharedPreferences (key names / values are never reported verbatim). */
        async testAuthStorage(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0010', 'MASVS-AUTH', 'Authentication Data Storage',
                'Checks for insecure storage of authentication tokens and credentials in SharedPreferences');
            try {
                const { out, via } = await this.asApp(packageName, 'cat shared_prefs/*.xml');
                if (out === null) {
                    results.findings.push({ type: 'inaccessible', note: 'SharedPreferences not accessible (not debuggable, no root) - could not check' });
                } else if (!/No such file|not found/i.test(out)) {
                    for (const f of scanForSecrets(prefsToText(out))) {
                        if (f.type === 'email') continue;
                        results.findings.push({ type: 'insecure_storage', dataType: f.type, count: f.count, sample: f.sample, severity: 'medium',
                            note: `${f.type} appears ${f.count}x in plaintext SharedPreferences (via ${via}) - verify it is encrypted`,
                            recommendation: 'Store secrets in the Android Keystore / EncryptedSharedPreferences' });
                        escalate(results, 'medium'); results.status = 'review';
                    }
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        /* ---------- MASVS-PLATFORM ---------- */

        async testExportedComponents(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0020', 'MASVS-PLATFORM', 'Exported Components Analysis',
                'Analyzes components reachable by other apps (components with intent filters, and content providers)');
            try {
                const dump = await this.getPackageDump(packageName);
                const filters = U.parseResolverFilters(dump, packageName);
                const groups = { activity: 'exported_activities', service: 'exported_services', receiver: 'exported_receivers' };
                const notes = {
                    activity: 'Exported activities found - verify they handle untrusted input safely',
                    service: 'Exported services found - verify proper permission checks',
                    receiver: 'Exported broadcast receivers found - verify intent filter security'
                };
                for (const kind of Object.keys(groups)) {
                    const comps = [...new Set(filters.filter(f => f.kind === kind).map(f => f.component))];
                    if (!comps.length) continue;
                    const unprotected = [...new Set(filters.filter(f => f.kind === kind && !f.permission).map(f => f.component))];
                    const finding = { type: groups[kind], count: comps.length, components: comps, note: notes[kind],
                        unprotected: unprotected.length };
                    if (kind !== 'activity' && unprotected.length) {
                        finding.severity = 'medium';
                        finding.note += ` (${unprotected.length} without a permission requirement)`;
                        escalate(results, 'medium');
                    }
                    results.findings.push(finding);
                }

                const providerSection = (dump.match(/Registered ContentProviders:[\s\S]*?(?=\n\S|$)/) || [''])[0];
                const re = new RegExp(U.escapeRegExp(packageName) + '/[\\w.$]+', 'g');
                const providers = [...new Set(providerSection.match(re) || [])];
                if (providers.length) {
                    results.findings.push({ type: 'exported_providers', count: providers.length, components: providers, severity: 'medium',
                        note: 'Content providers found - verify SQL injection and path traversal protection, and that grantUriPermissions is scoped' });
                    escalate(results, 'medium');
                }
                if (results.findings.length) results.status = 'review';
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        /** Browsable VIEW filters: custom URL schemes and web links. */
        async testDeepLinks(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0021', 'MASVS-PLATFORM', 'Deep Link Analysis',
                'Analyzes deep link/app link configurations for security issues');
            try {
                const dump = await this.getPackageDump(packageName);
                const links = U.parseResolverFilters(dump, packageName)
                    .filter(f => f.schemes.length && f.actions.includes('android.intent.action.VIEW'));
                const custom = new Set(), web = new Set(), hosts = new Set();
                for (const f of links) {
                    let isWeb = false;
                    for (const s of f.schemes) {
                        if (/^https?$/i.test(s)) { web.add(s); isWeb = true; } else custom.add(s);
                    }
                    if (isWeb) f.authorities.forEach(a => hosts.add(a.replace(/:\s*-?\d+$/, '')));
                }
                if (custom.size) {
                    results.findings.push({ type: 'custom_schemes', schemes: [...custom], severity: 'medium',
                        note: `Custom URL scheme(s) ${[...custom].join(', ')} - any app can fire these; validate all deep link parameters`,
                        recommendation: 'Prefer verified HTTPS App Links over custom schemes' });
                    escalate(results, 'medium'); results.status = 'review';
                }
                if (web.size) {
                    results.findings.push({ type: 'web_links', hosts: [...hosts],
                        note: `App handles web URLs${hosts.size ? ' for ' + [...hosts].join(', ') : ''} - verify App Links are verified (assetlinks.json)` });
                    try {
                        const v = await this.sh(`pm get-app-links ${packageName} 2>&1`);
                        if (/Domain verification state/i.test(v) && /(none|legacy_failure|1024|ask)/i.test(v) && !/verified/i.test(v)) {
                            results.findings.push({ type: 'unverified_app_links', severity: 'medium', note: 'No verified App Link domains - links open a chooser and can be hijacked by other apps' });
                            escalate(results, 'medium'); results.status = 'review';
                        }
                    } catch (e) { /* pm get-app-links needs Android 12+ */ }
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        async testIntentFilters(packageName) {
            this.assertPackage(packageName);
            const results = newResult('INTENT-FILTERS', 'MASVS-PLATFORM', 'Intent Filter Analysis',
                'Analyzes intent filters for potential attack surface');
            try {
                const filters = U.parseResolverFilters(await this.getPackageDump(packageName), packageName);
                const actions = new Set(), schemes = new Set(), hosts = new Set();
                for (const f of filters) {
                    f.actions.forEach(a => actions.add(a));
                    f.schemes.forEach(s => schemes.add(s));
                    f.authorities.forEach(a => hosts.add(a.replace(/:\s*-?\d+$/, '')));
                }
                const customActions = [...actions].filter(a => !a.startsWith('android.'));
                if (schemes.size) results.findings.push({ type: 'url_schemes', schemes: [...schemes], note: 'URL schemes registered: ' + [...schemes].join(', ') });
                if (hosts.size) results.findings.push({ type: 'app_links', hosts: [...hosts], note: 'Hosts: ' + [...hosts].join(', ') });
                if (customActions.length) results.findings.push({ type: 'custom_actions', actions: customActions, note: 'Custom intent actions: ' + customActions.join(', ') });
                const browsable = filters.filter(f => f.categories.includes('android.intent.category.BROWSABLE')).length;
                if (browsable) results.findings.push({ type: 'browsable', count: browsable, note: `${browsable} BROWSABLE filter(s) - reachable from web pages`, severity: 'low' });
                if (results.findings.length) results.status = 'review';
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        async testWebViewConfig(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0022', 'MASVS-PLATFORM', 'WebView Security Configuration',
                'Heuristic check of the APK for WebView / JavaScript-bridge usage');
            try {
                const path = (await this.adb.getApkPaths(packageName))[0];
                const hits = await this.sh(`unzip -p ${shQuote(path)} 'classes*.dex' 2>/dev/null | strings 2>/dev/null | grep -E 'addJavascriptInterface|setJavaScriptEnabled|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|WebViewClient' | sort -u | head -20`, 60000);
                if (!hits.trim()) {
                    results.findings.push({ type: 'not_analyzed', note: 'No WebView indicators found, or `unzip`/`strings` are unavailable on this device (heuristic only)' });
                } else {
                    results.findings.push({ type: 'webview_detected', note: 'App appears to use WebView - verify JavaScript is disabled if not needed' });
                    if (/addJavascriptInterface/.test(hits)) {
                        results.findings.push({ type: 'javascript_interface', severity: 'high', note: 'addJavascriptInterface in use - verify no sensitive APIs are exposed and only trusted content is loaded' });
                        escalate(results, 'high');
                    }
                    if (/setAllowUniversalAccessFromFileURLs|setAllowFileAccess/.test(hits)) {
                        results.findings.push({ type: 'webview_file_access', severity: 'medium', note: 'WebView file access settings referenced - verify they are disabled' });
                        escalate(results, 'medium');
                    }
                    results.status = 'review';
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        /* ---------- MASVS-RESILIENCE ---------- */

        async testRootDetection() {
            const results = newResult('MASTG-TEST-0038', 'MASVS-RESILIENCE', 'Root Detection Analysis',
                'Checks device root status and common root indicators');
            try {
                const suCheck = await this.sh('which su 2>/dev/null; ls /system/xbin/su /system/bin/su /sbin/su /su/bin/su /vendor/bin/su 2>/dev/null');
                if (suCheck.trim()) {
                    results.findings.push({ type: 'su_binary', path: suCheck.split('\n')[0], note: 'su binary found - device appears to be rooted' });
                    escalate(results, 'medium');
                }
                const magisk = await this.sh('ls /data/adb/magisk /sbin/.magisk 2>/dev/null | head -1');
                if (magisk.trim()) results.findings.push({ type: 'magisk', note: 'Magisk installation detected' });

                const rootApps = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.koushikdutta.superuser', 'com.noshufou.android.su', 'me.weishu.kernelsu'];
                const pkgList = await this.sh('pm list packages');
                for (const app of rootApps) {
                    if (pkgList.includes('package:' + app)) results.findings.push({ type: 'root_app', package: app, note: `Root management app detected (${app})` });
                }
                const tags = await this.sh('getprop ro.build.tags');
                if (tags.includes('test-keys')) results.findings.push({ type: 'test_keys', note: 'Device built with test-keys - indicates custom ROM' });

                const frida = await this.sh('ps -A 2>/dev/null | grep -i frida | grep -v grep');
                if (frida.trim()) {
                    results.findings.push({ type: 'frida_server', severity: 'high', note: 'Frida server process detected - dynamic instrumentation active' });
                    escalate(results, 'high');
                }
                if (results.findings.length) results.status = 'review';
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        async testDebuggable(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0039', 'MASVS-RESILIENCE', 'Debuggable Application Check',
                'Checks if app is debuggable which allows runtime manipulation');
            try {
                const flags = U.parsePackageFlags(await this.getPackageDump(packageName));
                if (flags.size === 0) {
                    results.status = 'error'; results.error = 'Could not read package flags (is the package installed?)';
                } else if (flags.has('DEBUGGABLE')) {
                    results.findings.push({ type: 'debuggable', severity: 'critical',
                        note: 'Application is debuggable (android:debuggable=true) - allows run-as access to private data and JDWP attach',
                        recommendation: 'Ship release builds with debuggable=false' });
                    escalate(results, 'critical'); results.status = 'fail';
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        async testEmulatorDetection() {
            const results = newResult('MASTG-TEST-0044', 'MASVS-RESILIENCE', 'Emulator Detection',
                'Checks if running on emulator (apps should detect this)');
            try {
                const props = await this.sh('getprop ro.build.fingerprint; getprop ro.product.model; getprop ro.hardware; getprop ro.kernel.qemu');
                const lower = props.toLowerCase();
                for (const indicator of ['sdk_gphone', 'generic', 'emulator', 'goldfish', 'ranchu', 'vbox', 'genymotion', 'android sdk built for']) {
                    if (lower.includes(indicator)) {
                        results.findings.push({ type: 'emulator_indicator', indicator, note: `Emulator indicator "${indicator}" found in build properties` });
                    }
                }
                if ((await this.sh('getprop ro.kernel.qemu')).trim() === '1') {
                    results.findings.push({ type: 'qemu', note: 'Running on QEMU-based emulator' });
                }
                if (results.findings.length) results.status = 'review';
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        /* ---------- MASVS-CODE ---------- */

        async testMinSdkVersion(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0033', 'MASVS-CODE', 'Minimum SDK Version',
                'Checks if app targets outdated Android versions with known weaknesses');
            try {
                const dump = await this.getPackageDump(packageName);
                const minSdk = (dump.match(/minSdk=(\d+)/) || [])[1];
                const targetSdk = (dump.match(/targetSdk=(\d+)/) || [])[1];
                const version = (dump.match(/versionName=(\S+)/) || [])[1];
                if (minSdk) {
                    const v = parseInt(minSdk, 10);
                    results.findings.push({ type: 'min_sdk', value: v, note: `Minimum SDK: ${v} (Android ${this.sdkToAndroidVersion(v)})` });
                    if (v < 21) {
                        results.findings.push({ type: 'outdated_min_sdk', severity: 'high', note: 'minSdkVersion < 21 - app supports Android 4.x with known vulnerabilities' });
                        escalate(results, 'high'); results.status = 'fail';
                    } else if (v < 26) {
                        results.findings.push({ type: 'old_min_sdk', severity: 'medium', note: 'minSdkVersion < 26 - consider increasing for better security defaults' });
                        escalate(results, 'medium'); if (results.status === 'pass') results.status = 'review';
                    }
                }
                if (targetSdk) {
                    const v = parseInt(targetSdk, 10);
                    results.findings.push({ type: 'target_sdk', value: v, note: `Target SDK: ${v} (Android ${this.sdkToAndroidVersion(v)})` });
                    if (v < 30) {
                        results.findings.push({ type: 'outdated_target_sdk', severity: 'medium', note: 'targetSdkVersion < 30 - missing scoped storage and other platform security improvements' });
                        escalate(results, 'medium'); if (results.status === 'pass') results.status = 'review';
                    }
                }
                if (version) results.findings.push({ type: 'app_version', value: version, note: `Version: ${version}` });
                if (!minSdk && !targetSdk) { results.status = 'error'; results.error = 'Could not read SDK levels'; }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        async testApkSignature(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0035', 'MASVS-CODE', 'APK Signature Analysis',
                'Analyzes APK signing scheme');
            try {
                const dump = await this.getPackageDump(packageName);
                const m = dump.match(/apkSigningVersion[:=]\s*(\d+)/) || dump.match(/PackageSignatures\{[^}]*?version:(\d+)/);
                if (m) {
                    const v = parseInt(m[1], 10);
                    results.findings.push({ type: 'signing_scheme', version: v, note: `APK Signature Scheme v${v}` });
                    if (v < 2) {
                        results.findings.push({ type: 'weak_signing', severity: 'low', note: 'Uses v1 (JAR) signing only - vulnerable to Janus (CVE-2017-13156) on Android 5-8; use v2/v3' });
                        escalate(results, 'low'); results.status = 'review';
                    }
                } else {
                    results.findings.push({ type: 'unknown_signing', note: 'Signature scheme not reported by this Android version' });
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        /** Where the app was installed from. */
        async testInstallSource(packageName) {
            this.assertPackage(packageName);
            const results = newResult('INSTALL-SOURCE', 'MASVS-CODE', 'Installation Source',
                'Checks which installer put the app on the device');
            try {
                const dump = await this.getPackageDump(packageName);
                const m = dump.match(/installerPackageName=(\S+)/) || dump.match(/installInitiatingPackageName=(\S+)/);
                const installer = m ? m[1] : 'null';
                const trusted = ['com.android.vending', 'com.sec.android.app.samsungapps', 'com.amazon.venezia', 'com.huawei.appmarket', 'com.xiaomi.mipicks', 'com.google.android.packageinstaller'];
                results.findings.push({ type: 'installer', value: installer, note: `Installer: ${installer}` });
                if (installer === 'null' || installer === 'com.android.shell') {
                    results.findings.push({ type: 'sideloaded', severity: 'low', note: 'App was sideloaded (adb/unknown source) - not distributed through a store' });
                    escalate(results, 'low'); results.status = 'review';
                } else if (!trusted.includes(installer) && !installer.startsWith('com.android.')) {
                    results.findings.push({ type: 'third_party_store', severity: 'low', note: `Installed by ${installer}` });
                    results.status = 'review';
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        /* ---------- MASVS-NETWORK ---------- */

        async testNetworkSecurity(packageName) {
            this.assertPackage(packageName);
            const results = newResult('MASTG-TEST-0019', 'MASVS-NETWORK', 'Network Security Configuration',
                'Analyzes cleartext traffic policy and network security config');
            try {
                const dump = await this.getPackageDump(packageName);
                const target = parseInt((dump.match(/targetSdk=(\d+)/) || [])[1], 10);
                const flags = U.parsePackageFlags(dump);
                const hasNsc = /networkSecurityConfigRes=0x[0-9a-f]*[1-9a-f]/i.test(dump);
                const explicitCleartext = dump.includes('usesCleartextTraffic=true') || flags.has('USES_CLEARTEXT_TRAFFIC');
                if (explicitCleartext) {
                    results.findings.push({ type: 'cleartext_traffic', severity: 'medium', note: 'App explicitly enables cleartext (HTTP) traffic (usesCleartextTraffic=true)',
                        recommendation: 'Disable cleartext traffic and use HTTPS everywhere' });
                    escalate(results, 'medium'); results.status = 'review';
                } else if (!isNaN(target) && target < 28 && !hasNsc) {
                    results.findings.push({ type: 'cleartext_default', severity: 'medium', note: `targetSdk ${target} < 28: cleartext HTTP is permitted by default` });
                    escalate(results, 'medium'); results.status = 'review';
                }
                if (hasNsc) {
                    results.findings.push({ type: 'network_security_config', note: 'App uses a network_security_config.xml - review for certificate pinning and cleartext domain exceptions' });
                    if (results.status === 'pass') results.status = 'review';
                } else if (!explicitCleartext) {
                    results.findings.push({ type: 'no_pinning_config', severity: 'low', note: 'No network_security_config detected - certificate pinning is not declaratively configured' });
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        /* ---------- Permissions ---------- */

        async testPermissions(packageName) {
            this.assertPackage(packageName);
            const results = newResult('PERM-ANALYSIS', 'MASVS-PLATFORM', 'Permission Analysis',
                'Analyzes app permissions for security and privacy concerns');
            try {
                const dump = await this.getPackageDump(packageName);
                const granted = [];
                for (const [perm, info] of Object.entries(DANGEROUS_PERMS)) {
                    if (new RegExp(U.escapeRegExp(perm) + ': granted=true').test(dump)) {
                        granted.push({ permission: perm, description: info.desc, group: info.group });
                    }
                }
                if (granted.length) {
                    results.findings.push({ type: 'dangerous_permissions', count: granted.length, permissions: granted,
                        note: `${granted.length} dangerous permission(s) granted: ${granted.map(p => p.permission.replace('android.permission.', '')).join(', ')}` });
                    results.status = 'review';
                    const has = (s) => granted.some(p => p.permission.includes(s));
                    if ((has('LOCATION') && (has('CAMERA') || has('RECORD_AUDIO'))) || has('SMS') || has('SYSTEM_ALERT_WINDOW') || has('MANAGE_EXTERNAL_STORAGE')) {
                        results.findings.push({ type: 'sensitive_permission_combo', severity: 'medium', note: 'High-risk permission combination detected - verify legitimate use' });
                        escalate(results, 'medium');
                    }
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        async testDangerousPermissionsOnly(packageName) {
            this.assertPackage(packageName);
            const results = newResult('DANGEROUS-PERMS', 'MASVS-PLATFORM', 'Dangerous Permissions Analysis',
                'Analyzes only dangerous runtime permissions that access sensitive user data');
            try {
                const dump = await this.getPackageDump(packageName);
                const granted = [];
                for (const [perm, info] of Object.entries(DANGEROUS_PERMS)) {
                    if (new RegExp(U.escapeRegExp(perm) + ': granted=true').test(dump)) {
                        granted.push({ permission: perm, description: info.desc, group: info.group });
                    }
                }
                if (granted.length) {
                    const groups = {};
                    for (const p of granted) (groups[p.group] = groups[p.group] || []).push(p);
                    results.findings.push({ type: 'granted_dangerous_permissions', count: granted.length, permissions: granted, groups,
                        note: `${granted.length} dangerous permission(s) currently granted to this app` });
                    const high = granted.some(p => /SMS|CALL_LOG|BACKGROUND_LOCATION|MANAGE_EXTERNAL_STORAGE|SYSTEM_ALERT_WINDOW/.test(p.permission));
                    results.severity = high ? 'high' : 'medium';
                    results.status = 'review';
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        /* ---------- Device level checks ---------- */

        async testDeviceSecurity() {
            const results = newResult('DEVICE-POSTURE', 'MASVS-RESILIENCE', 'Device Security Posture',
                'Checks patch level, bootloader, verified boot, SELinux and debugging exposure of the device itself');
            try {
                const script = ['ro.build.version.security_patch', 'ro.boot.flash.locked', 'ro.boot.verifiedbootstate', 'ro.debuggable',
                    'ro.build.type', 'service.adb.tcp.port', 'persist.adb.tcp.port', 'ro.secure']
                    .map(p => `echo "${p}=$(getprop ${p})"`).join('; ') + '; echo "selinux=$(getenforce 2>/dev/null)"';
                const raw = await this.sh(script);
                const p = {};
                raw.split('\n').forEach(l => { const i = l.indexOf('='); if (i > 0) p[l.slice(0, i)] = l.slice(i + 1).trim(); });

                const patch = p['ro.build.version.security_patch'];
                if (/^\d{4}-\d{2}-\d{2}$/.test(patch || '')) {
                    const ageDays = (Date.now() - new Date(patch).getTime()) / 86400000;
                    results.findings.push({ type: 'security_patch', value: patch, note: `Security patch level: ${patch} (${Math.round(ageDays)} days old)` });
                    if (ageDays > 365) {
                        results.findings.push({ type: 'outdated_patch', severity: 'high', note: 'Security patch is more than a year old - device lacks fixes for known CVEs', recommendation: 'Update the device' });
                        escalate(results, 'high'); results.status = 'fail';
                    } else if (ageDays > 180) {
                        results.findings.push({ type: 'old_patch', severity: 'medium', note: 'Security patch is older than 6 months' });
                        escalate(results, 'medium'); if (results.status === 'pass') results.status = 'review';
                    }
                }
                if (p['ro.boot.flash.locked'] === '0') {
                    results.findings.push({ type: 'bootloader_unlocked', severity: 'high', note: 'Bootloader is unlocked - verified boot protections can be bypassed' });
                    escalate(results, 'high'); results.status = 'fail';
                }
                if (p['ro.boot.verifiedbootstate'] && p['ro.boot.verifiedbootstate'] !== 'green') {
                    results.findings.push({ type: 'verified_boot', severity: 'medium', note: `Verified boot state is "${p['ro.boot.verifiedbootstate']}" (expected green)` });
                    escalate(results, 'medium'); if (results.status === 'pass') results.status = 'review';
                }
                if (p.selinux && /permissive/i.test(p.selinux)) {
                    results.findings.push({ type: 'selinux_permissive', severity: 'high', note: 'SELinux is in Permissive mode - mandatory access control is not enforced' });
                    escalate(results, 'high'); results.status = 'fail';
                }
                if (p['ro.debuggable'] === '1' || p['ro.secure'] === '0') {
                    results.findings.push({ type: 'ro_debuggable', severity: 'high', note: 'System image is debuggable (ro.debuggable=1 / ro.secure=0) - adb root available' });
                    escalate(results, 'high'); results.status = 'fail';
                }
                if (['userdebug', 'eng'].includes(p['ro.build.type'])) {
                    results.findings.push({ type: 'build_type', severity: 'medium', note: `Non-production build type: ${p['ro.build.type']}` });
                    escalate(results, 'medium'); if (results.status === 'pass') results.status = 'review';
                }
                const tcp = p['service.adb.tcp.port'] || p['persist.adb.tcp.port'];
                if (tcp && tcp !== '-1' && tcp !== '0') {
                    results.findings.push({ type: 'adb_over_network', severity: 'high', note: `ADB over network is enabled on port ${tcp} - anyone on the network may attempt to connect` });
                    escalate(results, 'high'); results.status = 'fail';
                }
                const a11y = (await this.sh('settings get secure enabled_accessibility_services 2>/dev/null')).trim();
                if (a11y && a11y !== 'null') {
                    results.findings.push({ type: 'accessibility_services', services: a11y.split(':'), severity: 'low',
                        note: `Accessibility services enabled: ${a11y.split(':').join(', ')} (can read screen content)` });
                    escalate(results, 'low'); if (results.status === 'pass') results.status = 'review';
                }
                const listeners = (await this.sh('settings get secure enabled_notification_listeners 2>/dev/null')).trim();
                if (listeners && listeners !== 'null') {
                    results.findings.push({ type: 'notification_listeners', services: listeners.split(':'), severity: 'low',
                        note: `Notification listeners enabled: ${listeners.split(':').join(', ')}` });
                    if (results.status === 'pass') results.status = 'review';
                }
            } catch (e) {
                results.status = 'error'; results.error = e.message;
            }
            return results;
        }

        async runDeviceAudit(onProgress = null) {
            const tests = [
                { name: 'Device Posture', fn: () => this.testDeviceSecurity() },
                { name: 'Root Detection', fn: () => this.testRootDetection() },
                { name: 'Emulator Detection', fn: () => this.testEmulatorDetection() }
            ];
            return this._runTests('device', tests, onProgress);
        }

        /* ---------- Data access helpers used by the UI ---------- */

        async getLocalStorageFiles(packageName) {
            this.assertPackage(packageName);
            const result = { sharedPrefs: [], databases: [], files: [], external: [] };
            const dataDir = `/data/data/${packageName}`;
            const fromEntries = (entries, sub, type, filter) => (entries || [])
                .filter(e => (filter ? filter(e) : true))
                .map(e => ({ name: e.name, path: `${dataDir}/${sub}/${e.name}`, size: String(e.size), type: e.isDir ? 'folder' : (type || this.getFileType(e.name)) }));
            try {
                result.sharedPrefs = fromEntries(await this.listAppDir(packageName, 'shared_prefs'), 'shared_prefs', 'xml', e => !e.isDir);
                result.databases = fromEntries(await this.listAppDir(packageName, 'databases'), 'databases', 'db', e => !e.isDir && !/-(journal|wal|shm)$/.test(e.name));
                const root = await this.hasRoot();
                const filesOut = await this.asApp(packageName, 'find files -type f 2>/dev/null | head -100');
                if (filesOut.out) {
                    for (const rel of filesOut.out.split('\n').map(s => s.trim()).filter(s => s.startsWith('files/'))) {
                        result.files.push({ name: rel.split('/').pop(), path: `${dataDir}/${rel}`, size: '-', type: this.getFileType(rel) });
                    }
                }
                const cache = await this.listAppDir(packageName, 'cache');
                for (const e of cache || []) {
                    result.files.push({ name: `[cache] ${e.name}`, path: `${dataDir}/cache/${e.name}`, size: String(e.size), type: e.isDir ? 'folder' : this.getFileType(e.name) });
                }
                void root;
                const ext = await this.sh(`ls -la ${shQuote(`/sdcard/Android/data/${packageName}/`)} 2>/dev/null`);
                for (const e of ext.split('\n').map(parseLsLine).filter(Boolean)) {
                    result.external.push({ name: e.name, path: `/sdcard/Android/data/${packageName}/${e.name}`, size: String(e.size), type: e.isDir ? 'folder' : this.getFileType(e.name) });
                }
            } catch (e) { /* partial results are fine */ }
            return result;
        }

        async readStorageFile(packageName, filePath) {
            this.assertPackage(packageName);
            if (!filePath) throw new Error('No file path provided');
            try {
                const direct = filePath.startsWith('/sdcard/') || filePath.startsWith('/storage/emulated/');
                const content = direct ? await this.sh(`cat ${shQuote(filePath)}`) : await this.sh(suWrap(`cat ${shQuote(filePath)}`));
                return content && content.trim() ? content : '[File is empty or could not be read]';
            } catch (e) {
                return '[Could not read file - root access may be required]';
            }
        }

        getFileType(fileName) {
            if (!fileName) return 'file';
            const ext = fileName.split('.').pop()?.toLowerCase();
            const types = { xml: 'xml', json: 'json', db: 'db', sqlite: 'db', sqlite3: 'db', txt: 'text', log: 'text', cfg: 'config', conf: 'config',
                properties: 'config', png: 'image', jpg: 'image', jpeg: 'image', gif: 'image', webp: 'image', pem: 'key', key: 'key', jks: 'key', p12: 'key' };
            return types[ext] || 'file';
        }

        async getAppInfo(packageName) {
            this.assertPackage(packageName);
            const info = { packageName };
            try {
                const dump = await this.getPackageDump(packageName);
                const match = (re) => { const m = dump.match(re); return m ? m[1].trim() : null; };
                info.versionName = match(/versionName=(\S+)/);
                info.versionCode = match(/versionCode=(\d+)/);
                info.targetSdk = match(/targetSdk=(\d+)/);
                info.minSdk = match(/minSdk=(\d+)/);
                info.firstInstall = match(/firstInstallTime=(.+)/);
                info.lastUpdate = match(/lastUpdateTime=(.+)/);
                info.dataDir = match(/dataDir=(\S+)/);
                info.uid = match(/userId=(\d+)/);
                info.installer = match(/installerPackageName=(\S+)/);
                const pkgFlags = U.parsePackageFlags(dump);
                info.flags = ['DEBUGGABLE', 'ALLOW_BACKUP', 'SYSTEM', 'HAS_CODE', 'LARGE_HEAP', 'TEST_ONLY', 'PERSISTENT'].filter(f => pkgFlags.has(f));
                if (dump.includes('usesCleartextTraffic=true') || pkgFlags.has('USES_CLEARTEXT_TRAFFIC')) info.flags.push('CLEARTEXT_TRAFFIC');
                const sig = dump.match(/apkSigningVersion[:=]\s*(\d+)/) || dump.match(/PackageSignatures\{[^}]*?version:(\d+)/);
                info.signingVersion = sig ? 'v' + sig[1] : null;
                const sizeOut = await this.sh(`du -sh ${shQuote(`/data/data/${packageName}/`)} 2>/dev/null`);
                const sizeMatch = sizeOut.match(/^([\d.]+\S*)/);
                info.dataSize = sizeMatch ? sizeMatch[1] : null;
                const codePath = match(/codePath=(\S+)/);
                if (codePath) {
                    info.apkPath = codePath;
                    const apkSizeOut = await this.sh(`du -sh ${shQuote(codePath)} 2>/dev/null`);
                    const m = apkSizeOut.match(/^([\d.]+\S*)/);
                    info.apkSize = m ? m[1] : null;
                }
            } catch (e) {
                info.error = e.message;
            }
            return info;
        }

        async getRunningProcesses(packageName) {
            if (packageName) this.assertPackage(packageName);
            try {
                const output = await this.sh('ps -A -o PID,USER,VSZ,RSS,STAT,NAME 2>/dev/null || ps -A 2>/dev/null || ps');
                const procs = [];
                for (const line of output.split('\n')) {
                    const parts = line.trim().split(/\s+/);
                    if (parts.length >= 2 && /^\d+$/.test(parts[0])) {
                        const proc = { pid: parts[0], user: parts[1], vsz: parts[2] || '-', rss: parts[3] || '-', stat: parts[4] || '-', name: parts.slice(5).join(' ') || parts[parts.length - 1] };
                        if (!packageName || proc.name.toLowerCase().includes(packageName.toLowerCase())) procs.push(proc);
                    }
                }
                return procs;
            } catch (e) {
                return [];
            }
        }

        async getActiveConnections(packageName) {
            if (packageName) this.assertPackage(packageName);
            try {
                let uid = '';
                if (packageName) {
                    const m = (await this.getPackageDump(packageName)).match(/userId=(\d+)/);
                    uid = m ? m[1] : '';
                }
                const out = (await this.sh('cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp 2>/dev/null')).split('\n');
                const states = { '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING' };
                const parseAddr = (hex) => {
                    const [ip, port] = hex.split(':');
                    const p = parseInt(port, 16);
                    if (ip.length === 8) {
                        const o = [];
                        for (let i = ip.length - 2; i >= 0; i -= 2) o.push(parseInt(ip.substr(i, 2), 16));
                        return o.join('.') + ':' + p;
                    }
                    return '[' + ip + ']:' + p;
                };
                const connections = [];
                for (const line of out) {
                    const parts = line.trim().split(/\s+/);
                    if (parts.length < 8 || !/^\d+:$/.test(parts[0])) continue;
                    if (uid && parts[7] !== uid) continue;
                    connections.push({ local: parseAddr(parts[1]), remote: parseAddr(parts[2]), state: states[parts[3]] || parts[3], uid: parts[7] });
                }
                return connections;
            } catch (e) {
                return [];
            }
        }

        sdkToAndroidVersion(sdk) {
            const versions = {
                36: '16', 35: '15', 34: '14', 33: '13', 32: '12L', 31: '12', 30: '11', 29: '10',
                28: '9', 27: '8.1', 26: '8.0', 25: '7.1', 24: '7.0', 23: '6.0',
                22: '5.1', 21: '5.0', 19: '4.4', 18: '4.3', 17: '4.2', 16: '4.1'
            };
            return versions[sdk] || `SDK ${sdk}`;
        }

        /* ---------- Orchestration ---------- */

        async _runTests(label, tests, onProgress) {
            const out = { summary: { pass: 0, fail: 0, review: 0, error: 0 }, tests: [] };
            for (let i = 0; i < tests.length; i++) {
                if (onProgress) onProgress(tests[i].name, i + 1, tests.length);
                try {
                    const result = await tests[i].fn();
                    result.severity = normalizeSeverity(result.severity);
                    out.tests.push(result);
                    out.summary[result.status] = (out.summary[result.status] || 0) + 1;
                } catch (e) {
                    out.tests.push({ id: 'ERROR', title: tests[i].name, status: 'error', error: e.message, findings: [], severity: 'info' });
                    out.summary.error++;
                }
            }
            return out;
        }

        /** Run all security tests for a package. */
        async runFullAudit(packageName, onProgress = null, options = {}) {
            this.assertPackage(packageName);
            this.clearCache();
            const started = Date.now();
            const tests = [
                { name: 'Local Storage', fn: () => this.testLocalStorage(packageName) },
                { name: 'Backup Configuration', fn: () => this.testBackupEnabled(packageName) },
                { name: 'Log Analysis', fn: () => this.testLogcat(packageName) },
                { name: 'Exported Components', fn: () => this.testExportedComponents(packageName) },
                { name: 'Deep Links', fn: () => this.testDeepLinks(packageName) },
                { name: 'Intent Filters', fn: () => this.testIntentFilters(packageName) },
                { name: 'WebView Security', fn: () => this.testWebViewConfig(packageName) },
                { name: 'Debuggable Check', fn: () => this.testDebuggable(packageName) },
                { name: 'SDK Version', fn: () => this.testMinSdkVersion(packageName) },
                { name: 'APK Signature', fn: () => this.testApkSignature(packageName) },
                { name: 'Install Source', fn: () => this.testInstallSource(packageName) },
                { name: 'Network Security', fn: () => this.testNetworkSecurity(packageName) },
                { name: 'Auth Storage', fn: () => this.testAuthStorage(packageName) },
                { name: 'Permissions', fn: () => this.testPermissions(packageName) }
            ];
            if (options.includeDevice !== false) {
                tests.push({ name: 'Device Posture', fn: () => this.testDeviceSecurity() });
                tests.push({ name: 'Root Detection', fn: () => this.testRootDetection() });
                tests.push({ name: 'Emulator Detection', fn: () => this.testEmulatorDetection() });
            }
            const body = await this._runTests(packageName, tests, onProgress);
            const report = { packageName, timestamp: new Date().toISOString(), durationMs: Date.now() - started, ...body };
            report.riskScore = U.computeRiskScore(report);
            this.clearCache();
            return report;
        }

        /**
         * Fast triage of many apps: debuggable / backup / SDK levels / installer / dangerous permission count.
         * Runs `concurrency` apps at a time (the transport is concurrency-safe).
         */
        async triageApps(packages, onProgress = null, concurrency = 3) {
            const rows = new Array(packages.length);
            let next = 0, done = 0;
            const worker = async () => {
                while (next < packages.length) {
                    const idx = next++;
                    const pkg = packages[idx];
                    try {
                        const dump = await this.sh(`dumpsys package ${pkg}`, 60000);
                        const flags = U.parsePackageFlags(dump);
                        const perms = Object.keys(DANGEROUS_PERMS).filter(p => new RegExp(U.escapeRegExp(p) + ': granted=true').test(dump));
                        const row = {
                            package: pkg,
                            debuggable: flags.has('DEBUGGABLE'),
                            allowBackup: flags.has('ALLOW_BACKUP'),
                            cleartext: dump.includes('usesCleartextTraffic=true'),
                            targetSdk: parseInt((dump.match(/targetSdk=(\d+)/) || [])[1], 10) || null,
                            minSdk: parseInt((dump.match(/minSdk=(\d+)/) || [])[1], 10) || null,
                            installer: (dump.match(/installerPackageName=(\S+)/) || [])[1] || 'null',
                            dangerousPerms: perms.length
                        };
                        let score = 0;
                        if (row.debuggable) score += 40;
                        if (row.allowBackup) score += 10;
                        if (row.cleartext) score += 10;
                        if (row.targetSdk && row.targetSdk < 30) score += 10;
                        if (row.minSdk && row.minSdk < 21) score += 10;
                        score += Math.min(20, row.dangerousPerms * 2);
                        row.risk = Math.min(100, score);
                        rows[idx] = row;
                    } catch (e) {
                        rows[idx] = { package: pkg, error: e.message, risk: 0 };
                    }
                    done++;
                    if (onProgress) onProgress(pkg, done, packages.length);
                }
            };
            await Promise.all(Array.from({ length: Math.min(concurrency, packages.length) }, worker));
            return rows;
        }
    }

    SecurityAuditor.scanForSecrets = scanForSecrets;
    SecurityAuditor.DANGEROUS_PERMS = DANGEROUS_PERMS;
    global.SecurityAuditor = SecurityAuditor;
    void MODULE_KEY;
})(window);
