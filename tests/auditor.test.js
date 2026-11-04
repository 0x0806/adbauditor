'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadLibs } = require('./helpers/env');
const { dump } = require('./fixtures/dumpsys-package');

const plain = x => JSON.parse(JSON.stringify(x));

/** Build an auditor over a scripted fake `adb`. `rules` is [[regex|string, reply|fn]]. */
function auditorWith(rules, apks = ['/data/app/base.apk']) {
    const ctx = loadLibs();
    const calls = [];
    const adb = {
        calls,
        async shell(cmd) {
            calls.push(cmd);
            for (const [m, reply] of rules) {
                if (typeof m === 'string' ? cmd.includes(m) : m.test(cmd)) return typeof reply === 'function' ? reply(cmd) : reply;
            }
            return '';
        },
        async getApkPaths() { return apks; }
    };
    return { auditor: new ctx.SecurityAuditor(adb), adb, ctx };
}
const PKG = 'com.example.app';

test('rejects invalid package names before touching the device', async () => {
    const { auditor, adb } = auditorWith([]);
    for (const bad of ['', 'a b', 'x; reboot', '$(id)', 'com.example/..', "a'b", '1abc.def']) {
        await assert.rejects(() => auditor.testDebuggable(bad), /Invalid package/);
    }
    assert.equal(adb.calls.length, 0);
});

test('backup: allowBackup=false app passes, allowBackup=true fails (regression: old check failed everything)', async () => {
    const off = auditorWith([['dumpsys package', dump({ flags: 'HAS_CODE ALLOW_CLEAR_USER_DATA' })]]);
    assert.equal((await off.auditor.testBackupEnabled(PKG)).status, 'pass');
    const on = auditorWith([['dumpsys package', dump()]]);
    const r = await on.auditor.testBackupEnabled(PKG);
    assert.equal(r.status, 'fail');
    assert.equal(r.severity, 'medium');
});

test('backup: unreadable dump is an error, not a false pass', async () => {
    const { auditor } = auditorWith([['dumpsys package', 'Unable to find package']]);
    assert.equal((await auditor.testBackupEnabled(PKG)).status, 'error');
});

test('debuggable: only the DEBUGGABLE flag counts (the word debug elsewhere does not)', async () => {
    const clean = auditorWith([['dumpsys package', dump({ extra: '    something debuggable-sounding=true\n' })]]);
    assert.equal((await clean.auditor.testDebuggable(PKG)).status, 'pass');
    const dbg = auditorWith([['dumpsys package', dump({ flags: 'DEBUGGABLE HAS_CODE ALLOW_BACKUP' })]]);
    const r = await dbg.auditor.testDebuggable(PKG);
    assert.equal(r.status, 'fail');
    assert.equal(r.severity, 'critical');
});

test('exported components are parsed from resolver tables and foreign packages are excluded', async () => {
    const { auditor } = auditorWith([['dumpsys package', dump()]]);
    const r = plain(await auditor.testExportedComponents(PKG));
    const by = Object.fromEntries(r.findings.map(f => [f.type, f]));
    assert.deepEqual(by.exported_activities.components.sort(), [`${PKG}/.DeepLinkActivity`, `${PKG}/.MainActivity`]);
    assert.deepEqual(by.exported_receivers.components.sort(), [`${PKG}/.ProtectedReceiver`, `${PKG}/.SyncReceiver`]);
    assert.equal(by.exported_receivers.unprotected, 1);
    assert.deepEqual(by.exported_services.components, [`${PKG}/.SyncService`]);
    assert.ok(!JSON.stringify(r).includes('com.other.lib'));
    assert.deepEqual(by.exported_providers.components, [`${PKG}/.DataProvider`]);
    assert.equal(r.status, 'review');
});

test('deep links: custom scheme flagged, https host reported (regression: old parser never matched real dumpsys)', async () => {
    const { auditor } = auditorWith([['dumpsys package', dump()], ['pm get-app-links', '']]);
    const r = plain(await auditor.testDeepLinks(PKG));
    const custom = r.findings.find(f => f.type === 'custom_schemes');
    assert.deepEqual(custom.schemes, ['myapp']);
    const web = r.findings.find(f => f.type === 'web_links');
    assert.deepEqual(web.hosts, ['example.com']);
    assert.equal(r.status, 'review');
});

test('intent filters summarise schemes, hosts, custom actions and browsable filters', async () => {
    const { auditor } = auditorWith([['dumpsys package', dump()]]);
    const r = plain(await auditor.testIntentFilters(PKG));
    const types = r.findings.map(f => f.type);
    assert.ok(types.includes('url_schemes') && types.includes('app_links') && types.includes('custom_actions') && types.includes('browsable'));
});

test('min SDK severity tiers', async () => {
    const old = auditorWith([['dumpsys package', dump({ minSdk: 16, targetSdk: 25 })]]);
    const r = await old.auditor.testMinSdkVersion(PKG);
    assert.equal(r.status, 'fail');
    assert.equal(r.severity, 'high');
    const ok = auditorWith([['dumpsys package', dump({ minSdk: 26, targetSdk: 34 })]]);
    assert.equal((await ok.auditor.testMinSdkVersion(PKG)).status, 'pass');
});

test('signature scheme read from PackageSignatures version', async () => {
    const { auditor } = auditorWith([['dumpsys package', dump()]]);
    const r = plain(await auditor.testApkSignature(PKG));
    assert.equal(r.findings[0].version, 3);
    assert.equal(r.status, 'pass');
});

test('network: no longer flags every app as cleartext; honours targetSdk default', async () => {
    const modern = auditorWith([['dumpsys package', dump({ targetSdk: 33 })]]);
    const rm = await modern.auditor.testNetworkSecurity(PKG);
    assert.equal(rm.status, 'pass');
    const legacy = auditorWith([['dumpsys package', dump({ targetSdk: 24 })]]);
    assert.equal((await legacy.auditor.testNetworkSecurity(PKG)).status, 'review');
    const explicit = auditorWith([['dumpsys package', dump({ extra: '    usesCleartextTraffic=true\n' })]]);
    assert.equal((await explicit.auditor.testNetworkSecurity(PKG)).status, 'review');
});

test('permissions: only granted dangerous permissions are reported', async () => {
    const { auditor } = auditorWith([['dumpsys package', dump()]]);
    const r = plain(await auditor.testDangerousPermissionsOnly(PKG));
    const perms = r.findings[0].permissions.map(p => p.permission).sort();
    assert.deepEqual(perms, ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.CAMERA']);
    const full = plain(await auditor.testPermissions(PKG));
    assert.ok(full.findings.some(f => f.type === 'sensitive_permission_combo'));
});

test('install source: sideloaded apps are noted', async () => {
    const { auditor } = auditorWith([['dumpsys package', dump({ extra: '' }).replace('com.android.vending', 'null')]]);
    const r = plain(await auditor.testInstallSource(PKG));
    assert.ok(r.findings.some(f => f.type === 'sideloaded'));
});

test('logcat test never clears the device log and reports masked samples only', async () => {
    const secret = 'password=hunter2hunter2';
    const { auditor, adb } = auditorWith([
        ['pidof', '4321'],
        ['logcat -d', `01-01 D/App(4321): login ${secret} token=abcdefghijklmnop1234 card 4111 1111 1111 1111 mail bob@example.com`]
    ]);
    const r = plain(await auditor.testLogcat(PKG));
    assert.equal(r.status, 'fail');
    assert.ok(!adb.calls.some(c => /logcat\s+-c/.test(c)), 'must not clear logs');
    const text = JSON.stringify(r);
    assert.ok(!text.includes('hunter2hunter2'), 'raw secret must not appear in the report');
    assert.ok(r.findings.some(f => f.dataType === 'credit_card'));
    assert.ok(r.findings.some(f => f.dataType === 'email'));
});

test('credit card detection uses Luhn (random 16-digit numbers are ignored)', async () => {
    const found = loadLibs().SecurityAuditor.scanForSecrets('id 1234 5678 9012 3456 ok');
    assert.equal(found.filter(f => f.type === 'credit_card').length, 0);
});

test('auth storage: finds secrets via root fallback without leaking values', async () => {
    const xml = '<map><string name="auth_token">abcdef1234567890XYZ</string><string name="password">s3cretpw</string></map>';
    const { auditor } = auditorWith([
        [/run-as/, 'run-as: package not debuggable: com.example.app'],
        [/su -c 'id'|su -c id/, 'uid=0(root)'],
        [/cat shared_prefs/, xml]
    ]);
    const r = plain(await auditor.testAuthStorage(PKG));
    assert.equal(r.status, 'review');
    assert.ok(!JSON.stringify(r).includes('s3cretpw'));
});

test('local storage: inaccessible private storage is reported honestly, not as a pass', async () => {
    const { auditor } = auditorWith([[/run-as/, 'run-as: package not debuggable'], [/su -c/, 'su: not found']]);
    const r = plain(await auditor.testLocalStorage(PKG));
    assert.ok(r.findings.some(f => f.type === 'inaccessible'));
});

test('local storage: lists prefs/dbs through run-as, flags world-readable files', async () => {
    const ls = (dir) => `total 8\n-rw-rw---- 1 u0_a234 u0_a234 1234 2024-03-04 11:30 ${dir === 'databases' ? 'app.db' : 'prefs.xml'}\n-rw------- 1 u0_a234 u0_a234 12 2024-03-04 11:30 x-journal`;
    const { auditor, adb } = auditorWith([
        [/find \. -type f -perm/, './files/leak.txt\n'],
        [/ls -la.*databases/, ls('databases')],
        [/ls -la.*shared_prefs/, ls('shared_prefs')],
        [/ls -la.*files/, 'total 0\n-rw------- 1 u0_a234 u0_a234 5 2024-03-04 11:30 a.txt'],
        ['/sdcard/Android/data', 'NONE']
    ]);
    const r = plain(await auditor.testLocalStorage(PKG));
    assert.equal(r.status, 'fail');
    assert.ok(r.findings.some(f => f.type === 'world_readable_files'));
    assert.ok(r.findings.some(f => f.type === 'database' && f.file === 'app.db'));
    assert.ok(!r.findings.some(f => f.file === 'x-journal'));
    assert.ok(adb.calls.every(c => !c.includes('${')));
});

test('device posture: old patch, unlocked bootloader, permissive SELinux, adb over tcp', async () => {
    const { auditor } = auditorWith([
        [/getprop ro.build.version.security_patch/, 'ro.build.version.security_patch=2019-01-05\nro.boot.flash.locked=0\nro.boot.verifiedbootstate=orange\nro.debuggable=1\nro.build.type=userdebug\nservice.adb.tcp.port=5555\npersist.adb.tcp.port=\nro.secure=0\nselinux=Permissive'],
        [/enabled_accessibility_services/, 'com.evil/.Svc:com.good/.Svc']
    ]);
    const r = plain(await auditor.testDeviceSecurity());
    const types = r.findings.map(f => f.type);
    for (const t of ['outdated_patch', 'bootloader_unlocked', 'verified_boot', 'selinux_permissive', 'ro_debuggable', 'build_type', 'adb_over_network', 'accessibility_services']) {
        assert.ok(types.includes(t), 'missing ' + t);
    }
    assert.equal(r.status, 'fail');
});

test('device posture: healthy device passes', async () => {
    const recent = new Date(Date.now() - 20 * 86400000).toISOString().slice(0, 10);
    const { auditor } = auditorWith([[/getprop ro.build.version.security_patch/, `ro.build.version.security_patch=${recent}\nro.boot.flash.locked=1\nro.boot.verifiedbootstate=green\nro.debuggable=0\nro.build.type=user\nservice.adb.tcp.port=\npersist.adb.tcp.port=\nro.secure=1\nselinux=Enforcing`]]);
    assert.equal((await auditor.testDeviceSecurity()).status, 'pass');
});

test('runFullAudit aggregates results, caches dumpsys and computes a risk score', async () => {
    const { auditor, adb } = auditorWith([
        ['dumpsys package', dump({ flags: 'DEBUGGABLE HAS_CODE ALLOW_BACKUP' })],
        [/run-as/, 'run-as: package not debuggable']
    ]);
    const progress = [];
    const report = plain(await auditor.runFullAudit(PKG, (n, i, t) => progress.push([n, i, t])));
    assert.equal(report.packageName, PKG);
    assert.equal(report.tests.length, 17);
    assert.equal(progress.at(-1)[1], progress.at(-1)[2]);
    const total = Object.values(report.summary).reduce((a, b) => a + b, 0);
    assert.equal(total, 17);
    assert.ok(report.riskScore > 0);
    assert.ok(report.tests.find(t => t.id === 'MASTG-TEST-0039').status === 'fail');
    const dumps = adb.calls.filter(c => c.startsWith('dumpsys package')).length;
    assert.equal(dumps, 1, 'package dump is fetched once per audit');
});

test('one failing test does not abort the audit', async () => {
    const { auditor, adb } = auditorWith([['dumpsys package', dump()]]);
    const orig = adb.shell;
    adb.shell = async (cmd) => { if (cmd.startsWith('pidof')) throw new Error('boom'); return orig.call(adb, cmd); };
    const report = plain(await auditor.runFullAudit(PKG, null, { includeDevice: false }));
    assert.equal(report.tests.length, 14);
    assert.ok(report.tests.some(t => t.status === 'error'));
});

test('triageApps ranks apps and survives per-app errors', async () => {
    const { auditor } = auditorWith([
        [/dumpsys package com\.bad/, dump({ pkg: 'com.bad', flags: 'DEBUGGABLE ALLOW_BACKUP' })],
        [/dumpsys package com\.good/, dump({ pkg: 'com.good', flags: 'HAS_CODE' })],
        [/dumpsys package com\.broken/, () => { throw new Error('nope'); }]
    ]);
    const rows = plain(await auditor.triageApps(['com.bad', 'com.good', 'com.broken'], null, 2));
    assert.equal(rows[0].debuggable, true);
    assert.ok(rows[0].risk > rows[1].risk);
    assert.ok(rows[2].error);
});

test('getAppInfo parses version, flags and sizes', async () => {
    const { auditor } = auditorWith([['dumpsys package', dump()], [/du -sh '\/data\/data/, '1.2M\t/data/data/x'], [/du -sh '\/data\/app/, '34M\t/data/app/x']]);
    const info = plain(await auditor.getAppInfo(PKG));
    assert.equal(info.versionName, '1.4.2');
    assert.equal(info.targetSdk, '33');
    assert.equal(info.signingVersion, 'v3');
    assert.ok(info.flags.includes('ALLOW_BACKUP'));
    assert.equal(info.dataSize, '1.2M');
});

test('getActiveConnections decodes /proc/net/tcp and filters by uid', async () => {
    const tcp = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10234        0 111 1 0 100 0
   1: 0F02000A:C350 0802A8C0:01BB 01 00000000:00000000 00:00000000 00000000 10999        0 222 1 0 100 0`;
    const { auditor } = auditorWith([['dumpsys package', dump()], [/cat \/proc\/net/, tcp]]);
    const conns = plain(await auditor.getActiveConnections(PKG));
    assert.equal(conns.length, 1);
    assert.deepEqual(conns[0], { local: '127.0.0.1:8080', remote: '0.0.0.0:0', state: 'LISTEN', uid: '10234' });
});
