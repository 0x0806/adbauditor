'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('child_process');
const { createContext, load } = require('./helpers/env');

const ctx = load(createContext(), ['js/utils.js', 'js/toolkit.js']);
const plain = x => JSON.parse(JSON.stringify(x));

function kit(replies = {}) {
    const calls = [];
    const adb = { calls, async shell(cmd, timeout) { calls.push(cmd); for (const [k, v] of Object.entries(replies)) if (cmd.includes(k)) return typeof v === 'function' ? v(cmd) : v; return ''; }, async pullFile(p) { calls.push('pull ' + p); return new Uint8Array([1, 2, 3]); } };
    return { t: new ctx.DeviceToolkit(adb), adb, calls };
}
/** Split a command line exactly as a POSIX shell would (globbing off). Hostile payloads in these tests are harmless ($(id)). */
function shSplit(cmd) {
    const out = execFileSync('sh', ['-c', 'set -f; eval "set -- $1"; for a in "$@"; do printf \'%s\\0\' "$a"; done', 'sh', cmd]).toString();
    return out.split('\0').slice(0, -1);
}

test('reboot only accepts known modes', async () => {
    const { t, calls } = kit();
    await t.reboot('recovery');
    assert.deepEqual(calls, ['reboot recovery']);
    await assert.rejects(() => t.reboot('system; rm -rf /'), /Unknown reboot mode/);
});

test('radio toggles', async () => {
    const { t, calls } = kit();
    await t.setWifi(true); await t.setWifi(false); await t.setBluetooth(true); await t.setMobileData(false); await t.setAirplane(true);
    assert.deepEqual(calls, ['svc wifi enable', 'svc wifi disable', 'svc bluetooth enable', 'svc data disable', 'cmd connectivity airplane-mode enable']);
});

test('brightness, tap and swipe validate integers', async () => {
    const { t, calls } = kit();
    await t.setBrightness('128'); await t.tap(10, 20); await t.swipe(1, 2, 3, 4, 500);
    assert.deepEqual(calls, ['settings put system screen_brightness 128', 'input tap 10 20', 'input swipe 1 2 3 4 500']);
    assert.throws(() => t.setBrightness(300), /brightness/);
    assert.throws(() => t.tap('1; reboot', 2), /x must/);
    assert.throws(() => t.tap(1.5, 2), /x must/);
    assert.throws(() => t.swipe(1, 2, 3, 4, 0), /duration/);
});

test('keyEvent maps names to codes and rejects unknown keys', async () => {
    const { t, calls } = kit();
    await t.keyEvent('HOME'); await t.keyEvent('keycode_back');
    assert.deepEqual(calls, ['input keyevent 3', 'input keyevent 4']);
    assert.throws(() => t.keyEvent('X; id'), /Unknown key/);
});

test('typeText: spaces become %s, hostile text stays one quoted argument, non-ASCII rejected', async () => {
    const { t, calls } = kit();
    await t.typeText("it's a $(reboot) test");
    assert.deepEqual(shSplit(calls[0]), ['input', 'text', "it's%sa%s$(reboot)%stest"]);
    assert.throws(() => t.typeText('héllo'), /ASCII/);
    assert.throws(() => t.typeText(''), /1-500/);
});

test('openUrl validates the scheme and keeps the URL as one argument', async () => {
    const { t, calls } = kit();
    await t.openUrl("https://example.com/a?b=1&c='2'");
    assert.deepEqual(shSplit(calls[0]), ['am', 'start', '-a', 'android.intent.action.VIEW', '-d', "https://example.com/a?b=1&c='2'"]);
    assert.throws(() => t.openUrl('example.com'), /Invalid URL/);
    assert.throws(() => t.openUrl('https://x.com; reboot'), /Invalid URL/);
});

test('intent builder: structured input, every token quoted, typed extras validated', () => {
    const { t } = kit();
    const cmd = t.buildIntentCommand({ kind: 'activity', action: 'android.intent.action.VIEW', component: 'com.example/.Main$Inner', data: "myapp://open?x=1&y='2'", categories: ['android.intent.category.BROWSABLE'],
        extras: [{ type: 'string', key: 'token', value: "a b'c$(id)" }, { type: 'int', key: 'n', value: '5' }, { type: 'bool', key: 'flag', value: 'true' }] });
    assert.deepEqual(shSplit(cmd), ['am', 'start', '-a', 'android.intent.action.VIEW', '-n', 'com.example/.Main$Inner', '-d', "myapp://open?x=1&y='2'", '-c', 'android.intent.category.BROWSABLE',
        '--es', 'token', "a b'c$(id)", '--ei', 'n', '5', '--ez', 'flag', 'true']);
    assert.match(t.buildIntentCommand({ kind: 'broadcast', action: 'com.x.ACTION' }), /^am broadcast -a /);
    assert.match(t.buildIntentCommand({ kind: 'service', component: 'a.b/.S' }), /^am startservice /);
});

test('intent builder rejects malformed input', () => {
    const { t } = kit();
    assert.throws(() => t.buildIntentCommand({ kind: 'activity' }), /Provide an action/);
    assert.throws(() => t.buildIntentCommand({ kind: 'weird', action: 'a.b' }), /Unknown intent kind/);
    assert.throws(() => t.buildIntentCommand({ kind: 'activity', action: 'a b; reboot' }), /Invalid action/);
    assert.throws(() => t.buildIntentCommand({ kind: 'activity', component: 'com.example Main' }), /Invalid component/);
    assert.throws(() => t.buildIntentCommand({ kind: 'activity', action: 'a.b', extras: [{ type: 'int', key: 'k', value: 'abc' }] }), /extra value/);
    assert.throws(() => t.buildIntentCommand({ kind: 'activity', action: 'a.b', extras: [{ type: 'string', key: 'k;x', value: 'v' }] }), /extra key/);
    assert.throws(() => t.buildIntentCommand({ kind: 'activity', action: 'a.b', extras: [{ type: 'bool', key: 'k', value: 'yes' }] }), /true or false/);
    assert.throws(() => t.buildIntentCommand({ kind: 'activity', action: 'a.b', package: 'bad pkg' }), /Invalid package/);
    assert.throws(() => t.buildIntentCommand({ kind: 'activity', action: 'a.b', mimeType: 'text plain' }), /MIME/);
});

test('content provider query: only content:// URIs, projection/sort restricted, where quoted', () => {
    const { t } = kit();
    const cmd = t.buildProviderQuery('content://com.example.provider/users', { projection: '_id:name', where: "name='x' OR 1=1", sort: '_id DESC' });
    assert.deepEqual(shSplit(cmd), ['content', 'query', '--uri', 'content://com.example.provider/users', '--projection', '_id:name', '--where', "name='x' OR 1=1", '--sort', '_id DESC']);
    assert.throws(() => t.buildProviderQuery('file:///etc/passwd'), /content:\/\//);
    assert.throws(() => t.buildProviderQuery('content://a/b; reboot'), /content:\/\//);
    assert.throws(() => t.buildProviderQuery('content://a/b', { projection: 'x;y' }), /projection/);
    assert.throws(() => t.buildProviderQuery('content://a/b', { sort: 'x;y' }), /sort/);
});

test('permissions and package management validate names', async () => {
    const { t, calls } = kit();
    await t.grantPermission('com.a.b', 'android.permission.CAMERA'); await t.revokePermission('com.a.b', 'android.permission.CAMERA');
    await t.setAppEnabled('com.a.b', false); await t.setAppEnabled('com.a.b', true); await t.appOps('com.a.b'); await t.killPackage('com.a.b'); await t.killPid(1234);
    assert.deepEqual(calls, ["pm grant com.a.b 'android.permission.CAMERA'", "pm revoke com.a.b 'android.permission.CAMERA'", 'pm disable-user --user 0 com.a.b', 'pm enable com.a.b', 'appops get com.a.b', 'am force-stop com.a.b', 'kill 1234']);
    assert.throws(() => t.grantPermission('com.a.b; id', 'android.permission.CAMERA'), /Invalid package/);
    assert.throws(() => t.grantPermission('com.a.b', 'x; id'), /Invalid permission/);
    assert.throws(() => t.killPid('1; reboot'), /pid/);
    assert.throws(() => t.killPid(1), /pid/);
});

test('settings: namespace and key validation, values quoted', async () => {
    const { t, calls } = kit({ 'settings list global': 'a=1\nb=two=2\nnoequals\n' });
    await t.putSetting('global', 'my.key', "v'1 $(x)");
    assert.deepEqual(shSplit(calls[0]), ['settings', 'put', 'global', 'my.key', "v'1 $(x)"]);
    assert.deepEqual(plain(await t.listSettings('global')), [{ key: 'a', value: '1' }, { key: 'b', value: 'two=2' }]);
    assert.throws(() => t.putSetting('bogus', 'k', 'v'), /namespace/);
    assert.throws(() => t.putSetting('global', 'k; reboot', 'v'), /key/);
    assert.throws(() => t.getSetting('global', ''), /key/);
});

test('listProps parses getprop output', async () => {
    const { t } = kit({ getprop: '[ro.b]: [two]\n[ro.a]: [one words]\ngarbage\n[empty]: []' });
    assert.deepEqual(plain(await t.listProps()), [{ key: 'empty', value: '' }, { key: 'ro.a', value: 'one words' }, { key: 'ro.b', value: 'two' }]);
});

test('dumpsys: service name and arguments validated', async () => {
    const { t, calls } = kit({ 'dumpsys -l': 'Currently running services:\n  battery\n  wifi\n  bad name!\n' });
    assert.deepEqual(plain(await t.listDumpsysServices()), ['battery', 'wifi']);
    await t.dumpsys('package', 'com.example.app');
    assert.equal(calls.at(-1), "dumpsys 'package' 'com.example.app'");
    assert.throws(() => t.dumpsys('x; id'), /Invalid service/);
    assert.throws(() => t.dumpsys('wifi', '$(id)'), /Invalid dumpsys/);
});

test('log snapshot only accepts known buffers; numeric lines', async () => {
    const { t, calls } = kit();
    await t.logSnapshot('crash', 500);
    assert.equal(calls[0], 'logcat -b crash -d -v threadtime -t 500');
    assert.throws(() => t.logSnapshot('main; id'), /Unknown log buffer/);
    assert.throws(() => t.logSnapshot('main', 'x'), /lines/);
});

test('package snapshot parsing and diff', async () => {
    const { t } = kit({ 'pm list packages': 'package:com.b  installer=com.android.vending versionCode:5\npackage:com.a versionCode:2 installer=null\npackage:com.c' });
    const snap = plain(await t.packageSnapshot());
    assert.deepEqual(snap.map(p => p.pkg), ['com.a', 'com.b', 'com.c']);
    assert.equal(snap[1].installer, 'com.android.vending');
    assert.equal(snap[1].versionCode, '5');
    const next = [{ pkg: 'com.a', versionCode: '3', installer: 'null' }, { pkg: 'com.b', versionCode: '5', installer: 'com.evil.store' }, { pkg: 'com.new', versionCode: '1', installer: null }];
    const d = plain(ctx.DeviceToolkit.diffSnapshots(snap, next));
    assert.deepEqual(d.added.map(p => p.pkg), ['com.new']);
    assert.deepEqual(d.removed.map(p => p.pkg), ['com.c']);
    assert.deepEqual(d.updated, [{ pkg: 'com.a', from: '2', to: '3' }]);
    assert.deepEqual(d.installerChanged, [{ pkg: 'com.b', from: 'com.android.vending', to: 'com.evil.store' }]);
});

test('storage summary parses df', async () => {
    const { t } = kit({ 'df -h': 'Filesystem Size Used Avail Use% Mounted on\n/dev/block/dm-9 100G 40G 60G 40% /data\ntmpfs 3G 0 3G 0% /dev' });
    const rows = plain(await t.storageSummary());
    assert.equal(rows[0].mount, '/data'); assert.equal(rows[0].usePct, '40%');
});

test('network info parsing incl. proxy and private DNS', async () => {
    const { t } = kit({ '@@ADDR': '@@ADDR\n2: wlan0    inet 192.168.1.20/24 brd 192.168.1.255 scope global wlan0\n3: lo    inet6 ::1/128 scope host\n@@ROUTE\ndefault via 192.168.1.1 dev wlan0\n@@DNS\n8.8.8.8\n\n@@PROXY\n10.0.0.5:8080\n@@PRIVDNS\nhostname\ndns.example.com' });
    const n = plain(await t.networkInfo());
    assert.deepEqual(n.addresses[0], { iface: 'wlan0', family: 'inet', address: '192.168.1.20/24' });
    assert.equal(n.proxy, '10.0.0.5:8080');
    assert.deepEqual(n.privateDns, { mode: 'hostname', host: 'dns.example.com' });
    assert.deepEqual(n.dns, ['8.8.8.8']);
});

test('proxy set/clear: strict host+port validation; clear removes every related key', async () => {
    const { t, calls } = kit({ 'settings get global http_proxy': ':0' });
    await t.setProxy('192.168.1.5', 8080);
    assert.deepEqual(shSplit(calls[0]), ['settings', 'put', 'global', 'http_proxy', '192.168.1.5:8080']);
    await t.setProxy('proxy.local', '3128');
    assert.throws(() => t.setProxy('1.2.3.999', 80), /host/);
    assert.throws(() => t.setProxy('host; reboot', 80), /host/);
    assert.throws(() => t.setProxy('host', 70000), /port/);
    calls.length = 0;
    const result = await t.clearProxy();
    assert.equal(result, ':0');
    assert.equal(calls[0], "settings put global http_proxy ':0'");
    assert.match(calls[1], /delete global global_http_proxy_host.*global_http_proxy_port.*global_http_proxy_exclusion_list/);
    assert.equal(calls[2], 'settings get global http_proxy');
});

test('screen record pulls the file and always cleans up', async () => {
    const { t, calls } = kit();
    const bytes = await t.screenRecord(5);
    assert.equal(bytes.length, 3);
    assert.match(calls[0], /^screenrecord --time-limit 5 '\/data\/local\/tmp\/\.adbaud_rec_\d+\.mp4'$/);
    assert.match(calls[1], /^pull \/data\/local\/tmp/);
    assert.match(calls[2], /^rm -f /);
    await assert.rejects(() => t.screenRecord(999), /seconds/);
});
