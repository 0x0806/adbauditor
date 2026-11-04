'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadLibs } = require('./helpers/env');
const U = loadLibs().ABUtils;
const plain = x => JSON.parse(JSON.stringify(x));

test('shQuote round-trips hostile strings through a real shell', () => {
    const nasty = ["plain", "it's", "$(touch /tmp/pwned)", "`id`", "a b  c", 'quo"te', "back\\slash", "semi;colon && x | y", "new\nline", "*glob*", "-rf", "'", "''", "é日本🚀", "$HOME ${PATH}"];
    for (const s of nasty) {
        const out = execFileSync('sh', ['-c', `printf %s ${U.shQuote(s)}`]).toString();
        assert.equal(out, s);
    }
});

test('suWrap survives nested shells (su -c "<quoted command>")', () => {
    // emulate `su -c`: the argument is re-parsed by another sh
    const cmd = `printf %s ${U.shQuote("tricky 'name' $(id)")}`;
    const wrapped = U.suWrap(cmd).replace(/^su -c /, '');
    const out = execFileSync('sh', ['-c', `sh -c ${wrapped}`]).toString();
    assert.equal(out, "tricky 'name' $(id)");
});

test('isValidPackageName', () => {
    for (const ok of ['com.example', 'a.b.c', 'com.Example_App.v2', 'a']) assert.ok(U.isValidPackageName(ok), ok);
    for (const bad of ['', null, undefined, 'com..x', '.com', 'com.', '1com.x', 'com.x y', 'com.x;ls', 'a/b', 'a'.repeat(300)]) assert.ok(!U.isValidPackageName(bad), String(bad));
});

test('normalizePath resolves dot segments and cannot escape root', () => {
    assert.equal(U.normalizePath('/sdcard//a/../b/./c/'), '/sdcard/b/c');
    assert.equal(U.normalizePath('../../..'), '/');
    assert.equal(U.normalizePath(''), '/');
    assert.equal(U.joinPath('/', 'x'), '/x');
    assert.equal(U.joinPath('/a/b/', 'x'), '/a/b/x');
});

test('escapeHtml escapes everything dangerous', () => {
    assert.equal(U.escapeHtml(`<img src=x onerror="a('b')">&\``), '&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;&#96;');
    assert.equal(U.escapeHtml(null), '');
    assert.equal(U.escapeHtml(0), '0');
});

test('formatSize / formatDuration', () => {
    assert.equal(U.formatSize(0), '0 B');
    assert.equal(U.formatSize(1536), '1.5 KB');
    assert.equal(U.formatSize(5 * 1048576), '5.0 MB');
    assert.equal(U.formatSize('abc'), 'abc');
    assert.equal(U.formatSize('-'), '-');
    assert.equal(U.formatDuration(250), '250 ms');
    assert.equal(U.formatDuration(65000), '1m 5s');
});

test('safeFileName strips path tricks', () => {
    assert.equal(U.safeFileName('../../etc/passwd'), '.._.._etc_passwd'.replace(/^\.+/, ''));
    assert.equal(U.safeFileName('a:b*c?.apk'), 'a_b_c_.apk');
    assert.equal(U.safeFileName('', 'fb'), 'fb');
    assert.ok(!U.safeFileName('..hidden').startsWith('.'));
});

test('base64 helpers round-trip binary data', () => {
    const bytes = Uint8Array.from({ length: 70000 }, (_, i) => (i * 31) & 255);
    const back = U.base64ToBytes(U.bytesToBase64(bytes));
    assert.equal(Buffer.compare(Buffer.from(back), Buffer.from(bytes)), 0);
    assert.throws(() => U.base64ToBytes('  \n'), /Empty/);
});

test('parseLsLine handles toybox ISO, legacy format, symlinks, spaces and rejects noise', () => {
    const a = plain(U.parseLsLine('drwxrwx--x  3 u0_a123 u0_a123 4096 2024-03-04 11:30 my folder'));
    assert.deepEqual([a.isDir, a.name, a.size, a.owner], [true, 'my folder', 4096, 'u0_a123']);
    const b = plain(U.parseLsLine('lrwxrwxrwx 1 root root 21 2024-01-01 00:00 sdcard -> /storage/self/primary'));
    assert.deepEqual([b.isLink, b.name, b.target], [true, 'sdcard', '/storage/self/primary']);
    const c = plain(U.parseLsLine('-rw-rw---- root sdcard_rw 1234 Jan 02 12:34 old.txt'));
    assert.deepEqual([c.name, c.size], ['old.txt', 1234]);
    const d = plain(U.parseLsLine('-rw-r--r-- 1 shell shell 77 2024-03-04 11:30:15.123456789 +0000 file.log'));
    assert.equal(d.name, 'file.log');
    assert.equal(U.parseLsLine('total 48'), null);
    assert.equal(U.parseLsLine('ls: /x: Permission denied'), null);
    assert.equal(U.parseLsLine('drwx------ 2 u0 u0 4096 2024-03-04 11:30 .'), null);
});

test('crc32 matches the standard check value', () => {
    assert.equal(U.crc32(new TextEncoder().encode('123456789')), 0xCBF43926);
});

test('buildZip produces archives that standard tools can read', () => {
    const files = [
        { name: 'hello.txt', data: 'hello world' },
        { name: 'dir/bin.dat', data: Uint8Array.from({ length: 100000 }, (_, i) => i & 255) },
        { name: 'ünïcode-日本.txt', data: '✓' }
    ];
    const zip = U.buildZip(files);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zip-'));
    const file = path.join(dir, 'a.zip');
    fs.writeFileSync(file, zip);
    const py = `import zipfile,sys\nz=zipfile.ZipFile(sys.argv[1])\nassert z.testzip() is None\nprint('|'.join(sorted(z.namelist())))\nassert z.read('hello.txt')==b'hello world'\nassert len(z.read('dir/bin.dat'))==100000\nassert z.read('ünïcode-日本.txt').decode()=='✓'`;
    const r = spawnSync('python3', ['-c', py, file], { encoding: 'utf8' });
    fs.rmSync(dir, { recursive: true, force: true });
    assert.equal(r.status, 0, r.stderr);
});

test('parsePackageFlags merges flags and privateFlags', () => {
    const f = U.parsePackageFlags('  pkgFlags=[ HAS_CODE ]\n    flags=[ DEBUGGABLE ALLOW_BACKUP ]\n    privateFlags=[ PRIVATE_FLAG_X ]');
    assert.deepEqual([...f].sort(), ['ALLOW_BACKUP', 'DEBUGGABLE', 'HAS_CODE', 'PRIVATE_FLAG_X']);
    assert.equal(U.parsePackageFlags('nothing').size, 0);
});

test('severity helpers', () => {
    assert.equal(U.normalizeSeverity('warning'), 'medium');
    assert.equal(U.normalizeSeverity('???'), 'info');
    assert.equal(U.maxSeverity('low', 'high'), 'high');
    assert.equal(U.maxSeverity('critical', 'medium'), 'critical');
});

const report = () => ({
    packageName: 'com.x', timestamp: '2026-01-01T00:00:00Z', summary: { pass: 1, fail: 1, review: 1, error: 0 },
    tests: [
        { id: 'A', title: 'Pass test', status: 'pass', severity: 'info', findings: [] },
        { id: 'B', title: '<b>Evil</b>', status: 'fail', severity: 'critical', category: 'MASVS-X', description: 'd', findings: [{ note: '=HYPERLINK("http://x")', recommendation: 'fix' }] },
        { id: 'C', title: 'Rev', status: 'review', severity: 'medium', findings: [{ note: 'n' }] }
    ]
});

test('risk score is bounded and monotonic', () => {
    assert.equal(U.computeRiskScore({ tests: [] }), 0);
    const r = report();
    const s = U.computeRiskScore(r);
    assert.ok(s > 20 && s <= 100);
    r.tests.push(...Array.from({ length: 20 }, () => ({ status: 'fail', severity: 'critical' })));
    assert.equal(U.computeRiskScore(r), 100);
    assert.equal(U.riskLabel(0), 'Minimal');
    assert.equal(U.riskLabel(100), 'Critical');
});

test('CSV export neutralises formula injection and quotes cells', () => {
    const csv = U.reportToCSV(report());
    assert.ok(csv.includes(`"'=HYPERLINK(""http://x"")"`));
    assert.equal(csv.split('\r\n').length, 4);
});

test('HTML export escapes content; Markdown contains credits', () => {
    const html = U.reportToHtml(report(), { device: 'Pixel <9>' });
    assert.ok(!html.includes('<b>Evil</b>'));
    assert.ok(html.includes('&lt;b&gt;Evil&lt;/b&gt;'));
    assert.ok(html.includes('Pixel &lt;9&gt;'));
    const md = U.reportToMarkdown(report());
    assert.match(md, /Risk score/);
    assert.match(md, /0x0806/);
    assert.match(md, /Sandeep Wawdane/);
});

test('parseLsLine understands Android 5-6 listings without a link-count column', () => {
    const e = plain(U.parseLsLine('-rw-rw---- root sdcard_rw 1234 2016-03-04 11:30 my file.txt'));
    assert.deepEqual([e.name, e.size, e.owner, e.isDir], ['my file.txt', 1234, 'root', false]);
    const d = plain(U.parseLsLine('drwxrwx--x root sdcard_rw 2016-03-04 11:30 Android'));
    assert.deepEqual([d.name, d.isDir, d.size, d.owner], ['Android', true, 0, 'root']);   // toolbox prints no size for directories
    assert.equal(plain(U.parseLsLine('lrwxrwxrwx root root 2016-03-04 11:30 sdcard -> /storage/emulated/legacy')).target, '/storage/emulated/legacy');
    assert.equal(U.parseLsLine('-rw-rw---- root sdcard_rw 2016-03-04 11:30 file-without-size'), null, 'a regular file always has a size');
});
