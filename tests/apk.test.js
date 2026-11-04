'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadLibs } = require('./helpers/env');
const B = require('./helpers/apk-builder');

const A = loadLibs().ApkAnalyzer;
const plain = x => JSON.parse(JSON.stringify(x));
const run = (buf, opts) => A.analyzeApk(new Uint8Array(buf), opts).then(plain);
const haveSsl = B.hasOpenssl();

test('ZIP: reads deflated and stored entries even when local extra fields differ from the central directory', async () => {
    const zip = new A.ZipReader(new Uint8Array(B.buildZip([
        { name: 'a.txt', data: Buffer.from('hello hello hello hello') }, { name: 'dir/b.bin', data: Buffer.from([1, 2, 3, 4]), deflate: false }], { localExtra: 13 })));
    assert.deepEqual(plain(zip.names()), ['a.txt', 'dir/b.bin']);
    assert.equal(Buffer.from(await zip.read('a.txt')).toString(), 'hello hello hello hello');
    assert.deepEqual(Array.from(await zip.read('dir/b.bin')), [1, 2, 3, 4]);
    await assert.rejects(() => zip.read('nope'), /No such entry/);
});

test('ZIP: rejects non-zip input and truncated central directories', () => {
    assert.throws(() => new A.ZipReader(new Uint8Array(100)), /Not a ZIP/);
});

for (const [label, axml] of [['UTF-16 string pool', {}], ['UTF-8 string pool', { utf8: true }], ['stripped attribute names (resource-map only)', { stripNames: true }]]) {
    test(`manifest decoding: ${label}`, async () => {
        const r = await run(B.buildApk({ manifest: { axml } }));
        const m = r.manifest;
        assert.equal(m.package, 'com.example.app');
        assert.equal(m.versionName, '1.2.3');
        assert.equal(m.versionCode, 42);
        assert.equal(m.minSdk, 19);
        assert.equal(m.targetSdk, 28);
        assert.deepEqual(m.permissions.sort(), ['android.permission.CAMERA', 'android.permission.INTERNET', 'android.permission.READ_SMS']);
        assert.equal(m.application.debuggable, true);
        assert.equal(m.application.allowBackup, undefined);
        assert.equal(m.components.length, 7);
    });
}

test('manifest: implicit and explicit export rules', async () => {
    const m = (await run(B.buildApk())).manifest;
    const c = Object.fromEntries(m.components.map(x => [x.name, x]));
    assert.equal(c['com.example.Main'].exported, true);            // intent-filter, no explicit value -> implicitly exported
    assert.equal(c['com.example.Main'].exportedExplicit, false);
    assert.equal(c['com.example.Boot'].exported, true);
    assert.equal(c['com.example.Sync'].exported, true);
    assert.equal(c['com.example.Guarded'].permission, 'com.example.PERM');
    assert.equal(c['com.example.Private'].exported, false);
    assert.equal(c['com.example.Data'].grantUriPermissions, true);
    assert.deepEqual(c['com.example.Deep'].intentFilters[0].data[0].scheme, 'myapp');
});

test('manifest findings: debuggable, backup default, providers, unguarded service, custom scheme, old SDKs', async () => {
    const f = (await run(B.buildApk())).manifestFindings;
    const ids = f.map(x => x.id);
    for (const id of ['debuggable', 'allowBackup', 'minSdk', 'targetSdk', 'provider-exported', 'grant-uri', 'service-exported', 'custom-scheme', 'dangerous-permissions']) {
        assert.ok(ids.includes(id), 'missing finding ' + id);
    }
    assert.equal(f.find(x => x.id === 'debuggable').severity, 'critical');
    // the permission-guarded service must NOT be reported
    assert.ok(!f.some(x => x.id === 'service-exported' && x.title.includes('Guarded')));
    assert.ok(!f.some(x => x.title.includes('Private')));
});

test('manifest findings: cleartext default depends on targetSdk', async () => {
    const old = (await run(B.buildApk({ manifest: { targetSdk: 24 } }))).manifestFindings;
    assert.ok(old.some(x => x.id === 'cleartext-default'));
    const modern = (await run(B.buildApk({ manifest: { targetSdk: 28 } }))).manifestFindings;
    assert.ok(!modern.some(x => x.id === 'cleartext-default'));
});

test('manifest findings: hardened app is clean', async () => {
    const f = (await run(B.buildApk({ manifest: { debuggable: false, allowBackup: false, targetSdk: 34, minSdk: 26 } }))).manifestFindings;
    assert.ok(!f.some(x => ['debuggable', 'allowBackup', 'minSdk', 'targetSdk', 'cleartext-default'].includes(x.id)));
});

test('dex: strings table parsed; urls, ips, secrets (masked), API hints and trackers found', async () => {
    const r = await run(B.buildApk());
    assert.equal(r.dexCount, 1);
    assert.ok(r.dex.urls.includes('https://api.example.com/v1'));
    assert.deepEqual(r.dex.ips, ['10.20.30.40']);
    assert.ok(r.dex.secrets.some(s => s.type === 'aws_access_key'));
    assert.ok(!JSON.stringify(r).includes('AKIAABCDEFGHIJKLMNOP'), 'raw secret must not be reported');
    assert.ok(r.dex.apis.some(a => a.label === 'Dynamic code loading'));
    assert.ok(r.dex.trackers.includes('Facebook SDK'));
});

test('dex: handles multi-byte UTF-8 strings and rejects non-dex data', () => {
    const dex = new Uint8Array(B.buildDex(['héllo✓', 'x'.repeat(300)]));
    const s = A.readDexStrings(dex);
    assert.equal(s[0], 'héllo✓');
    assert.equal(s[1].length, 300);
    assert.throws(() => A.readDexStrings(new Uint8Array(200)), /Not a DEX/);
});

test('frameworks, native libs and embedded code detected', async () => {
    const r = await run(B.buildApk());
    assert.deepEqual(r.frameworks, ['Flutter']);
    assert.deepEqual(r.nativeLibs.abis, ['arm64-v8a']);
    assert.deepEqual(r.embeddedCode, ['assets/payload.dex']);
    assert.ok(r.findings.some(f => f.id === 'embedded'));
});

test('hashes match the file', async () => {
    const buf = B.buildApk();
    const r = await run(buf);
    const crypto = require('crypto');
    assert.equal(r.hashes.sha256, crypto.createHash('sha256').update(buf).digest('hex'));
    assert.equal(r.hashes.sha1, crypto.createHash('sha1').update(buf).digest('hex'));
});

test('unsigned APK is reported as unsigned (no false certificate)', async () => {
    const r = await run(B.buildApk());
    assert.equal(r.signing.schemes.length, 0);
    assert.equal(r.signing.certs.length, 0);
    assert.ok(r.signing.notes.some(n => /unsigned/.test(n)));
});

test('v1 signature: certificate parsed, debug cert flagged', { skip: !haveSsl }, async () => {
    const { pkcs7 } = B.makeSignature({ subject: '/CN=Android Debug/O=Android/C=US' });
    const r = await run(B.buildApk({ v1: pkcs7 }));
    assert.deepEqual(r.signing.schemes, [1]);
    const c = r.signing.certs[0];
    assert.match(c.subject, /CN=Android Debug/);
    assert.equal(c.debug, true);
    assert.equal(c.publicKey, 'RSA-2048');
    assert.equal(c.signatureAlgorithm, 'SHA256withRSA');
    assert.equal(c.selfSigned, true);
    assert.match(c.sha256, /^([0-9a-f]{2}:){31}[0-9a-f]{2}$/);
    assert.ok(r.signing.findings.some(f => /debug certificate/.test(f.title)));
    assert.ok(r.signing.findings.some(f => /v1 \(JAR\)/.test(f.title)));
});

test('v2 signing block: scheme and certificate extracted when there is no v1 signature', { skip: !haveSsl }, async () => {
    const { der } = B.makeSignature({ subject: '/CN=Release Key/O=Acme/C=DE', algo: 'sha256' });
    const r = await run(B.buildApk({ v2cert: der }));
    assert.deepEqual(r.signing.schemes, [2]);
    assert.equal(r.signing.certs.length, 1);
    assert.match(r.signing.certs[0].subject, /CN=Release Key, O=Acme|O=Acme/);
    assert.equal(r.signing.certs[0].debug, false);
    assert.ok(!r.signing.findings.some(f => /JAR/.test(f.title)));
});

test('weak signature algorithm and short RSA key are flagged', { skip: !haveSsl }, async () => {
    const { pkcs7 } = B.makeSignature({ subject: '/CN=Old/O=X', algo: 'sha1', bits: 1024 });
    const r = await run(B.buildApk({ v1: pkcs7 }));
    assert.ok(r.signing.findings.some(f => /Weak certificate signature/.test(f.title)), JSON.stringify(r.signing.findings));
    assert.ok(r.signing.findings.some(f => /Short RSA/.test(f.title)));
});

test('a broken manifest yields a warning instead of throwing', async () => {
    const buf = B.buildZip([{ name: 'AndroidManifest.xml', data: Buffer.from('not xml') }, { name: 'classes.dex', data: B.buildDex(['a']) }]);
    const r = await run(buf);
    assert.ok(r.warnings.some(w => /Manifest/.test(w)));
    assert.ok(r.dex);
});

test('markdown report contains findings and both credits', async () => {
    const r = A.apkReportToMarkdown(await A.analyzeApk(new Uint8Array(B.buildApk())), 'test.apk');
    assert.match(r, /APK Static Analysis - com\.example\.app/);
    assert.match(r, /\[critical\]/);
    assert.match(r, /0x0806/);
    assert.match(r, /Sandeep Wawdane/);
});

// Opt-in: set ADBAUD_APK_DIR to a folder of your own APKs to smoke-test the analyzer against real-world files.
const dir = process.env.ADBAUD_APK_DIR;
test('real APKs analyse without errors (opt-in via ADBAUD_APK_DIR)', { skip: !dir }, async () => {
    const fs = require('fs'), path = require('path');
    for (const f of fs.readdirSync(dir).filter(n => n.endsWith('.apk')).slice(0, 5)) {
        const r = await run(fs.readFileSync(path.join(dir, f)), { skipDex: false });
        assert.ok(r.manifest && r.manifest.package, f + ': manifest parsed');
        assert.equal(r.warnings.filter(w => /Manifest/.test(w)).length, 0, f);
    }
});
