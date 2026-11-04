'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadLibs } = require('./helpers/env');
const { MockAdbDevice } = require('./helpers/mock-device');
const { webcrypto } = require('crypto');
const plain = x => JSON.parse(JSON.stringify(x)); // vm contexts have their own prototypes

function memoryCredentials(ctx) {
    const keys = [];
    return {
        keys,
        async getKeys() { return keys.slice(); },
        async generateKey() {
            const kp = await webcrypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['sign']);
            const buffer = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', kp.privateKey));
            keys.push(buffer);
            return { buffer, privateKey: kp.privateKey };
        },
        async importKey(buf) { return webcrypto.subtle.importKey('pkcs8', buf, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' }, false, ['sign']); }
    };
}

async function connect(opts = {}) {
    const ctx = loadLibs();
    const dev = new MockAdbDevice(opts);
    const adb = new ctx.ADBConnection();
    adb.credentials = memoryCredentials(ctx);
    adb.device = dev;
    await adb.openDevice();
    await adb.authenticate();
    return { ctx, dev, adb };
}

test('connects and reads banner, negotiating maxPayload', async () => {
    const { adb } = await connect({ maxdata: 4096 });
    assert.ok(adb.connected);
    assert.equal(adb.maxPayload, 4096);
    assert.match(adb.banner, /Mock/);
});

test('shell returns output, reassembling 1-byte USB chunks', async () => {
    const { adb } = await connect({ outChunk: 1, shell: cmd => `echo:${cmd}\n` });
    assert.equal(await adb.shell('hello'), 'echo:hello');
});

test('shell decodes multibyte UTF-8 split across packets', async () => {
    const text = 'héllo wörld ✓ 日本語 🚀'.repeat(300);
    const { adb } = await connect({ maxdata: 4096, shell: () => new TextEncoder().encode(text) });
    assert.equal(await adb.shell('x'), text.trim());
});

test('large shell output spans many WRTE packets', async () => {
    const big = 'A'.repeat(500000);
    const { adb } = await connect({ shell: () => big });
    assert.equal((await adb.shell('big')).length, big.length);
});

test('concurrent shell commands do not corrupt each other (serialised transport)', async () => {
    const { adb, dev } = await connect({
        outChunk: 13,
        shell: async cmd => { await new Promise(r => setTimeout(r, Math.random() * 15)); return cmd.repeat(2000); }
    });
    const cmds = Array.from({ length: 12 }, (_, i) => `cmd${i}-`);
    const results = await Promise.all(cmds.map(c => adb.shell(c)));
    results.forEach((r, i) => assert.equal(r, cmds[i].repeat(2000)));
    assert.ok(dev.maxConcurrent > 1, 'commands really ran concurrently');
});

test('shell timeout fires when device stays silent (and does not desync the stream)', async () => {
    const { adb } = await connect({ shell: cmd => cmd === 'slow' ? new Promise(r => setTimeout(() => r('late'), 400)) : 'ok' });
    await assert.rejects(() => adb.shell('slow', 100), e => e.type === 'TIMEOUT');
    // the same connection must still work afterwards
    assert.equal(await adb.shell('fast'), 'ok');
});

test('shellWithStatus extracts exit code', async () => {
    const { adb } = await connect({ shell: cmd => (cmd.includes('__ADBAUD_RC__') ? 'out\n__ADBAUD_RC__3\n' : '') });
    assert.deepEqual(plain(await adb.shellWithStatus('false')), { output: 'out', code: 3 });
});

test('pull file with progress and size from STAT', async () => {
    const data = Uint8Array.from({ length: 300000 }, (_, i) => i % 251);
    const { adb } = await connect({ outChunk: 100, files: { '/sdcard/a.bin': data } });
    const seen = [];
    const got = await adb.pullFile('/sdcard/a.bin', (n, total) => seen.push([n, total]));
    assert.deepEqual(Array.from(got), Array.from(data));
    assert.equal(seen.at(-1)[0], data.length);
    assert.equal(seen.at(-1)[1], data.length);
});

test('pull of missing file reports a permission/not-found error', async () => {
    const { adb } = await connect({ files: {} });
    await assert.rejects(() => adb.pullFile('/nope'), /File read failed/);
});

test('push respects small device maxdata (chunks never exceed negotiated payload)', async () => {
    const data = Uint8Array.from({ length: 50000 }, (_, i) => (i * 7) % 256);
    const { adb, dev } = await connect({ maxdata: 4096 });
    const progress = [];
    await adb.pushFile('/sdcard/up.bin', data, 0o644, (n, t) => progress.push([n, t]));
    assert.deepEqual(Array.from(dev.pushed['/sdcard/up.bin']), Array.from(data));
    assert.equal(progress.at(-1)[0], data.length);
});

test('sync LIST parses directory entries and ignores . / ..', async () => {
    const { adb } = await connect({ dirs: { '/d': [
        { name: '.', mode: 0o040755, size: 0 }, { name: '..', mode: 0o040755, size: 0 },
        { name: 'sub', mode: 0o040755, size: 4096 }, { name: 'f.txt', mode: 0o100644, size: 12, mtime: 1700000000 },
        { name: 'lnk', mode: 0o120777, size: 5 }] } });
    const list = await adb.listDirectory('/d');
    assert.deepEqual(plain(list.map(e => e.name)), ['sub', 'f.txt', 'lnk']);
    assert.ok(list[0].isDirectory && list[1].isFile && list[2].isLink && !list[2].isDirectory);
});

test('streamShell streams chunks and stops cleanly while other commands still work', async () => {
    let dev;
    const { adb, dev: d } = await connect({ shell: (cmd, device) => {
        if (cmd === 'logcat') { return new Promise(() => {}); } // never ends by itself
        return 'pong';
    } });
    dev = d;
    const chunks = [];
    const stream = await adb.streamShell('logcat', c => chunks.push(c));
    // push data for the streaming socket manually
    const sock = [...dev.sockets.values()].find(s => s.service === 'shell:logcat');
    dev._write(sock, new TextEncoder().encode('line one\nline two\n'), false);
    assert.equal(await adb.shell('ping'), 'pong');
    await new Promise(r => setTimeout(r, 50));
    assert.equal(chunks.join(''), 'line one\nline two\n');
    await stream.stop();
    assert.equal(await adb.shell('ping'), 'pong');
});

test('USB write failure marks connection lost and fires onDisconnect once', async () => {
    const { adb, dev } = await connect({ shell: () => 'x' });
    let calls = 0;
    adb.onDisconnect = () => calls++;
    dev.failNextWrite = true;
    await assert.rejects(() => adb.shell('a'), e => e.type === 'CONNECTION_LOST');
    await assert.rejects(() => adb.shell('b'), e => e.type === 'CONNECTION_LOST');
    assert.equal(calls, 1);
    assert.equal(adb.isConnected(), false);
});

test('device unplugged during a read is detected', async () => {
    const { adb, dev } = await connect({ shell: () => new Promise(() => {}) });
    const p = adb.shell('hang', 5000);
    setTimeout(() => dev.unplug(), 30);
    await assert.rejects(p, e => e.type === 'CONNECTION_LOST');
});

test('corrupt packet magic is rejected as lost connection', async () => {
    const { adb, dev } = await connect({ shell: () => 'x' });
    const bad = new Uint8Array(24); // cmd=0, magic=0 -> invalid
    bad[0] = 1;
    dev._emit(bad);
    await assert.rejects(() => adb.recvPacket(1000), e => e.type === 'CONNECTION_LOST');
});

test('getDeviceProps fetches everything in one round trip', async () => {
    let shells = 0;
    const { adb } = await connect({ shell: cmd => {
        shells++;
        if (cmd.includes('getprop')) return [...cmd.matchAll(/echo "(\w+)=/g)].map(m => m[1] + '=' + m[1].toUpperCase() + '!').join('\n');
        if (cmd.includes('dumpsys battery')) return 'level: 77\ntemperature: 305\nstatus: 2';
        return '';
    } });
    const props = await adb.getDeviceProps();
    assert.equal(props.model, 'MODEL!');
    assert.equal(props.batteryLevel, 77);
    assert.equal(props.batteryTemp, 30.5);
    assert.equal(props.charging, true);
    assert.equal(shells, 2);
});

test('getApkPaths validates package names and returns split APKs', async () => {
    const { adb } = await connect({ shell: cmd => cmd.includes("'com.a.b'") ? 'package:/data/app/base.apk\npackage:/data/app/split_x.apk' : '' });
    assert.deepEqual(plain(await adb.getApkPaths('com.a.b')), ['/data/app/base.apk', '/data/app/split_x.apk']);
    await assert.rejects(() => adb.getApkPaths('x; reboot'), /Invalid package/);
});

test('screenshot rejects non-PNG payloads', async () => {
    const { adb } = await connect({ shell: () => 'not a png' });
    await assert.rejects(() => adb.takeScreenshot(), /Screenshot failed/);
});

/* ---------- authentication ---------- */

test('auth: first connect sends public key, second connect signs the token with the stored key', async () => {
    const ctx = loadLibs();
    const I = ctx.ADBInternals;
    const accepted = [];
    const creds = memoryCredentials(ctx);
    const verify = (token, sig) => {
        if (!accepted.length) return false;
        const blob = Buffer.from(accepted[0], 'base64');
        const le = b => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
        const n = le(blob.subarray(8, 264));
        const e = BigInt(blob.readUInt32LE(520));
        const em = I.modPow(I.bytesToBigInt(sig), e, n);
        return em === I.bytesToBigInt(I.pkcs1Sha1Block(token, 256));
    };
    const auth = { verify, onPublicKey: b64 => accepted.push(b64) };

    const dev1 = new MockAdbDevice({ auth });
    const adb1 = new ctx.ADBConnection(); adb1.credentials = creds; adb1.device = dev1;
    await adb1.openDevice(); await adb1.authenticate();
    assert.equal(accepted.length, 1);
    assert.equal(creds.keys.length, 1);

    const dev2 = new MockAdbDevice({ auth, shell: () => 'ok' });
    const adb2 = new ctx.ADBConnection(); adb2.credentials = creds; adb2.device = dev2;
    await adb2.openDevice(); await adb2.authenticate();
    assert.equal(accepted.length, 1, 'no new public key needed: signature was accepted');
    assert.equal(creds.keys.length, 1);
    assert.equal(await adb2.shell('x'), 'ok');
});

test('public key blob has Android layout (64 words, correct n0inv, rr, exponent)', async () => {
    const ctx = loadLibs();
    const I = ctx.ADBInternals;
    const kp = await webcrypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['sign']);
    const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', kp.privateKey));
    const blob = Buffer.from(I.generatePublicKey(pkcs8), 'base64');
    assert.equal(blob.length, 524);
    assert.equal(blob.readUInt32LE(0), 64);
    const { n } = I.parsePkcs8Rsa(pkcs8);
    const le = b => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
    assert.equal(le(blob.subarray(8, 264)), n);
    // n0inv * n[0] == -1 mod 2^32
    assert.equal((BigInt(blob.readUInt32LE(4)) * (n & 0xffffffffn)) % 0x100000000n, 0xffffffffn);
    assert.equal(le(blob.subarray(264, 520)), ((1n << 2048n) ** 2n) % n);
    assert.equal(blob.readUInt32LE(520), 65537);
});

test('raw token signature verifies against the RSA public key', async () => {
    const ctx = loadLibs();
    const I = ctx.ADBInternals;
    const kp = await webcrypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['sign']);
    const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', kp.privateKey));
    const token = Uint8Array.from({ length: 20 }, (_, i) => i * 11);
    const sig = I.signAdbToken(pkcs8, token);
    const { n, e } = I.parsePkcs8Rsa(pkcs8);
    assert.equal(I.modPow(I.bytesToBigInt(sig), e, n), I.bytesToBigInt(I.pkcs1Sha1Block(token, 256)));
});
