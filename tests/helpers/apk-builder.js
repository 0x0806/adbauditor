'use strict';
// Builds small but structurally real APKs for tests: binary AndroidManifest (AXML), DEX string table,
// deflated ZIP entries (with local extra fields that differ from the central directory), signatures.
const zlib = require('zlib');
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ANDROID_NS = 'http://schemas.android.com/apk/res/android';
const ATTR_IDS = { name: 0x1010003, exported: 0x1010010, permission: 0x1010006, debuggable: 0x101000f, allowBackup: 0x1010280, usesCleartextTraffic: 0x10104ec,
    minSdkVersion: 0x101020c, targetSdkVersion: 0x1010270, versionCode: 0x101021b, versionName: 0x101021c, scheme: 0x1010027, host: 0x1010028,
    authorities: 0x1010018, grantUriPermissions: 0x101001b, autoVerify: 0x10104ee, networkSecurityConfig: 0x1010527 };

function u16(n) { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; }
function u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; }

function stringPool(strings, utf8) {
    const bodies = strings.map(s => {
        if (utf8) {
            const raw = Buffer.from(s, 'utf8');
            return Buffer.concat([Buffer.from([s.length, raw.length]), raw, Buffer.from([0])]);
        }
        const raw = Buffer.from(s, 'utf16le');
        return Buffer.concat([u16(s.length), raw, u16(0)]);
    });
    const offsets = []; let off = 0;
    for (const b of bodies) { offsets.push(off); off += b.length; }
    let data = Buffer.concat(bodies);
    while (data.length % 4) data = Buffer.concat([data, Buffer.from([0])]);
    const headerSize = 28, stringsStart = headerSize + strings.length * 4;
    const size = stringsStart + data.length;
    return Buffer.concat([u16(0x0001), u16(headerSize), u32(size), u32(strings.length), u32(0), u32(utf8 ? 0x100 : 0), u32(stringsStart), u32(0),
        ...offsets.map(u32), data]);
}

/** node: { name, attrs: [[attrName, value, ns?]], children } ; values: string | number | boolean */
function buildAxml(root, { utf8 = false, stripNames = false } = {}) {
    const strings = []; const idx = (s) => { let i = strings.indexOf(s); if (i < 0) { i = strings.length; strings.push(s); } return i; };
    // resource-map attributes must come first in the pool
    const resAttrs = Object.keys(ATTR_IDS);
    resAttrs.forEach(a => idx(stripNames ? '' : a)); // when stripped, names are empty strings (only the res map identifies them)
    if (stripNames) { strings.length = 0; resAttrs.forEach((a, i) => strings.push('x' + i)); }
    const nameIdx = (a) => (stripNames ? resAttrs.indexOf(a) : strings.indexOf(a));
    const nsIdx = idx(ANDROID_NS), prefixIdx = idx('android');
    const chunks = [];
    const emit = (node) => {
        const attrs = node.attrs.map(([n, v]) => ({ n, v }));
        const body = [];
        const own = ATTR_IDS[node.attrs[0] && node.attrs[0][0]] !== undefined;
        void own;
        const tagIdx = idx(node.name);
        const buf = [u32(0xffffffff), u32(tagIdx), u16(20), u16(20), u16(attrs.length), u16(0), u16(0), u16(0)];
        for (const { n, v } of attrs) {
            const isAndroid = ATTR_IDS[n] !== undefined;
            const aName = isAndroid ? nameIdx(n) : idx(n);
            let raw = 0xffffffff, type = 0x03, data = 0;
            if (typeof v === 'string') { raw = idx(v); data = raw; type = 0x03; }
            else if (typeof v === 'boolean') { type = 0x12; data = v ? 0xffffffff : 0; }
            else if (v && v.ref) { type = 0x01; data = v.ref; }
            else { type = 0x10; data = v; }
            buf.push(u32(isAndroid ? nsIdx : 0xffffffff), u32(aName), u32(raw), u16(8), Buffer.from([0, type]), u32(data));
        }
        const payload = Buffer.concat(buf);
        chunks.push(Buffer.concat([u16(0x0102), u16(16), u32(16 + payload.length), u32(1), u32(0xffffffff), payload]));
        node.children.forEach(emit);
        chunks.push(Buffer.concat([u16(0x0103), u16(16), u32(24), u32(1), u32(0xffffffff), u32(0xffffffff), u32(tagIdx)]));
        void body;
    };
    // first pass registers all strings so the pool is complete before encoding
    const register = (node) => { idx(node.name); node.attrs.forEach(([n, v]) => { if (ATTR_IDS[n] === undefined) idx(n); if (typeof v === 'string') idx(v); }); node.children.forEach(register); };
    register(root);
    const resMap = Buffer.concat([u16(0x0180), u16(8), u32(8 + resAttrs.length * 4), ...resAttrs.map(a => u32(ATTR_IDS[a]))]);
    emit({ name: root.name, attrs: root.attrs, children: root.children });
    const pool = stringPool(strings, utf8);
    const nsStart = Buffer.concat([u16(0x0100), u16(16), u32(24), u32(1), u32(0xffffffff), u32(prefixIdx), u32(nsIdx)]);
    const nsEnd = Buffer.concat([u16(0x0101), u16(16), u32(24), u32(1), u32(0xffffffff), u32(prefixIdx), u32(nsIdx)]);
    const body = Buffer.concat([pool, resMap, nsStart, ...chunks, nsEnd]);
    return Buffer.concat([u16(0x0003), u16(8), u32(8 + body.length), body]);
}

const el = (name, attrs = [], children = []) => ({ name, attrs, children });

function sampleManifest(overrides = {}) {
    const o = Object.assign({ debuggable: true, allowBackup: undefined, targetSdk: 28, minSdk: 19 }, overrides);
    const appAttrs = [['name', 'com.example.App']];
    if (o.debuggable !== undefined) appAttrs.push(['debuggable', o.debuggable]);
    if (o.allowBackup !== undefined) appAttrs.push(['allowBackup', o.allowBackup]);
    return el('manifest', [['versionCode', 42], ['versionName', '1.2.3']].concat([['package_', 'x']].slice(0, 0)), [
        el('uses-sdk', [['minSdkVersion', o.minSdk], ['targetSdkVersion', o.targetSdk]]),
        el('uses-permission', [['name', 'android.permission.INTERNET']]),
        el('uses-permission', [['name', 'android.permission.CAMERA']]),
        el('uses-permission', [['name', 'android.permission.READ_SMS']]),
        el('application', appAttrs, [
            el('activity', [['name', 'com.example.Main']], [el('intent-filter', [], [el('action', [['name', 'android.intent.action.MAIN']]), el('category', [['name', 'android.intent.category.LAUNCHER']])])]),
            el('activity', [['name', 'com.example.Deep'], ['exported', true]], [el('intent-filter', [], [
                el('action', [['name', 'android.intent.action.VIEW']]), el('category', [['name', 'android.intent.category.BROWSABLE']]),
                el('data', [['scheme', 'myapp'], ['host', 'open']])])]),
            el('service', [['name', 'com.example.Sync'], ['exported', true]]),
            el('service', [['name', 'com.example.Guarded'], ['exported', true], ['permission', 'com.example.PERM']]),
            el('receiver', [['name', 'com.example.Boot']], [el('intent-filter', [], [el('action', [['name', 'android.intent.action.BOOT_COMPLETED']])])]),
            el('provider', [['name', 'com.example.Data'], ['authorities', 'com.example.data'], ['exported', true], ['grantUriPermissions', true]]),
            el('provider', [['name', 'com.example.Private'], ['authorities', 'com.example.priv'], ['exported', false]])
        ])
    ]);
}
// the manifest root also needs a "package" attribute (no namespace, string) - added by name
function manifestRoot(o) { const m = sampleManifest(o); m.attrs.push(['package', 'com.example.app']); return m; }

/** Minimal DEX with the given strings in its string_ids table. */
function buildDex(strings) {
    const headerSize = 0x70;
    const idsOff = headerSize;
    let dataOff = idsOff + strings.length * 4;
    const datas = [], offs = [];
    for (const s of strings) {
        offs.push(dataOff);
        const raw = Buffer.from(s, 'utf8');
        const uleb = []; let n = s.length;
        do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; uleb.push(b); } while (n);
        const d = Buffer.concat([Buffer.from(uleb), raw, Buffer.from([0])]);
        datas.push(d); dataOff += d.length;
    }
    const head = Buffer.alloc(headerSize);
    head.write('dex\n035\0', 0, 'latin1');
    head.writeUInt32LE(headerSize, 0x24);
    head.writeUInt32LE(strings.length, 0x38); head.writeUInt32LE(idsOff, 0x3c);
    head.writeUInt32LE(dataOff, 0x20);
    return Buffer.concat([head, ...offs.map(u32), ...datas]);
}

function crc32(buf) { return zlib.crc32 ? zlib.crc32(buf) >>> 0 : (() => { let c, crc = ~0; for (const b of buf) { c = (crc ^ b) & 0xff; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crc = (crc >>> 8) ^ c; } return ~crc >>> 0; })(); }

/** files: [{name, data(Buffer), deflate?}] ; extraBeforeCentral: Buffer inserted before the central directory (signing block). */
function buildZip(files, { extraBeforeCentral = null, localExtra = 8 } = {}) {
    const locals = [], centrals = []; let off = 0;
    for (const f of files) {
        const name = Buffer.from(f.name);
        const method = f.deflate === false ? 0 : 8;
        const comp = method === 8 ? zlib.deflateRawSync(f.data) : f.data;
        const crc = crc32(f.data);
        const extra = Buffer.alloc(localExtra, 0);      // local extra field deliberately differs from the central one (which is empty)
        const lh = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(method), u16(0), u16(0x21), u32(crc), u32(comp.length), u32(f.data.length), u16(name.length), u16(extra.length), name, extra, comp]);
        const ch = Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(method), u16(0), u16(0x21), u32(crc), u32(comp.length), u32(f.data.length), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(off), name]);
        locals.push(lh); centrals.push(ch); off += lh.length;
    }
    const pre = extraBeforeCentral || Buffer.alloc(0);
    const cdOff = off + pre.length;
    const cd = Buffer.concat(centrals);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(files.length), u16(files.length), u32(cd.length), u32(cdOff), u16(0)]);
    return Buffer.concat([...locals, pre, cd, eocd]);
}

function openssl(args, input) { return execFileSync('openssl', args, { input, stdio: ['pipe', 'pipe', 'pipe'] }); }
const hasOpenssl = () => spawnSync('openssl', ['version']).status === 0;

/** Self-signed cert + a PKCS#7 SignedData blob (like META-INF/CERT.RSA) and the raw cert DER. */
function makeSignature({ subject = '/CN=Android Debug/O=Android/C=US', algo = 'sha256', bits = 2048 } = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'abcert-'));
    const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem'), d = path.join(dir, 'd.txt');
    openssl(['req', '-x509', '-newkey', 'rsa:' + bits, '-nodes', '-keyout', k, '-out', c, '-days', '9000', '-subj', subject, '-' + algo]);
    fs.writeFileSync(d, 'hello');
    const pkcs7 = openssl(['smime', '-sign', '-binary', '-in', d, '-signer', c, '-inkey', k, '-outform', 'DER', '-nodetach', '-md', algo === 'md5' ? 'sha256' : algo]);
    const der = openssl(['x509', '-in', c, '-outform', 'DER']);
    fs.rmSync(dir, { recursive: true, force: true });
    return { pkcs7, der };
}

/** APK Signing Block with a v2 entry carrying one certificate. */
function signingBlock(certDer) {
    const cert = Buffer.concat([u32(certDer.length), certDer]);
    const certs = Buffer.concat([u32(cert.length), cert]);
    const digests = u32(0);
    const attrs = u32(0);
    const signedData = Buffer.concat([u32(digests.length), digests, certs, u32(attrs.length), attrs]);
    const signer = Buffer.concat([u32(signedData.length), signedData, u32(0), u32(0)]);
    const signers = Buffer.concat([u32(signer.length), signer]);
    const value = Buffer.concat([u32(signers.length), signers]);
    const idval = Buffer.concat([u32(0x7109871a), value]);
    const pair = Buffer.concat([u64(idval.length), idval]);
    const size = pair.length + 8 + 16;
    return Buffer.concat([u64(size), pair, u64(size), Buffer.from('APK Sig Block 42')]);
}
function u64(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; }

function buildApk({ manifest = {}, strings = ['Lcom/example/Main;', 'https://api.example.com/v1', 'AKIAABCDEFGHIJKLMNOP', 'Ldalvik/system/DexClassLoader;', 'setJavaScriptEnabled', 'Lcom/facebook/FacebookSdk;', '10.20.30.40'], v1 = null, v2cert = null, extraFiles = [] } = {}) {
    const files = [
        { name: 'AndroidManifest.xml', data: buildAxml(manifestRoot(manifest), manifest.axml || {}) },
        { name: 'classes.dex', data: buildDex(strings) },
        { name: 'lib/arm64-v8a/libflutter.so', data: Buffer.from('ELF'), deflate: false },
        { name: 'assets/payload.dex', data: Buffer.from('dex'), deflate: false },
        ...extraFiles
    ];
    if (v1) { files.push({ name: 'META-INF/CERT.SF', data: Buffer.from('Signature-Version: 1.0\n') }, { name: 'META-INF/CERT.RSA', data: v1 }); }
    return buildZip(files, { extraBeforeCentral: v2cert ? signingBlock(v2cert) : null });
}

module.exports = { buildAxml, manifestRoot, buildDex, buildZip, buildApk, makeSignature, signingBlock, hasOpenssl, el };
