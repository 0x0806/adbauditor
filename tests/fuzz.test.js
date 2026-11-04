'use strict';
// Deterministic mutation fuzzing: parsers must fail with a clean Error (never hang, never leak RangeError/TypeError).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { loadLibs, load } = require('./helpers/env');
const B = require('./helpers/apk-builder');

const ctx = load(loadLibs(), ['js/sqlite-reader.js']);
const A = ctx.ApkAnalyzer;

function rng(seed) { let s = seed; return () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff; }
function mutate(buf, rnd) {
    const b = Buffer.from(buf); const n = 1 + Math.floor(rnd() * 8);
    for (let i = 0; i < n; i++) {
        const m = rnd(), pos = Math.floor(rnd() * b.length);
        if (m < 0.5) b[pos] = Math.floor(rnd() * 256);
        else if (m < 0.7) b.writeUInt32LE(Math.floor(rnd() * 0xffffffff), Math.min(pos, b.length - 4));
        else if (m < 0.85) { for (let k = 0; k < 8 && pos + k < b.length; k++) b[pos + k] = 0xff; }
        else return b.subarray(0, pos);
    }
    return b;
}
const isCleanError = (e) => e && e.name === 'Error';

test('APK analyzer: mutated APKs either analyse or fail with a clean Error, quickly', async () => {
    const sig = B.hasOpenssl() ? B.makeSignature() : null;
    const base = B.buildApk({ v1: sig && sig.pkcs7, v2cert: sig && sig.der });
    const rnd = rng(42);
    for (let i = 0; i < 400; i++) {
        const t0 = Date.now();
        try { await A.analyzeApk(new Uint8Array(mutate(base, rnd))); } catch (e) { assert.ok(isCleanError(e), `iteration ${i}: ${e && e.name}: ${e && e.message}`); }
        assert.ok(Date.now() - t0 < 2000, `iteration ${i} was slow`);
    }
});

test('binary XML decoder: mutated manifests fail cleanly', () => {
    const ax = B.buildAxml(B.manifestRoot({}));
    const rnd = rng(7);
    for (let i = 0; i < 1500; i++) {
        const t0 = Date.now();
        try { A.decodeAxml(new Uint8Array(mutate(ax, rnd))); } catch (e) { assert.ok(isCleanError(e), `iteration ${i}: ${e && e.name}: ${e && e.message}`); }
        assert.ok(Date.now() - t0 < 500);
    }
});

test('DEX reader: mutated dex files fail cleanly', () => {
    const dex = B.buildDex(['Lcom/x;', 'https://a.b/c', 'hello']);
    const rnd = rng(9);
    for (let i = 0; i < 1000; i++) {
        try { A.readDexStrings(new Uint8Array(mutate(dex, rnd))); } catch (e) { assert.ok(isCleanError(e), `iteration ${i}: ${e && e.name}: ${e && e.message}`); }
    }
});

const py = spawnSync('python3', ['-c', 'import sqlite3']).status === 0;
test('SQLite reader: corrupted databases fail with a clean Error and never hang', { skip: !py }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'abfz-'));
    try {
        assert.equal(spawnSync('python3', [path.join(__dirname, 'helpers', 'make-sqlite.py'), dir]).status, 0);
        for (const [file, seed] of [['basic.db', 1], ['big.db', 2]]) {
            const src = fs.readFileSync(path.join(dir, file)); const rnd = rng(seed);
            for (let i = 0; i < 300; i++) {
                const t0 = Date.now();
                try {
                    const d = new ctx.SqliteDb(new Uint8Array(mutate(src, rnd)));
                    for (const t of d.tables()) { d.rows(t.name, { limit: 50 }); d.count(t.name); }
                } catch (e) { assert.ok(isCleanError(e), `${file} #${i}: ${e && e.name}: ${e && e.message}`); }
                assert.ok(Date.now() - t0 < 2000, `${file} #${i} was slow (${Date.now() - t0} ms)`);
            }
        }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('SQLite reader: a record header claiming an enormous length is rejected instantly', () => {
    const { SqliteDb } = ctx;
    const db = Object.create(SqliteDb.prototype);
    db.encoding = 1;
    assert.throws(() => db._decodeRecord(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x01])), /Corrupt database/);
});

test('APK analyzer: corrupting the inner manifest / dex / certificate / signing block never throws', async () => {
    const sig = B.hasOpenssl() ? B.makeSignature() : null;
    const axml = B.buildAxml(B.manifestRoot({}));
    const dex = B.buildDex(['Lcom/x;', 'https://a.b/c', 'AKIAABCDEFGHIJKLMNOP', 'Lcom/facebook/Foo;']);
    const block = sig ? B.signingBlock(sig.der) : null;
    const rnd = rng(1234);
    let analysed = 0;
    for (let i = 0; i < 500; i++) {
        const files = [
            { name: 'AndroidManifest.xml', data: rnd() < 0.7 ? mutate(axml, rnd) : axml },
            { name: 'classes.dex', data: rnd() < 0.7 ? mutate(dex, rnd) : dex }
        ];
        if (sig) { files.push({ name: 'META-INF/CERT.SF', data: Buffer.from('x') }, { name: 'META-INF/CERT.RSA', data: rnd() < 0.7 ? mutate(sig.pkcs7, rnd) : sig.pkcs7 }); }
        const zip = B.buildZip(files, { extraBeforeCentral: block ? (rnd() < 0.7 ? mutate(block, rnd) : block) : null });
        const t0 = Date.now();
        let report;
        try { report = await A.analyzeApk(new Uint8Array(zip)); } catch (e) { assert.fail(`iteration ${i}: analyzeApk threw ${e && e.name}: ${e && e.message}`); }
        assert.ok(Date.now() - t0 < 2000, `iteration ${i} slow`);
        assert.ok(Array.isArray(report.findings) && report.signing && report.hashes);
        analysed++;
    }
    assert.equal(analysed, 500);
});
