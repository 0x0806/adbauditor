'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { createContext, load } = require('./helpers/env');

const ctx = load(createContext(), ['js/sqlite-reader.js']);
const { SqliteDb } = ctx;
const py = spawnSync('python3', ['-c', 'import sqlite3']).status === 0;
let dir = null, expected = null;
if (py) {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'absqlite-'));
    const r = spawnSync('python3', [path.join(__dirname, 'helpers', 'make-sqlite.py'), dir], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error('fixture generation failed: ' + r.stderr);
    expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
}
const open = (n, wal) => new SqliteDb(new Uint8Array(fs.readFileSync(path.join(dir, n))), wal ? new Uint8Array(fs.readFileSync(path.join(dir, wal))) : null);
const norm = (rows) => rows.map(r => r.map(v => (v instanceof Uint8Array ? 'b:' + Buffer.from(v).toString('hex') : typeof v === 'bigint' ? Number(v) : v)));

test('rejects non-sqlite data', () => {
    assert.throws(() => new SqliteDb(new Uint8Array(200)), /Not a SQLite/);
});

test('column parser handles quoting, constraints and rowid alias', () => {
    const cols = SqliteDb.parseColumns('CREATE TABLE "t x"(id INTEGER PRIMARY KEY AUTOINCREMENT, `n` TEXT NOT NULL DEFAULT (1,2), [w] NUMERIC(10,2), PRIMARY KEY(id), UNIQUE(n))');
    assert.deepEqual(JSON.parse(JSON.stringify(cols.map(c => c.name))), ['id', 'n', 'w']);
    assert.equal(cols[0].rowidAlias, true);
    assert.equal(cols[1].rowidAlias, false);
});

test('basic.db: schema, every serial type, NULLs, ALTER TABLE columns, rowid alias', { skip: !py }, () => {
    const db = open('basic.db');
    const names = db.tables().map(t => t.name).sort();
    assert.deepEqual(JSON.parse(JSON.stringify(names)), ['odd name', 'users']);
    assert.ok(db.schema().some(e => e.type === 'index') && db.schema().some(e => e.type === 'view'));
    assert.deepEqual(JSON.parse(JSON.stringify(db.tables().find(t => t.name === 'users').columns.map(c => c.name))), ['id', 'name', 'age', 'score', 'avatar', 'note', 'extra']);
    const users = norm(db.rows('users').rows);
    assert.deepEqual(JSON.parse(JSON.stringify(users)), expected['basic.db'].users);
    assert.deepEqual(JSON.parse(JSON.stringify(norm(db.rows('odd name').rows))), expected['basic.db']['odd name']);
    assert.equal(db.count('users'), 12);
});

test('rowids.db: negative and >2^53 rowids are exact (9-byte varints)', { skip: !py }, () => {
    const db = open('rowids.db');
    const rows = db.rows('ids').rows.map(r => [String(r[0]), r[1]]).sort((a, b) => (BigInt(a[0]) < BigInt(b[0]) ? -1 : 1));
    assert.deepEqual(JSON.parse(JSON.stringify(rows)), expected['rowids.db']);
});

test('big.db: overflow pages and multi-level b-tree match sqlite exactly', { skip: !py }, () => {
    const db = open('big.db');
    assert.equal(db.pageSize, expected['big.db'].page_size);
    assert.equal(db.count('docs'), expected['big.db'].count);
    const all = db.rows('docs', { limit: 100000 });
    assert.equal(all.rows.length, expected['big.db'].count);
    assert.deepEqual(JSON.parse(JSON.stringify(norm(all.rows.slice(0, 3)))), expected['big.db'].first);
    assert.deepEqual(JSON.parse(JSON.stringify(norm(all.rows.slice(-2)))), expected['big.db'].last);
    assert.equal(all.rows[0][1].length, 20000);                 // TEXT stored across overflow pages
    assert.equal(all.rows[0][2].length, 10240);                 // BLOB across overflow pages
});

test('pagination: limit/offset/hasMore', { skip: !py }, () => {
    const db = open('big.db');
    const a = db.rows('docs', { limit: 10 });
    assert.equal(a.rows.length, 10); assert.equal(a.hasMore, true);
    const b = db.rows('docs', { limit: 10, offset: 5 });
    assert.equal(b.rows[0][0], a.rows[5][0]);
    const end = db.rows('docs', { limit: 10, offset: 5995 });
    assert.equal(end.hasMore, false);
    assert.equal(end.rows.length, 6);
});

test('utf16.db: UTF-16 text decoded', { skip: !py }, () => {
    const db = open('utf16.db');
    assert.equal(db.encoding, 2);
    assert.deepEqual(JSON.parse(JSON.stringify(norm(db.rows('t').rows))), expected['utf16.db'].t);
});

test('WITHOUT ROWID tables are reported, not misread', { skip: !py }, () => {
    const db = open('worowid.db');
    const r = db.rows('kv');
    assert.equal(r.rows.length, 0);
    assert.match(r.note, /WITHOUT ROWID/);
    assert.equal(db.count('kv'), null);
});

test('WAL overlay: rows that only exist in the -wal file are visible', { skip: !py }, () => {
    const without = open('wal-main.db');
    const withWal = open('wal-main.db', 'wal-main.db-wal');
    assert.ok(withWal.walFrames > 0);
    assert.equal(without.rows('t').rows.length < 50, true, 'main file alone is missing rows');
    assert.deepEqual(JSON.parse(JSON.stringify(norm(withWal.rows('t', { limit: 1000 }).rows))), expected['wal.db'].t);
});

test('truncated database gives a clear error', { skip: !py }, () => {
    const buf = new Uint8Array(fs.readFileSync(path.join(dir, 'big.db'))).slice(0, 8192);
    const db = new SqliteDb(buf);
    assert.throws(() => db.rows('docs', { limit: 100000 }), /beyond the end|truncated/);
});

test('formatCell', () => {
    assert.equal(SqliteDb.formatCell(null), 'NULL');
    assert.match(SqliteDb.formatCell(new Uint8Array([1, 255])), /^x'01ff'$/);
    assert.equal(SqliteDb.formatCell('a'.repeat(300)).length, 201);
});

test.after(() => { if (dir) fs.rmSync(dir, { recursive: true, force: true }); });
