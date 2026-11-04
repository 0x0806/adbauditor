/**
 * ADB Auditor - minimal read-only SQLite file reader (tables, rows, schema, WAL overlay).
 * Lets you inspect app databases pulled from a device without any server or library.
 *
 * @author Sandeep Wawdane (original creator of ADB Auditor)
 * @contributor 0x0806 (SQLite viewer)
 * @license See LICENSE (CC BY-NC-ND 4.0, (c) Sandeep Wawdane)
 */
(function(global) {
    'use strict';

    const MAGIC = 'SQLite format 3\0';

    class SqliteDb {
        /** @param {Uint8Array} bytes database file  @param {Uint8Array=} wal optional -wal file contents */
        constructor(bytes, wal = null) {
            this.bytes = bytes;
            this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
            if (bytes.length < 100 || new TextDecoder('latin1').decode(bytes.subarray(0, 16)) !== MAGIC) throw new Error('Not a SQLite 3 database');
            const ps = this.view.getUint16(16);
            this.pageSize = ps === 1 ? 65536 : ps;
            this.reserved = bytes[20];
            this.usable = this.pageSize - this.reserved;
            this.isWal = bytes[18] === 2 && bytes[19] === 2;        // file-format version 2 = journal_mode=WAL
            this.encoding = this.view.getUint32(56);                // 1 UTF-8, 2 UTF-16le, 3 UTF-16be
            this.pageCount = Math.floor(bytes.length / this.pageSize);
            this.overlay = new Map();
            this.walFrames = 0;
            if (wal && wal.length >= 32) this._applyWal(wal);
            this._master = null;
        }

        _applyWal(wal) {
            const v = new DataView(wal.buffer, wal.byteOffset, wal.byteLength);
            const magic = v.getUint32(0);
            if (magic !== 0x377f0682 && magic !== 0x377f0683) return;
            const pageSize = v.getUint32(8) === 1 ? 65536 : v.getUint32(8);
            if (pageSize !== this.pageSize) return;
            const salt1 = v.getUint32(16), salt2 = v.getUint32(20);
            let pending = new Map(), committed = 0;
            const frame = 24 + pageSize;
            for (let o = 32; o + frame <= wal.length; o += frame) {
                if (v.getUint32(o + 8) !== salt1 || v.getUint32(o + 12) !== salt2) break;    // stale frames from an earlier WAL generation
                pending.set(v.getUint32(o), wal.subarray(o + 24, o + frame));
                if (v.getUint32(o + 4) !== 0) {                                              // commit frame
                    for (const [pg, data] of pending) this.overlay.set(pg, data);
                    this.pageCount = Math.max(this.pageCount, v.getUint32(o + 4));
                    pending = new Map(); committed++;
                }
            }
            this.walFrames = committed;
        }

        _page(n) {
            if (n < 1) throw new Error('Invalid page number ' + n);
            const ov = this.overlay.get(n);
            if (ov) return ov;
            const start = (n - 1) * this.pageSize;
            if (start + this.pageSize > this.bytes.length) throw new Error('Page ' + n + ' is beyond the end of the file (truncated database?)');
            return this.bytes.subarray(start, start + this.pageSize);
        }

        /**
         * Decode an SQLite varint. Returns a Number when the value is a safe integer, otherwise a BigInt (signed 64-bit,
         * exactly as stored - negative rowids use the 9-byte form). Callers that expect sizes reject non-Numbers.
         */
        static _varint(buf, p) {
            if (p < 0 || p >= buf.length) throw new Error('Corrupt database: read past the end of a page');
            const safe = (big) => (big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big);
            let v = 0;
            for (let i = 0; i < 8; i++) {
                if (p + i >= buf.length) throw new Error('Corrupt database: truncated varint');
                const b = buf[p + i];
                if (i < 7) {                                   // up to 49 bits: exact in a Number
                    v = v * 128 + (b & 0x7f);
                    if (!(b & 0x80)) return [v, p + i + 1];
                } else {                                       // 8th byte: switch to BigInt
                    const big = BigInt(v) * 128n + BigInt(b & 0x7f);
                    if (!(b & 0x80)) return [safe(big), p + 8];
                    if (p + 8 >= buf.length) throw new Error('Corrupt database: truncated varint');
                    return [safe(BigInt.asIntN(64, (big << 8n) | BigInt(buf[p + 8]))), p + 9];   // 9-byte form: last byte contributes 8 bits
                }
            }
        }

        static _corrupt(what) { return new Error('Corrupt database: ' + what); }

        _decodeText(b) {
            if (this.encoding === 2) return new TextDecoder('utf-16le').decode(b);
            if (this.encoding === 3) return new TextDecoder('utf-16be').decode(b);
            return new TextDecoder('utf-8').decode(b);
        }

        _readRecord(page, pos, payloadSize) {
            if (typeof payloadSize !== 'number' || !(payloadSize >= 0) || payloadSize > 0x7fffffff || payloadSize > this.bytes.length + this.overlay.size * this.pageSize) throw SqliteDb._corrupt('implausible record size');
            if (pos < 0 || pos > page.length) throw SqliteDb._corrupt('cell offset outside page');
            // local payload size rules (table b-tree leaf)
            const U = this.usable, X = U - 35;
            let local = payloadSize;
            if (payloadSize > X) {
                const M = Math.floor(((U - 12) * 32) / 255) - 23;
                const K = M + ((payloadSize - M) % (U - 4));
                local = K <= X ? K : M;
            }
            let payload = page.subarray(pos, pos + local);
            if (payload.length < local) throw SqliteDb._corrupt('record runs past the end of its page');
            if (local < payloadSize) {
                const parts = [payload];
                if (pos + local + 4 > page.length) throw SqliteDb._corrupt('overflow pointer outside page');
                let next = new DataView(page.buffer, page.byteOffset, page.byteLength).getUint32(pos + local), remaining = payloadSize - local, guard = 0;
                const maxPages = this.pageCount + this.overlay.size + 1;
                while (next && remaining > 0) {
                    if (guard++ > maxPages) throw SqliteDb._corrupt('overflow chain loops');
                    const ov = this._page(next);
                    next = new DataView(ov.buffer, ov.byteOffset, ov.byteLength).getUint32(0);
                    const take = Math.min(remaining, U - 4);
                    parts.push(ov.subarray(4, 4 + take)); remaining -= take;
                }
                const all = new Uint8Array(payloadSize); let o = 0;
                for (const p of parts) { all.set(p, o); o += p.length; }
                payload = all;
            }
            return this._decodeRecord(payload);
        }

        _decodeRecord(buf) {
            const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
            let [hdrLen, p] = SqliteDb._varint(buf, 0);
            if (typeof hdrLen !== 'number' || hdrLen > buf.length || hdrLen < p) throw SqliteDb._corrupt('bad record header length');
            const types = [];
            while (p < hdrLen) {
                const [t, np] = SqliteDb._varint(buf, p);
                if (typeof t !== 'number' || t < 0) throw SqliteDb._corrupt('bad serial type');
                types.push(t); p = np;
            }
            const out = [];
            let q = hdrLen;
            const need = (n) => { if (q + n > buf.length) throw SqliteDb._corrupt('record value runs past its payload'); };
            for (const t of types) {
                if (t === 0) out.push(null);
                else if (t === 8) out.push(0);
                else if (t === 9) out.push(1);
                else if (t >= 1 && t <= 6) {
                    const n = [0, 1, 2, 3, 4, 6, 8][t];
                    need(n);
                    let val = 0n;
                    for (let i = 0; i < n; i++) val = (val << 8n) | BigInt(buf[q + i]);
                    if (buf[q] & 0x80) val -= 1n << BigInt(n * 8);                              // two's complement
                    out.push(val >= BigInt(Number.MIN_SAFE_INTEGER) && val <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(val) : val);
                    q += n; continue;
                } else if (t === 7) { need(8); out.push(dv.getFloat64(q)); q += 8; continue; }
                else if (t >= 12) {
                    const len = t % 2 === 0 ? (t - 12) / 2 : (t - 13) / 2;
                    need(len);
                    const slice = buf.subarray(q, q + len);
                    out.push(t % 2 === 0 ? slice.slice() : this._decodeText(slice));
                    q += len; continue;
                } else out.push(null);
            }
            return out;
        }

        /** Iterate all (rowid, record) pairs of a table b-tree. */
        *_walkTable(rootPage, depth = 0, seen = new Set()) {
            if (depth > 40) throw SqliteDb._corrupt('b-tree too deep');
            if (seen.has(rootPage)) throw SqliteDb._corrupt('b-tree page referenced twice (cycle)');
            seen.add(rootPage);
            const page = this._page(rootPage);
            const base = rootPage === 1 ? 100 : 0;
            const dv = new DataView(page.buffer, page.byteOffset, page.byteLength);
            const type = page[base], cells = dv.getUint16(base + 3);
            if (base + (type === 0x05 ? 12 : 8) + cells * 2 > page.length) throw SqliteDb._corrupt('cell pointer array outside page');
            if (type === 0x0d) {
                for (let i = 0; i < cells; i++) {
                    const ptr = dv.getUint16(base + 8 + i * 2);
                    const [payload, p1] = SqliteDb._varint(page, ptr);
                    const [rowid, p2] = SqliteDb._varint(page, p1);
                    yield [rowid, this._readRecord(page, p2, payload)];
                }
            } else if (type === 0x05) {
                for (let i = 0; i < cells; i++) yield* this._walkTable(dv.getUint32(dv.getUint16(base + 12 + i * 2)), depth + 1, seen);
                yield* this._walkTable(dv.getUint32(base + 8), depth + 1, seen);
            } else throw SqliteDb._corrupt(`unexpected b-tree page type 0x${type.toString(16)} on page ${rootPage}`);
        }

        /** Run fn, converting low-level range/type errors caused by corruption into a clear message. */
        static _guard(fn) {
            try { return fn(); } catch (e) {
                if (e && e.name === 'RangeError') throw SqliteDb._corrupt(e.message);
                throw e;
            }
        }

        /** sqlite_master entries: { type, name, tbl, rootpage, sql } */
        schema() {
            if (!this._master) {
                const m = [];
                SqliteDb._guard(() => { for (const [, r] of this._walkTable(1)) m.push({ type: r[0], name: r[1], tbl: r[2], rootpage: r[3], sql: r[4] }); });
                this._master = m;
            }
            return this._master;
        }

        static parseColumns(sql) {
            if (!sql) return [];
            const open = sql.indexOf('('), close = sql.lastIndexOf(')');
            if (open < 0 || close < open) return [];
            const body = sql.slice(open + 1, close);
            const parts = []; let depth = 0, cur = '', quote = null;
            for (const ch of body) {
                if (quote) { cur += ch; if (ch === quote) quote = null; continue; }
                if (ch === '"' || ch === "'" || ch === '`') { quote = ch; cur += ch; continue; }
                if (ch === '[') { quote = ']'; cur += ch; continue; }
                if (ch === '(') depth++; if (ch === ')') depth--;
                if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch;
            }
            if (cur.trim()) parts.push(cur);
            const cols = [];
            for (const raw of parts) {
                const t = raw.trim();
                if (/^(PRIMARY|UNIQUE|FOREIGN|CHECK|CONSTRAINT)\b/i.test(t)) continue;
                const m = /^(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|'([^']+)'|(\S+))\s*(.*)$/s.exec(t);
                if (!m) continue;
                const name = m[1] || m[2] || m[3] || m[4] || m[5];
                cols.push({ name, type: (m[6] || '').split(/\s+(?:PRIMARY|NOT|NULL|DEFAULT|UNIQUE|CHECK|REFERENCES|COLLATE|GENERATED|AS)\b/i)[0].trim(), rowidAlias: /\bINTEGER\s+PRIMARY\s+KEY\b/i.test(t) && !/DESC/i.test(t) });
            }
            return cols;
        }

        tables() {
            return this.schema().filter(e => e.type === 'table').map(e => {
                const virtual = e.rootpage === 0 || /^\s*CREATE\s+VIRTUAL/i.test(e.sql || '');
                return { name: e.name, sql: e.sql, rootpage: e.rootpage, columns: SqliteDb.parseColumns(e.sql), virtual, withoutRowid: /WITHOUT\s+ROWID/i.test(e.sql || '') };
            });
        }

        /** Read rows. Returns { columns, rows, hasMore, note }. */
        rows(tableName, { limit = 500, offset = 0 } = {}) {
            const t = this.tables().find(x => x.name === tableName);
            if (!t) throw new Error('No such table: ' + tableName);
            const cols = t.columns.map(c => c.name);
            if (t.virtual) return { columns: cols, rows: [], hasMore: false, note: 'Virtual table - contents are not stored in the file' };
            if (t.withoutRowid) return { columns: cols, rows: [], hasMore: false, note: 'WITHOUT ROWID tables are not supported by this viewer' };
            const out = []; let i = 0, hasMore = false;
            SqliteDb._guard(() => {
                for (const [rowid, rec] of this._walkTable(t.rootpage)) {
                    if (i++ < offset) continue;
                    if (out.length >= limit) { hasMore = true; break; }
                    const row = rec.slice();
                    t.columns.forEach((c, k) => { if (c.rowidAlias && row[k] === null) row[k] = rowid; });
                    while (row.length < cols.length) row.push(null);              // columns added later with ALTER TABLE
                    out.push(row);
                }
            });
            return { columns: cols, rows: out, hasMore };
        }

        count(tableName) {
            const t = this.tables().find(x => x.name === tableName);
            if (!t || t.virtual || t.withoutRowid) return null;
            let n = 0;
            SqliteDb._guard(() => { for (const _ of this._walkTable(t.rootpage)) n++; });
            return n;
        }
    }

    /** Format a cell for display (BLOBs as hex preview, bigints as strings). */
    function formatCell(v, max = 200) {
        if (v === null) return 'NULL';
        if (v instanceof Uint8Array) return 'x\'' + Array.from(v.subarray(0, 32), b => b.toString(16).padStart(2, '0')).join('') + (v.length > 32 ? `…' (${v.length} bytes)` : '\'');
        const s = String(v);
        return s.length > max ? s.slice(0, max) + '…' : s;
    }

    global.SqliteDb = SqliteDb;
    global.SqliteDb.formatCell = formatCell;
})(typeof window !== 'undefined' ? window : globalThis);
