'use strict';
// A scriptable fake Android device that speaks the ADB wire protocol over a WebUSB-shaped API.
const CMD = { CNXN: 0x4e584e43, AUTH: 0x48545541, OPEN: 0x4e45504f, OKAY: 0x59414b4f, CLSE: 0x45534c43, WRTE: 0x45545257 };
const sum = b => { let s = 0; for (const x of b) s = (s + x) >>> 0; return s; };
const sid = s => s.charCodeAt(0) | (s.charCodeAt(1) << 8) | (s.charCodeAt(2) << 16) | (s.charCodeAt(3) << 24);
const idStr = n => String.fromCharCode(n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255);

function packet(cmd, a0, a1, payload = new Uint8Array(0)) {
    const buf = new Uint8Array(24 + payload.length);
    const v = new DataView(buf.buffer);
    v.setUint32(0, cmd, true); v.setUint32(4, a0, true); v.setUint32(8, a1, true);
    v.setUint32(12, payload.length, true); v.setUint32(16, sum(payload), true);
    v.setUint32(20, (cmd ^ 0xffffffff) >>> 0, true);
    buf.set(payload, 24);
    return buf;
}

class MockAdbDevice {
    /**
     * opts: { maxdata, outChunk, shell(cmd)->string|Uint8Array|Promise, files:{path:Uint8Array},
     *         dirs:{path:[{name,mode,size,mtime}]}, auth:{verify(token,sig,pubkeys)->bool, onPublicKey(b64)},
     *         banner, serialNumber }
     */
    constructor(opts = {}) {
        this.opts = Object.assign({ maxdata: 4096, outChunk: 0, banner: 'device::ro.product.model=Mock;', serialNumber: 'MOCK123' }, opts);
        this.opened = false;
        this.productName = 'Mock Device';
        this.manufacturerName = 'Mock';
        this.serialNumber = this.opts.serialNumber;
        this.configuration = { configurationValue: 1 };
        this.configurations = [{
            configurationValue: 1,
            interfaces: [{ interfaceNumber: 0, alternates: [{
                interfaceClass: 0xff, interfaceSubclass: 0x42, interfaceProtocol: 1,
                endpoints: [
                    { type: 'bulk', direction: 'in', endpointNumber: 1, packetSize: 512 },
                    { type: 'bulk', direction: 'out', endpointNumber: 2, packetSize: 512 }
                ]
            }] }]
        }];
        this.inbox = [];            // device -> host chunks
        this.waiters = [];          // pending transferIn
        this.hostBuf = [];          // host -> device raw writes
        this.sockets = new Map();   // hostLocalId -> socket
        this.nextRemote = 100;
        this.pushed = {};           // files written via sync SEND
        this.log = [];              // received host packets
        this.maxConcurrent = 0;
        this.failNextWrite = false;
        this.transferInCalls = 0;
    }

    async open() { this.opened = true; }
    async close() { this.opened = false; this._failWaiters(new Error('device closed')); }
    async selectConfiguration() {}
    async claimInterface() {}

    _failWaiters(err) { for (const w of this.waiters.splice(0)) w.reject(err); }
    unplug() { this.opened = false; this._failWaiters(new Error('NetworkError: device unplugged')); this.unplugged = true; }

    async transferOut(ep, data) {
        if (this.unplugged || this.failNextWrite) { this.failNextWrite = false; throw new Error('NetworkError: write failed'); }
        this.hostBuf.push(Uint8Array.from(data));
        this._parseHost();
        return { status: 'ok', bytesWritten: data.length };
    }

    transferIn(ep, len) {
        this.transferInCalls++;
        if (this.unplugged) return Promise.reject(new Error('NetworkError: unplugged'));
        return new Promise((resolve, reject) => {
            this.waiters.push({ len, resolve, reject });
            this._flush();
        });
    }

    _emit(bytes) {
        const step = this.opts.outChunk || bytes.length || 1;
        for (let o = 0; o < bytes.length; o += step) this.inbox.push(bytes.slice(o, o + step));
        this._flush();
    }

    _flush() {
        while (this.waiters.length && this.inbox.length) {
            const w = this.waiters.shift();
            const chunk = this.inbox.shift();
            const take = Math.min(w.len, chunk.length);
            const out = chunk.slice(0, take);
            if (take < chunk.length) this.inbox.unshift(chunk.slice(take));
            // hand back a DataView over a larger buffer with a non-zero offset to exercise byteOffset handling
            const backing = new Uint8Array(out.length + 5);
            backing.set(out, 5);
            w.resolve({ status: 'ok', data: new DataView(backing.buffer, 5, out.length) });
        }
    }

    _send(cmd, a0, a1, payload) { this._emit(packet(cmd, a0, a1, payload)); }

    _parseHost() {
        // hostBuf holds raw writes; header (24) is its own write, payload (optional) a second write
        for (;;) {
            if (!this.hostBuf.length) return;
            const h = this.hostBuf[0];
            if (h.length < 24) return;
            const v = new DataView(h.buffer, h.byteOffset, 24);
            const len = v.getUint32(12, true);
            if (len > 0 && this.hostBuf.length < 2) return;
            this.hostBuf.shift();
            const payload = len > 0 ? this.hostBuf.shift() : new Uint8Array(0);
            this._onPacket({ cmd: v.getUint32(0, true), a0: v.getUint32(4, true), a1: v.getUint32(8, true), payload });
        }
    }

    _onPacket(p) {
        this.log.push(p);
        switch (p.cmd) {
            case CMD.CNXN: return this._onCnxn();
            case CMD.AUTH: return this._onAuth(p);
            case CMD.OPEN: return this._onOpen(p);
            case CMD.WRTE: return this._onWrite(p);
            case CMD.OKAY: return this._onOkay(p);
            case CMD.CLSE: return this._onClose(p);
        }
    }

    _cnxn() { this._send(CMD.CNXN, 0x01000001, this.opts.maxdata, new TextEncoder().encode(this.opts.banner)); }

    _onCnxn() {
        if (!this.opts.auth) return this._cnxn();
        this.token = new Uint8Array(20).map((_, i) => (i * 13 + 7) & 255);
        this._send(CMD.AUTH, 1, 0, this.token);
    }

    _onAuth(p) {
        const a = this.opts.auth;
        if (p.a0 === 2) { // signature
            if (a.verify(this.token, p.payload)) return this._cnxn();
            this.token = this.token.map(x => (x + 1) & 255);
            return this._send(CMD.AUTH, 1, 0, this.token);
        }
        if (p.a0 === 3) { // public key: "user accepts the prompt"
            a.onPublicKey(new TextDecoder().decode(p.payload).replace(/\0.*$/, '').split(' ')[0]);
            return this._cnxn();
        }
    }

    _onOpen(p) {
        const service = new TextDecoder().decode(p.payload).replace(/\0$/, '');
        const remote = this.nextRemote++;
        const sock = { local: p.a0, remote, service, pending: [], awaiting: false, closing: false, syncBuf: new Uint8Array(0), recv: null };
        this.sockets.set(p.a0, sock);
        this.maxConcurrent = Math.max(this.maxConcurrent, this.sockets.size);
        this._send(CMD.OKAY, remote, p.a0);
        if (service.startsWith('shell:')) {
            const cmd = service.slice(6);
            const run = async () => {
                let out;
                try { out = await this.opts.shell(cmd, this); } catch (e) { out = 'error: ' + e.message + '\n'; }
                if (typeof out === 'string') out = new TextEncoder().encode(out);
                this._write(sock, out, true);
            };
            run();
        } else if (service.startsWith('sync:')) {
            sock.sync = true;
        } else {
            this._send(CMD.CLSE, 0, p.a0); this.sockets.delete(p.a0);
        }
    }

    _write(sock, bytes, closeAfter) {
        for (let o = 0; o < bytes.length; o += this.opts.maxdata) sock.pending.push(bytes.slice(o, o + this.opts.maxdata));
        if (closeAfter) sock.closing = true;
        this._pump(sock);
    }

    _pump(sock) {
        if (sock.awaiting) return;
        if (sock.pending.length) {
            sock.awaiting = true;
            this._send(CMD.WRTE, sock.remote, sock.local, sock.pending.shift());
        } else if (sock.closing) {
            this._send(CMD.CLSE, sock.remote, sock.local);
            this.sockets.delete(sock.local);
        }
    }

    _onOkay(p) { const s = this.sockets.get(p.a0); if (s) { s.awaiting = false; this._pump(s); } }
    _onClose(p) { if (this.sockets.delete(p.a0)) this._send(CMD.CLSE, 0, p.a0); }

    _onWrite(p) {
        const s = this.sockets.get(p.a0);
        if (!s) return;
        this._send(CMD.OKAY, s.remote, s.local);
        if (s.sync) this._syncData(s, p.payload);
    }

    _syncData(s, data) {
        const merged = new Uint8Array(s.syncBuf.length + data.length);
        merged.set(s.syncBuf); merged.set(data, s.syncBuf.length);
        s.syncBuf = merged;
        for (;;) {
            const b = s.syncBuf;
            if (s.recv) { if (!this._recvData(s)) return; continue; }
            if (b.length < 8) return;
            const v = new DataView(b.buffer, b.byteOffset);
            const id = idStr(v.getUint32(0, true));
            const n = v.getUint32(4, true);
            if (b.length < 8 + (id === 'DATA' || id === 'DONE' ? 0 : n)) return;
            if (id === 'LIST' || id === 'STAT' || id === 'RECV') {
                const path = new TextDecoder().decode(b.slice(8, 8 + n));
                s.syncBuf = b.slice(8 + n);
                this['_sync' + id](s, path);
            } else if (id === 'SEND') {
                const spec = new TextDecoder().decode(b.slice(8, 8 + n));
                s.syncBuf = b.slice(8 + n);
                s.recv = { path: spec.replace(/,\d+$/, ''), chunks: [] };
            } else { s.syncBuf = new Uint8Array(0); return; }
        }
    }

    _recvData(s) {
        const b = s.syncBuf;
        if (b.length < 8) return false;
        const v = new DataView(b.buffer, b.byteOffset);
        const id = idStr(v.getUint32(0, true));
        const n = v.getUint32(4, true);
        if (id === 'DATA') {
            if (n > this.opts.maxdata - 8) { s.recv = null; this._okayFail(s, 'chunk exceeds maxdata'); return false; }
            if (b.length < 8 + n) return false;
            s.recv.chunks.push(b.slice(8, 8 + n)); s.syncBuf = b.slice(8 + n); return true;
        }
        if (id === 'DONE') {
            s.syncBuf = b.slice(8);
            const total = s.recv.chunks.reduce((a, c) => a + c.length, 0);
            const out = new Uint8Array(total); let o = 0;
            for (const c of s.recv.chunks) { out.set(c, o); o += c.length; }
            this.pushed[s.recv.path] = out; s.recv = null;
            const ok = new Uint8Array(8); new DataView(ok.buffer).setUint32(0, sid('OKAY'), true);
            this._write(s, ok, false); return true;
        }
        return false;
    }

    _okayFail(s, msg) {
        const m = new TextEncoder().encode(msg); const out = new Uint8Array(8 + m.length);
        const v = new DataView(out.buffer); v.setUint32(0, sid('FAIL'), true); v.setUint32(4, m.length, true); out.set(m, 8);
        this._write(s, out, false);
    }

    _syncSTAT(s, path) {
        const f = this.opts.files && this.opts.files[path];
        const out = new Uint8Array(16); const v = new DataView(out.buffer);
        v.setUint32(0, sid('STAT'), true); v.setUint32(4, f ? 0o100644 : 0, true); v.setUint32(8, f ? f.length : 0, true); v.setUint32(12, 1700000000, true);
        this._write(s, out, false);
    }

    _syncRECV(s, path) {
        const f = this.opts.files && this.opts.files[path];
        if (!f) return this._okayFail(s, 'No such file or directory');
        const parts = [];
        for (let o = 0; o < f.length; o += 64 * 1024) {
            const c = f.slice(o, o + 64 * 1024); const h = new Uint8Array(8 + c.length); const v = new DataView(h.buffer);
            v.setUint32(0, sid('DATA'), true); v.setUint32(4, c.length, true); h.set(c, 8); parts.push(h);
        }
        const done = new Uint8Array(8); new DataView(done.buffer).setUint32(0, sid('DONE'), true); parts.push(done);
        const all = new Uint8Array(parts.reduce((a, c) => a + c.length, 0)); let o = 0;
        for (const p of parts) { all.set(p, o); o += p.length; }
        this._write(s, all, false);
    }

    _syncLIST(s, path) {
        const dir = this.opts.dirs && this.opts.dirs[path];
        if (!dir) return this._okayFail(s, 'No such directory');
        const parts = [];
        for (const e of dir) {
            const nb = new TextEncoder().encode(e.name); const b = new Uint8Array(20 + nb.length); const v = new DataView(b.buffer);
            v.setUint32(0, sid('DENT'), true); v.setUint32(4, e.mode, true); v.setUint32(8, e.size, true); v.setUint32(12, e.mtime || 0, true); v.setUint32(16, nb.length, true); b.set(nb, 20); parts.push(b);
        }
        const d = new Uint8Array(20); new DataView(d.buffer).setUint32(0, sid('DONE'), true); parts.push(d);
        const all = new Uint8Array(parts.reduce((a, c) => a + c.length, 0)); let o = 0;
        for (const p of parts) { all.set(p, o); o += p.length; }
        this._write(s, all, false);
    }
}

module.exports = { MockAdbDevice, packet, CMD };
