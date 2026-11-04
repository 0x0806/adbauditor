/**
 * ADB protocol core (WebUSB).
 * @preserve
 * @author Sandeep Wawdane (original creator of ADB Auditor)
 * @contributor 0x0806 (concurrency-safe transport, auth signing, sync fixes)
 * @license See LICENSE (CC BY-NC-ND 4.0, (c) Sandeep Wawdane)
 */
(function(global) {
    'use strict';

    const DEBUG = false;
    const BUILD_ID = 'U2FuZGVlcFc=';
    function log(...args) { if (DEBUG) console.log('[ADB]', ...args); }
    function logError(...args) { console.error('[ADB ERROR]', ...args); }

    const ADB = {
        VERSION: 0x01000001,
        MAX_PAYLOAD: 256 * 1024,
        CMD_CNXN: 0x4e584e43,
        CMD_AUTH: 0x48545541,
        CMD_OPEN: 0x4e45504f,
        CMD_OKAY: 0x59414b4f,
        CMD_CLSE: 0x45534c43,
        CMD_WRTE: 0x45545257,
        AUTH_TOKEN: 1,
        AUTH_SIGNATURE: 2,
        AUTH_RSAPUBLICKEY: 3,
    };

    function cmdName(cmd) {
        const names = {
            [ADB.CMD_CNXN]: 'CNXN',
            [ADB.CMD_AUTH]: 'AUTH',
            [ADB.CMD_OPEN]: 'OPEN',
            [ADB.CMD_OKAY]: 'OKAY',
            [ADB.CMD_CLSE]: 'CLSE',
            [ADB.CMD_WRTE]: 'WRTE'
        };
        return names[cmd] || `0x${cmd.toString(16)}`;
    }

    const ErrorType = {
        CONNECTION_LOST: 'CONNECTION_LOST',
        DEVICE_BUSY: 'DEVICE_BUSY',
        PERMISSION_DENIED: 'PERMISSION_DENIED',
        TIMEOUT: 'TIMEOUT',
        PROTOCOL_ERROR: 'PROTOCOL_ERROR',
        NOT_FOUND: 'NOT_FOUND',
        UNKNOWN: 'UNKNOWN'
    };

    class ADBError extends Error {
        constructor(message, type = ErrorType.UNKNOWN, recoverable = false) {
            super(message);
            this.name = 'ADBError';
            this.type = type;
            this.recoverable = recoverable;
        }

        getUserMessage() {
            switch (this.type) {
                case ErrorType.CONNECTION_LOST:
                    return 'Connection lost. Your device may have gone to sleep, been unplugged, or you switched tabs. Please click "Reconnect" to continue.';
                case ErrorType.DEVICE_BUSY:
                    return 'Device is busy. Close any other ADB connections (like Android Studio or Chrome DevTools) and try again.';
                case ErrorType.PERMISSION_DENIED:
                    return 'Access denied. Check if USB debugging is still enabled and authorized on your device.';
                case ErrorType.TIMEOUT:
                    return 'Operation timed out. Your device may be slow to respond. Try again.';
                case ErrorType.PROTOCOL_ERROR:
                    return 'Communication error. Please disconnect and reconnect your device.';
                case ErrorType.NOT_FOUND:
                    return this.message;
                default:
                    return this.message;
            }
        }
    }

    const USB_FILTER = { classCode: 0xFF, subclassCode: 0x42, protocolCode: 0x01 };
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    function checksum(data) {
        let sum = 0;
        for (let i = 0; i < data.length; i++) sum = (sum + data[i]) >>> 0;
        return sum;
    }

    function makePacket(cmd, arg0, arg1, payload = new Uint8Array(0)) {
        const header = new Uint8Array(24);
        const v = new DataView(header.buffer);
        v.setUint32(0, cmd, true);
        v.setUint32(4, arg0, true);
        v.setUint32(8, arg1, true);
        v.setUint32(12, payload.length, true);
        v.setUint32(16, checksum(payload), true);
        v.setUint32(20, (cmd ^ 0xFFFFFFFF) >>> 0, true);
        return { header, payload };
    }

    function parseHeader(data) {
        const v = new DataView(data.buffer, data.byteOffset, 24);
        return {
            cmd: v.getUint32(0, true),
            arg0: v.getUint32(4, true),
            arg1: v.getUint32(8, true),
            len: v.getUint32(12, true),
            check: v.getUint32(16, true),
            magic: v.getUint32(20, true)
        };
    }

    function syncId(s) {
        return s.charCodeAt(0) | (s.charCodeAt(1) << 8) | (s.charCodeAt(2) << 16) | (s.charCodeAt(3) << 24);
    }

    function syncIdStr(id) {
        return String.fromCharCode(id & 0xFF, (id >> 8) & 0xFF, (id >> 16) & 0xFF, (id >> 24) & 0xFF);
    }

    class CredentialStore {
        constructor() {
            this.dbName = 'ADBauditorDB';
            this.storeName = 'keys';
        }

        async open() {
            return new Promise((resolve, reject) => {
                const req = indexedDB.open(this.dbName, 1);
                req.onerror = () => reject(req.error);
                req.onupgradeneeded = () => req.result.createObjectStore(this.storeName, { autoIncrement: true });
                req.onsuccess = () => resolve(req.result);
            });
        }

        async generateKey() {
            log('Generating new RSA key pair');
            const keyPair = await crypto.subtle.generateKey(
                { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
                true, ['sign']
            );
            const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
            const keyBuffer = new Uint8Array(pkcs8);
            
            const db = await this.open();
            await new Promise((resolve, reject) => {
                const tx = db.transaction(this.storeName, 'readwrite');
                tx.objectStore(this.storeName).add(keyBuffer);
                tx.oncomplete = () => { db.close(); resolve(); };
                tx.onerror = () => reject(tx.error);
            });
            log('New key saved to IndexedDB');
            return { buffer: keyBuffer, privateKey: keyPair.privateKey };
        }

        async getKeys() {
            const db = await this.open();
            return new Promise((resolve, reject) => {
                const tx = db.transaction(this.storeName, 'readonly');
                const req = tx.objectStore(this.storeName).getAll();
                req.onsuccess = () => {
                    log(`Found ${req.result?.length || 0} stored keys`);
                    resolve(req.result || []);
                };
                tx.oncomplete = () => db.close();
                tx.onerror = () => reject(tx.error);
            });
        }

        async importKey(buf) {
            return crypto.subtle.importKey('pkcs8', buf, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' }, false, ['sign']);
        }
    }

    /* ---------- Minimal DER / RSA helpers (for ADB token signing) ---------- */

    function derRead(buf, pos) {
        const tag = buf[pos];
        let len = buf[pos + 1];
        let p = pos + 2;
        if (len & 0x80) {
            const n = len & 0x7f;
            len = 0;
            for (let i = 0; i < n; i++) len = (len * 256) + buf[p++];
        }
        return { tag, start: p, end: p + len };
    }

    function bytesToBigInt(bytes) {
        let hex = '';
        for (const b of bytes) hex += b.toString(16).padStart(2, '0');
        return BigInt('0x' + (hex || '0'));
    }

    function bigIntToBytes(value, length) {
        let hex = value.toString(16);
        if (hex.length % 2) hex = '0' + hex;
        const out = new Uint8Array(length);
        const raw = hex.match(/../g) || [];
        const off = length - raw.length;
        if (off < 0) throw new Error('Integer too large');
        raw.forEach((h, i) => { out[off + i] = parseInt(h, 16); });
        return out;
    }

    function modPow(base, exp, mod) {
        let result = 1n;
        base %= mod;
        while (exp > 0n) {
            if (exp & 1n) result = (result * base) % mod;
            exp >>= 1n;
            base = (base * base) % mod;
        }
        return result;
    }

    /** Extract n, e, d from a PKCS#8 wrapped RSAPrivateKey. */
    function parsePkcs8Rsa(pkcs8) {
        const buf = pkcs8 instanceof Uint8Array ? pkcs8 : new Uint8Array(pkcs8);
        const outer = derRead(buf, 0);                       // PrivateKeyInfo SEQUENCE
        let p = outer.start;
        const version = derRead(buf, p); p = version.end;    // INTEGER
        const alg = derRead(buf, p); p = alg.end;            // AlgorithmIdentifier
        const octet = derRead(buf, p);                       // OCTET STRING
        const rsa = derRead(buf, octet.start);               // RSAPrivateKey SEQUENCE
        p = rsa.start;
        const ints = [];
        for (let i = 0; i < 4; i++) {                        // version, n, e, d
            const item = derRead(buf, p);
            ints.push(buf.slice(item.start, item.end));
            p = item.end;
        }
        const strip = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; return b.slice(i); };
        return { n: bytesToBigInt(strip(ints[1])), e: bytesToBigInt(strip(ints[2])), d: bytesToBigInt(strip(ints[3])) };
    }

    const SHA1_DIGEST_INFO = new Uint8Array([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]);

    /** EMSA-PKCS1-v1_5 block where `digest` (20 bytes) is used as-is (ADB signs the token without re-hashing). */
    function pkcs1Sha1Block(digest, k = 256) {
        const em = new Uint8Array(k);
        em[1] = 0x01;
        const tLen = SHA1_DIGEST_INFO.length + digest.length;
        em.fill(0xff, 2, k - tLen - 1);
        em[k - tLen - 1] = 0x00;
        em.set(SHA1_DIGEST_INFO, k - tLen);
        em.set(digest, k - digest.length);
        return em;
    }

    /** Sign the 20-byte AUTH token exactly like `adb` does (RSA_sign with NID_sha1 over the raw token). */
    function signAdbToken(pkcs8, token) {
        const { n, d } = parsePkcs8Rsa(pkcs8);
        const em = bytesToBigInt(pkcs1Sha1Block(token, 256));
        return bigIntToBytes(modPow(em, d, n), 256);
    }

    /** Build the base64 public key blob in Android's RSAPublicKey layout. */
    function generatePublicKey(privKeyBuf) {
        const { n, e } = parsePkcs8Rsa(privKeyBuf);
        const words = 64;
        const R = 1n << 2048n;
        const n0 = n & 0xffffffffn;
        // n0inv = -n^-1 mod 2^32
        let inv = 1n;
        for (let i = 0; i < 5; i++) inv = (inv * (2n - n0 * inv)) & 0xffffffffn;
        const n0inv = (0x100000000n - inv) & 0xffffffffn;
        const rr = (R * R) % n;
        const out = new Uint8Array(4 + 4 + 256 + 256 + 4);
        const v = new DataView(out.buffer);
        v.setUint32(0, words, true);
        v.setUint32(4, Number(n0inv), true);
        const littleEndian = (value) => bigIntToBytes(value, 256).reverse();
        out.set(littleEndian(n), 8);
        out.set(littleEndian(rr), 8 + 256);
        v.setUint32(8 + 512, Number(e), true);
        let bin = '';
        for (let i = 0; i < out.length; i++) bin += String.fromCharCode(out[i]);
        return btoa(bin);
    }

    class USBWatcher {
        constructor(callback) {
            this.callback = callback;
            this.disposed = false;
            
            if (navigator.usb) {
                navigator.usb.addEventListener('connect', this.handleConnect);
                navigator.usb.addEventListener('disconnect', this.handleDisconnect);
                log('USB Watcher initialized');
            }
        }

        handleConnect = (event) => {
            if (this.disposed) return;
            log('USB device connected:', event.device.serialNumber);
            this.callback('connect', event.device);
        }

        handleDisconnect = (event) => {
            if (this.disposed) return;
            log('USB device disconnected:', event.device.serialNumber);
            this.callback('disconnect', event.device);
        }

        dispose() {
            this.disposed = true;
            if (navigator.usb) {
                navigator.usb.removeEventListener('connect', this.handleConnect);
                navigator.usb.removeEventListener('disconnect', this.handleDisconnect);
            }
            log('USB Watcher disposed');
        }
    }


    class DeviceDescriptor {
        constructor(type, serial, name) {
            this.type = type;
            this.serial = serial;
            this.name = name || serial;
            this.lastConnected = null;
        }

        get displayName() {
            return this.name ? `${this.serial} (${this.name})` : this.serial;
        }

        toJSON() {
            return {
                type: this.type,
                serial: this.serial,
                name: this.name,
                lastConnected: this.lastConnected
            };
        }
    }

    class USBDeviceDescriptor extends DeviceDescriptor {
        constructor(usbDevice) {
            super('usb', usbDevice.serialNumber, usbDevice.productName);
            this.usbDevice = usbDevice;
        }

        get displayName() {
            const name = this.usbDevice.productName || 'USB Device';
            return `${this.serial} (${name})`;
        }
    }

    class WebSocketDeviceDescriptor extends DeviceDescriptor {
        constructor(address, name) {
            super('websocket', address, name || 'WebSocket');
            this.address = address;
        }
    }

    class TCPDeviceDescriptor extends DeviceDescriptor {
        constructor(host, port, name) {
            super('tcp', `${host}:${port}`, name || 'TCP/ADB');
            this.host = host;
            this.port = port;
        }
    }

    class DeviceManager {
        constructor() {
            this.devices = new Map();
            this.activeConnection = null;
            this.activeDevice = null;
            this.watcher = null;
            this.listeners = new Set();
            
            this.loadSavedDevices();
        }

        static isWebUSBSupported() {
            return !!navigator.usb;
        }

        static isTCPSupported() {
            return typeof navigator.openTCPSocket === 'function';
        }

        addEventListener(callback) {
            this.listeners.add(callback);
            return () => this.listeners.delete(callback);
        }

        emit(event, data) {
            for (const listener of this.listeners) {
                try {
                    listener(event, data);
                } catch (e) {
                    logError('Event listener error:', e);
                }
            }
        }

        startWatching() {
            if (this.watcher) return;
            
            this.watcher = new USBWatcher((event, usbDevice) => {
                if (event === 'connect') {
                    const descriptor = new USBDeviceDescriptor(usbDevice);
                    this.devices.set(descriptor.serial, descriptor);
                    this.emit('deviceAdded', descriptor);
                    this.emit('devicesChanged', this.getDeviceList());
                } else if (event === 'disconnect') {
                    const serial = usbDevice.serialNumber;
                    if (this.activeDevice?.serial === serial) {
                        this.emit('activeDeviceDisconnected', this.activeDevice);
                        this.activeDevice = null;
                        this.activeConnection = null;
                    }
                    this.emit('deviceRemoved', { serial });
                    this.emit('devicesChanged', this.getDeviceList());
                }
            });
        }

        stopWatching() {
            if (this.watcher) {
                this.watcher.dispose();
                this.watcher = null;
            }
        }

        async refreshUSBDevices() {
            if (!navigator.usb) return [];
            
            try {
                const usbDevices = await navigator.usb.getDevices();
                log(`Found ${usbDevices.length} paired USB devices`);
                
                for (const [serial, descriptor] of this.devices) {
                    if (descriptor.type === 'usb') {
                        const stillPresent = usbDevices.some(d => 
                            d.serialNumber === serial || 
                            (!d.serialNumber && !serial)
                        );
                        if (!stillPresent) {
                            this.devices.delete(serial);
                            log('Removed disconnected USB device:', serial);
                        }
                    }
                }
                
                const descriptors = [];
                for (const usbDevice of usbDevices) {
                    const serial = usbDevice.serialNumber || 
                        `usb-${usbDevice.vendorId}-${usbDevice.productId}`;
                    
                    const descriptor = new USBDeviceDescriptor(usbDevice);
                    descriptor.serial = serial;
                    this.devices.set(serial, descriptor);
                    descriptors.push(descriptor);
                    log('Updated USB device:', serial, '- Product:', usbDevice.productName);
                }
                
                this.emit('devicesChanged', this.getDeviceList());
                
                return descriptors;
            } catch (e) {
                logError('Failed to get USB devices:', e);
                return [];
            }
        }

        async requestUSBDevice() {
            if (!navigator.usb) {
                throw new ADBError('WebUSB not supported', ErrorType.UNKNOWN);
            }

            try {
                const usbDevice = await navigator.usb.requestDevice({
                    filters: [USB_FILTER]
                });
                
                const descriptor = new USBDeviceDescriptor(usbDevice);
                this.devices.set(descriptor.serial, descriptor);
                this.emit('deviceAdded', descriptor);
                this.emit('devicesChanged', this.getDeviceList());
                
                log('New USB device paired:', descriptor.serial);
                return descriptor;
            } catch (e) {
                if (e.name === 'NotFoundError') {
                    throw new ADBError('No device selected', ErrorType.NOT_FOUND);
                }
                throw new ADBError('USB access failed: ' + e.message, ErrorType.PERMISSION_DENIED);
            }
        }

        addWebSocketDevice(address, name) {
            const descriptor = new WebSocketDeviceDescriptor(address, name);
            this.devices.set(descriptor.serial, descriptor);
            this.saveDevices();
            this.emit('deviceAdded', descriptor);
            this.emit('devicesChanged', this.getDeviceList());
            return descriptor;
        }

        addTCPDevice(host, port, name) {
            const descriptor = new TCPDeviceDescriptor(host, port, name);
            this.devices.set(descriptor.serial, descriptor);
            this.saveDevices();
            this.emit('deviceAdded', descriptor);
            this.emit('devicesChanged', this.getDeviceList());
            return descriptor;
        }

        removeDevice(serial) {
            const device = this.devices.get(serial);
            if (device) {
                this.devices.delete(serial);
                if (device.type !== 'usb') {
                    this.saveDevices();
                }
                this.emit('deviceRemoved', device);
                this.emit('devicesChanged', this.getDeviceList());
            }
        }

        getDevice(serial) {
            return this.devices.get(serial);
        }

        getDeviceList() {
            return Array.from(this.devices.values());
        }

        getDevicesByType() {
            const usb = [];
            const websocket = [];
            const tcp = [];
            
            for (const device of this.devices.values()) {
                switch (device.type) {
                    case 'usb': usb.push(device); break;
                    case 'websocket': websocket.push(device); break;
                    case 'tcp': tcp.push(device); break;
                }
            }
            
            return { usb, websocket, tcp };
        }

        saveDevices() {
            const toSave = {
                websocket: [],
                tcp: []
            };
            
            for (const device of this.devices.values()) {
                if (device.type === 'websocket') {
                    toSave.websocket.push({
                        address: device.address,
                        name: device.name
                    });
                } else if (device.type === 'tcp') {
                    toSave.tcp.push({
                        host: device.host,
                        port: device.port,
                        name: device.name
                    });
                }
            }
            
            localStorage.setItem('adb-devices', JSON.stringify(toSave));
            log('Saved devices to localStorage');
        }

        loadSavedDevices() {
            try {
                const saved = localStorage.getItem('adb-devices');
                if (!saved) return;
                
                const data = JSON.parse(saved);
                
                if (data.websocket) {
                    for (const ws of data.websocket) {
                        const descriptor = new WebSocketDeviceDescriptor(ws.address, ws.name);
                        this.devices.set(descriptor.serial, descriptor);
                    }
                }
                
                if (data.tcp) {
                    for (const tcp of data.tcp) {
                        const descriptor = new TCPDeviceDescriptor(tcp.host, tcp.port, tcp.name);
                        this.devices.set(descriptor.serial, descriptor);
                    }
                }
                
                log('Loaded saved devices from localStorage');
            } catch (e) {
                logError('Failed to load saved devices:', e);
            }
        }

        async initialize() {
            this.startWatching();
            
            await this.refreshUSBDevices();
            
            this.emit('devicesChanged', this.getDeviceList());
            
            log('Device Manager initialized');
        }

        dispose() {
            this.stopWatching();
            this.devices.clear();
            this.listeners.clear();
        }
    }

    const READ_SIZE = 64 * 1024;
    const SYNC_MAX_CHUNK = 64 * 1024;

    /** Serialise async work on a named promise chain (a tiny mutex). */
    function withLock(owner, key, fn) {
        const prev = owner[key];
        let release;
        owner[key] = new Promise(r => { release = r; });
        return prev.then(fn).finally(release);
    }

    class ADBConnection {
        constructor() {
            this.device = null;
            this.deviceDescriptor = null;
            this.inEndpoint = null;
            this.outEndpoint = null;
            this.connected = false;
            this.localId = 1;
            this.credentials = new CredentialStore();
            this.maxPayload = ADB.MAX_PAYLOAD;
            this.banner = '';

            this._rxChunks = [];
            this._rxLen = 0;
            this._inflight = null;
            this._readLock = Promise.resolve();
            this._writeLock = Promise.resolve();
            this.pendingPackets = new Map();

            this.lastActivity = Date.now();
            this.connectionLost = false;
            this.stats = { bytesIn: 0, bytesOut: 0, commands: 0 };

            this.onDisconnect = null;
            this.onError = null;

            this._disconnectedResolve = null;
            this._disconnectedReject = null;
            this.disconnected = new Promise((resolve, reject) => {
                this._disconnectedResolve = resolve;
                this._disconnectedReject = reject;
            });
        }

        async connectToDevice(descriptor) {
            if (descriptor.type !== 'usb') {
                throw new ADBError('Only USB devices are currently supported', ErrorType.UNKNOWN);
            }

            this.deviceDescriptor = descriptor;
            this.device = descriptor.usbDevice;

            await this.openDevice();
            await this.authenticate();

            descriptor.lastConnected = new Date();

            return true;
        }

        async requestDevice() {
            if (!navigator.usb) {
                throw new ADBError('WebUSB not supported. Use Chrome, Edge, or Opera browser.', ErrorType.UNKNOWN);
            }
            try {
                this.device = await navigator.usb.requestDevice({ filters: [USB_FILTER] });
                log('Device selected:', this.device.productName);
                return this.device;
            } catch (e) {
                if (e.name === 'NotFoundError') {
                    throw new ADBError('No device selected. Click Connect and select your Android device.', ErrorType.NOT_FOUND);
                }
                throw new ADBError('USB access failed: ' + e.message, ErrorType.PERMISSION_DENIED);
            }
        }

        findInterface() {
            for (const cfg of this.device.configurations) {
                for (const iface of cfg.interfaces) {
                    for (const alt of iface.alternates) {
                        if (alt.interfaceClass === USB_FILTER.classCode &&
                            alt.interfaceSubclass === USB_FILTER.subclassCode &&
                            alt.interfaceProtocol === USB_FILTER.protocolCode) {
                            let inEp = null, outEp = null;
                            for (const ep of alt.endpoints) {
                                if (ep.type === 'bulk') {
                                    if (ep.direction === 'in') inEp = ep;
                                    else outEp = ep;
                                }
                            }
                            if (inEp && outEp) return { cfg, iface, alt, inEp, outEp };
                        }
                    }
                }
            }
            return null;
        }

        async openDevice() {
            try {
                await this.device.open();
                const info = this.findInterface();
                if (!info) {
                    await this.device.close();
                    throw new ADBError('No ADB interface found. Enable USB debugging on your device.', ErrorType.NOT_FOUND);
                }

                if (this.device.configuration?.configurationValue !== info.cfg.configurationValue) {
                    await this.device.selectConfiguration(info.cfg.configurationValue);
                }
                await this.device.claimInterface(info.iface.interfaceNumber);
                this.inEndpoint = info.inEp;
                this.outEndpoint = info.outEp;
                log('USB interface claimed successfully');
            } catch (e) {
                if (e instanceof ADBError) throw e;
                if (e.message?.includes('claimed')) {
                    throw new ADBError('Device already in use. Close Chrome DevTools, Android Studio, or other ADB connections.', ErrorType.DEVICE_BUSY);
                }
                throw new ADBError('Failed to open device: ' + e.message, ErrorType.UNKNOWN);
            }
        }

        /* ----- transport: serialised writes, serialised packet reads ----- */

        async send(pkt) {
            if (this.connectionLost) {
                throw new ADBError('Connection lost', ErrorType.CONNECTION_LOST, true);
            }
            // header + payload must go out back-to-back; concurrent senders are queued
            return withLock(this, '_writeLock', async () => {
                if (this.connectionLost) {
                    throw new ADBError('Connection lost', ErrorType.CONNECTION_LOST, true);
                }
                try {
                    await this.device.transferOut(this.outEndpoint.endpointNumber, pkt.header);
                    if (pkt.payload.length > 0) {
                        await this.device.transferOut(this.outEndpoint.endpointNumber, pkt.payload);
                    }
                    this.stats.bytesOut += pkt.header.length + pkt.payload.length;
                    this.lastActivity = Date.now();
                } catch (e) {
                    logError('Send failed:', e);
                    this.markDisconnected('USB write failed: ' + e.message);
                    throw new ADBError('Connection lost during send', ErrorType.CONNECTION_LOST, true);
                }
            });
        }

        markDisconnected(reason = 'Connection lost') {
            if (!this.connectionLost) {
                log('Marking connection as lost:', reason);
                this.connectionLost = true;
                this.connected = false;

                if (this._disconnectedResolve) {
                    this._disconnectedResolve(reason);
                }

                if (this.onDisconnect) {
                    this.onDisconnect(reason);
                }
            }
        }

        _resetBuffer() {
            this._rxChunks = [];
            this._rxLen = 0;
        }

        /** Start (or reuse) the single in-flight USB read; its data lands in the rx buffer. */
        _ensureRead() {
            if (this._inflight) return this._inflight;
            const p = this.device.transferIn(this.inEndpoint.endpointNumber, READ_SIZE).then(res => {
                this._inflight = null;
                if (res.data && res.data.byteLength > 0) {
                    const chunk = new Uint8Array(res.data.buffer, res.data.byteOffset, res.data.byteLength);
                    this._rxChunks.push(chunk);
                    this._rxLen += chunk.length;
                    this.stats.bytesIn += chunk.length;
                    this.lastActivity = Date.now();
                }
            }, e => {
                this._inflight = null;
                logError('Read failed:', e);
                this.markDisconnected('USB read failed: ' + e.message);
            });
            this._inflight = p;
            return p;
        }

        /** Wait until at least `len` bytes are buffered. Never consumes data, so a timeout cannot desync the stream. */
        async _waitBytes(len, timeout) {
            const deadline = Date.now() + timeout;
            while (this._rxLen < len) {
                if (this.connectionLost) {
                    throw new ADBError('Connection lost', ErrorType.CONNECTION_LOST, true);
                }
                const remaining = deadline - Date.now();
                if (remaining <= 0) {
                    throw new ADBError('Read timeout - device not responding', ErrorType.TIMEOUT, true);
                }
                let timer;
                const timedOut = new Promise(r => { timer = setTimeout(r, remaining); });
                try {
                    await Promise.race([this._ensureRead(), timedOut]);
                } finally {
                    clearTimeout(timer);
                }
            }
        }

        _peek(len) {
            const out = new Uint8Array(len);
            let off = 0;
            for (const c of this._rxChunks) {
                if (off >= len) break;
                const take = Math.min(c.length, len - off);
                out.set(c.subarray(0, take), off);
                off += take;
            }
            return out;
        }

        _drop(len) {
            let remaining = len;
            while (remaining > 0 && this._rxChunks.length) {
                const c = this._rxChunks[0];
                if (c.length <= remaining) {
                    remaining -= c.length;
                    this._rxChunks.shift();
                } else {
                    this._rxChunks[0] = c.subarray(remaining);
                    remaining = 0;
                }
            }
            this._rxLen -= len;
        }

        async readExact(len, timeout = 30000) {
            await this._waitBytes(len, timeout);
            const data = this._peek(len);
            this._drop(len);
            return data;
        }

        async _recvPacketUnlocked(timeout = 30000) {
            await this._waitBytes(24, timeout);
            const header = parseHeader(this._peek(24));

            const expectedMagic = (header.cmd ^ 0xFFFFFFFF) >>> 0;
            if (header.magic !== expectedMagic) {
                logError(`Invalid packet magic! cmd=${cmdName(header.cmd)} magic=${header.magic.toString(16)} expected=${expectedMagic.toString(16)}`);
                this._resetBuffer();
                this.markDisconnected('Invalid packet received - connection may be stale');
                throw new ADBError('Invalid packet - connection lost', ErrorType.CONNECTION_LOST, true);
            }
            if (header.len > ADB.MAX_PAYLOAD) {
                this._resetBuffer();
                this.markDisconnected('Oversized packet received');
                throw new ADBError(`Payload too large: ${header.len}`, ErrorType.PROTOCOL_ERROR);
            }

            // header stays buffered until the whole packet has arrived
            await this._waitBytes(24 + header.len, timeout);
            this._drop(24);
            const payload = header.len > 0 ? this._peek(header.len) : new Uint8Array(0);
            if (header.len > 0) this._drop(header.len);

            log(`<< ${cmdName(header.cmd)} arg0=${header.arg0} arg1=${header.arg1} len=${header.len}`);
            return { ...header, payload };
        }

        async recvPacket(timeout = 30000) {
            return withLock(this, '_readLock', () => this._recvPacketUnlocked(timeout));
        }

        /**
         * Wait for a packet addressed to `localId`. Packets for other sockets are queued for their owners,
         * so any number of commands/streams can run concurrently.
         */
        async waitPacket(localId, expectedCmds, timeout = 30000) {
            const deadline = Date.now() + timeout;
            const take = () => {
                const queue = this.pendingPackets.get(localId);
                if (!queue) return null;
                const i = queue.findIndex(p => expectedCmds.includes(p.cmd) || p.cmd === ADB.CMD_CLSE);
                return i >= 0 ? queue.splice(i, 1)[0] : null;
            };
            while (true) {
                const queued = take();
                if (queued) return queued;
                const remaining = deadline - Date.now();
                if (remaining <= 0) {
                    throw new ADBError('Operation timed out', ErrorType.TIMEOUT, true);
                }
                const pkt = await withLock(this, '_readLock', async () => {
                    const again = take();            // another waiter may have queued ours while we waited for the lock
                    if (again) return again;
                    const p = await this._recvPacketUnlocked(Math.max(1, deadline - Date.now()));
                    if (p.arg1 === localId) return p;
                    if (this.pendingPackets.has(p.arg1)) this.pendingPackets.get(p.arg1).push(p);
                    return null;                     // else: packet for a closed socket - drop
                });
                if (pkt) return pkt;
            }
        }

        async authenticate() {
            this._resetBuffer();
            this.pendingPackets.clear();
            this.connectionLost = false;
            this.localId = 1;

            const identity = encoder.encode('host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,abb');
            log('>> CNXN');
            await this.send(makePacket(ADB.CMD_CNXN, ADB.VERSION, this.maxPayload, identity));

            const authTimeout = 60000;
            const startTime = Date.now();

            while (true) {
                const left = authTimeout - (Date.now() - startTime);
                if (left <= 0) {
                    throw new ADBError('Connection timeout. Accept the USB debugging prompt on your device.', ErrorType.TIMEOUT);
                }

                let pkt;
                try {
                    pkt = await this.recvPacket(left);
                } catch (e) {
                    if (e.type === ErrorType.TIMEOUT) {
                        throw new ADBError('Connection timeout. Accept the USB debugging prompt on your device.', ErrorType.TIMEOUT);
                    }
                    throw e;
                }
                if (pkt.cmd === ADB.CMD_CNXN) {
                    this.maxPayload = Math.min(this.maxPayload, pkt.arg1);
                    this.connected = true;
                    this.banner = decoder.decode(pkt.payload);
                    log('Connected! Banner:', this.banner);
                    return true;
                } else if (pkt.cmd === ADB.CMD_AUTH) {
                    await this.handleAuth(pkt);
                    if (this.connected) return true;   // a stored key was accepted
                }
            }
        }

        async connect() {
            if (!this.device) await this.requestDevice();
            await this.openDevice();
            return this.authenticate();
        }

        async _signToken(keyBuf, token) {
            try {
                return signAdbToken(keyBuf, token);
            } catch (e) {
                log('Raw token signing failed, falling back to WebCrypto:', e.message);
                const privKey = await this.credentials.importKey(keyBuf);
                return new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privKey, token));
            }
        }

        async handleAuth(pkt) {
            if (pkt.arg0 !== ADB.AUTH_TOKEN) return;
            let token = pkt.payload;
            log('Auth requested, token length:', token.length);

            const keys = await this.credentials.getKeys();
            for (const keyBuf of keys) {
                try {
                    const sig = await this._signToken(keyBuf, token);
                    log('>> AUTH_SIGNATURE');
                    await this.send(makePacket(ADB.CMD_AUTH, ADB.AUTH_SIGNATURE, 0, sig));

                    const resp = await this.recvPacket();
                    if (resp.cmd === ADB.CMD_CNXN) {
                        this.maxPayload = Math.min(this.maxPayload, resp.arg1);
                        this.connected = true;
                        this.banner = decoder.decode(resp.payload);
                        log('Auth success with stored key');
                        return;
                    }
                    if (resp.cmd === ADB.CMD_AUTH && resp.arg0 === ADB.AUTH_TOKEN) {
                        token = resp.payload;
                        log('Key rejected, got new token');
                    }
                } catch (e) {
                    if (e instanceof ADBError && e.type === ErrorType.CONNECTION_LOST) throw e;
                    log('Key failed:', e.message);
                }
            }

            log('Generating new key and sending public key');
            const newKey = await this.credentials.generateKey();
            const pubKeyB64 = generatePublicKey(newKey.buffer);
            log('>> AUTH_RSAPUBLICKEY');
            await this.send(makePacket(ADB.CMD_AUTH, ADB.AUTH_RSAPUBLICKEY, 0,
                encoder.encode(pubKeyB64 + ' ADBauditor@browser\0')));
        }

        /* ----- sockets ----- */

        async openSocket(service) {
            const localId = this.localId++;
            this.pendingPackets.set(localId, []);

            log(`>> OPEN[${localId}] ${service}`);
            try {
                await this.send(makePacket(ADB.CMD_OPEN, localId, 0, encoder.encode(service + '\0')));

                const pkt = await this.waitPacket(localId, [ADB.CMD_OKAY, ADB.CMD_CLSE]);
                if (pkt.cmd === ADB.CMD_CLSE) {
                    throw new ADBError(`Service unavailable: ${service}`, ErrorType.PERMISSION_DENIED);
                }
                log(`Socket opened: local=${localId} remote=${pkt.arg0}`);
                return { localId, remoteId: pkt.arg0 };
            } catch (e) {
                this.pendingPackets.delete(localId);
                throw e;
            }
        }

        async writeSocket(sock, data) {
            const max = Math.max(1, this.maxPayload);
            if (data.length === 0) return true;
            for (let off = 0; off < data.length; off += max) {
                await this.send(makePacket(ADB.CMD_WRTE, sock.localId, sock.remoteId, data.subarray(off, off + max)));
                const pkt = await this.waitPacket(sock.localId, [ADB.CMD_OKAY, ADB.CMD_CLSE]);
                if (pkt.cmd !== ADB.CMD_OKAY) return false;
            }
            return true;
        }

        async readSocket(sock, timeout = 30000) {
            const pkt = await this.waitPacket(sock.localId, [ADB.CMD_WRTE, ADB.CMD_CLSE], timeout);
            if (pkt.cmd === ADB.CMD_CLSE) return null;
            await this.send(makePacket(ADB.CMD_OKAY, sock.localId, sock.remoteId));
            return pkt.payload;
        }

        async closeSocket(sock) {
            try {
                await this.send(makePacket(ADB.CMD_CLSE, sock.localId, sock.remoteId));
            } catch (e) { /* ignore */ }
            this.pendingPackets.delete(sock.localId);
        }

        /**
         * Run a shell command and return its (trimmed) combined output.
         * `timeout` is the maximum idle time between output chunks.
         */
        async shell(cmd, timeout = 30000) {
            log('Shell:', cmd);
            this.stats.commands++;
            const sock = await this.openSocket(`shell:${cmd}`);
            const dec = new TextDecoder();
            let output = '';
            try {
                while (true) {
                    const data = await this.readSocket(sock, timeout);
                    if (!data) break;
                    output += dec.decode(data, { stream: true });
                }
                output += dec.decode();
            } finally {
                await this.closeSocket(sock);
            }
            return output.trim();
        }

        /** Run a command and also report its exit status. Resolves to { output, code }. */
        async shellWithStatus(cmd, timeout = 30000) {
            const marker = '__ADBAUD_RC__';
            const raw = await this.shell(`${cmd}; echo ${marker}$?`, timeout);
            const idx = raw.lastIndexOf(marker);
            if (idx < 0) return { output: raw, code: null };
            return { output: raw.slice(0, idx).trim(), code: parseInt(raw.slice(idx + marker.length), 10) };
        }

        /**
         * Start a long-running command (logcat, ...) and stream decoded text to `onChunk`.
         * Returns { stop(), done } - `done` settles when the stream ends.
         */
        async streamShell(cmd, onChunk) {
            const sock = await this.openSocket(`shell:${cmd}`);
            const dec = new TextDecoder();
            let stopped = false;
            const done = (async () => {
                try {
                    while (!stopped && !this.connectionLost) {
                        let data;
                        try {
                            data = await this.readSocket(sock, 1000);
                        } catch (e) {
                            if (e.type === ErrorType.TIMEOUT && !stopped) continue;
                            if (stopped) break;
                            throw e;
                        }
                        if (!data) break;
                        const text = dec.decode(data, { stream: true });
                        if (text) onChunk(text);
                    }
                } finally {
                    await this.closeSocket(sock);
                }
            })();
            return {
                done,
                stop: async () => {
                    stopped = true;
                    await done.catch(() => {});
                }
            };
        }

        async listDirectory(path) {
            log('List directory:', path);
            const sock = await this.openSocket('sync:');
            const sync = new SyncSession(this, sock);
            try {
                return await sync.list(path);
            } finally {
                await this.closeSocket(sock);
            }
        }

        async statFile(path) {
            const sock = await this.openSocket('sync:');
            const sync = new SyncSession(this, sock);
            try {
                return await sync.stat(path);
            } finally {
                await this.closeSocket(sock);
            }
        }

        async pullFile(path, onProgress = null) {
            log('Pull file:', path);
            const sock = await this.openSocket('sync:');
            const sync = new SyncSession(this, sock);
            try {
                let total = 0;
                try { total = (await sync.stat(path)).size; } catch { /* size is only used for progress */ }
                return await sync.pull(path, onProgress ? (n) => onProgress(n, total) : null);
            } finally {
                await this.closeSocket(sock);
            }
        }

        async pushFile(path, data, mode = 0o644, onProgress = null) {
            log('Push file:', path);
            const sock = await this.openSocket('sync:');
            const sync = new SyncSession(this, sock);
            try {
                return await sync.push(path, data, mode, onProgress);
            } finally {
                await this.closeSocket(sock);
            }
        }

        async takeScreenshot() {
            log('Taking screenshot');
            const sock = await this.openSocket('shell:screencap -p');
            const chunks = [];
            try {
                while (true) {
                    const data = await this.readSocket(sock);
                    if (!data) break;
                    chunks.push(data);
                }
            } finally {
                await this.closeSocket(sock);
            }
            const total = chunks.reduce((s, c) => s + c.length, 0);
            log('Screenshot size:', total);
            const result = new Uint8Array(total);
            let off = 0;
            for (const c of chunks) { result.set(c, off); off += c.length; }
            if (total < 8 || result[0] !== 0x89 || result[1] !== 0x50) {
                throw new ADBError('Screenshot failed: device returned no image (screen may be secure/locked).', ErrorType.UNKNOWN);
            }
            return new Blob([result], { type: 'image/png' });
        }

        async getDeviceProps() {
            const props = {};
            const keys = {
                model: 'ro.product.model',
                brand: 'ro.product.brand',
                manufacturer: 'ro.product.manufacturer',
                device: 'ro.product.device',
                androidVersion: 'ro.build.version.release',
                sdkVersion: 'ro.build.version.sdk',
                serial: 'ro.serialno',
                buildId: 'ro.build.id',
                securityPatch: 'ro.build.version.security_patch',
                fingerprint: 'ro.build.fingerprint',
                cpuAbi: 'ro.product.cpu.abi',
                buildType: 'ro.build.type',
                buildTags: 'ro.build.tags',
                bootloaderLocked: 'ro.boot.flash.locked',
                verifiedBoot: 'ro.boot.verifiedbootstate',
                debuggable: 'ro.debuggable',
                selinuxMode: 'ro.boot.selinux'
            };
            // one round-trip instead of one per property
            const script = Object.entries(keys).map(([k, p]) => `echo "${k}=$(getprop ${p})"`).join('; ');
            let out = '';
            try { out = await this.shell(script); } catch { /* fall through to Unknown */ }
            const parsed = {};
            for (const line of out.split('\n')) {
                const i = line.indexOf('=');
                if (i > 0) parsed[line.slice(0, i)] = line.slice(i + 1).trim();
            }
            for (const k of Object.keys(keys)) props[k] = parsed[k] || (k === 'serial' ? (this.device?.serialNumber || 'Unknown') : 'Unknown');
            try {
                const bat = await this.shell('dumpsys battery');
                const m = bat.match(/level:\s*(\d+)/);
                props.batteryLevel = m ? parseInt(m[1], 10) : null;
                const t = bat.match(/temperature:\s*(\d+)/);
                props.batteryTemp = t ? parseInt(t[1], 10) / 10 : null;
                const st = bat.match(/status:\s*(\d+)/);
                props.charging = st ? st[1] === '2' : null;
            } catch { props.batteryLevel = null; }
            return props;
        }

        async listPackages(includeSystem = false) {
            const flag = includeSystem ? '' : '-3';
            const out = await this.shell(`pm list packages ${flag}`);
            return out.split('\n').filter(l => l.startsWith('package:')).map(l => l.substring(8).trim()).filter(Boolean).sort();
        }

        /** All APK paths of a package (base + splits). */
        async getApkPaths(pkg) {
            if (!ABUtils.isValidPackageName(pkg)) {
                throw new ADBError(`Invalid package name: ${pkg}`, ErrorType.NOT_FOUND);
            }
            const out = await this.shell(`pm path ${ABUtils.shQuote(pkg)}`);
            const lines = out.split('\n').filter(l => l.startsWith('package:'));
            if (lines.length === 0) {
                throw new ADBError(`No APK found for package: ${pkg}`, ErrorType.NOT_FOUND);
            }
            return lines.map(l => l.substring(8).trim());
        }

        async getApkPath(pkg) {
            log('Getting APK path for:', pkg);
            return (await this.getApkPaths(pkg))[0];
        }

        async pullApk(pkg, onProgress = null) {
            const path = await this.getApkPath(pkg);
            return this.pullFile(path, onProgress);
        }

        async disconnect() {
            log('Disconnecting');
            this.connected = false;
            this.connectionLost = true;
            if (this.device?.opened) {
                try { await this.device.close(); } catch {}
            }
            this.device = null;
            this.deviceDescriptor = null;
            this.pendingPackets.clear();
            this._resetBuffer();

            if (this._disconnectedResolve) {
                this._disconnectedResolve('User disconnected');
            }
        }

        isConnected() {
            return this.connected && !this.connectionLost && this.device?.opened;
        }

        async ping() {
            try {
                await this.shell('echo ping', 5000);
                return true;
            } catch (e) {
                return false;
            }
        }

        getDeviceInfo() {
            if (!this.device) return null;
            return {
                serial: this.device.serialNumber,
                name: this.device.productName,
                manufacturer: this.device.manufacturerName,
                connected: this.isConnected(),
                banner: this.banner
            };
        }
    }

    class SyncSession {
        constructor(adb, sock) {
            this.adb = adb;
            this.sock = sock;
            this._chunks = [];
            this._len = 0;
        }

        async writeCmd(id, arg) {
            const idVal = typeof id === 'string' ? syncId(id) : id;
            if (typeof arg === 'string') {
                const strBytes = encoder.encode(arg);
                const data = new Uint8Array(8 + strBytes.length);
                const v = new DataView(data.buffer);
                v.setUint32(0, idVal, true);
                v.setUint32(4, strBytes.length, true);
                data.set(strBytes, 8);
                await this.adb.writeSocket(this.sock, data);
            } else {
                const data = new Uint8Array(8);
                const v = new DataView(data.buffer);
                v.setUint32(0, idVal, true);
                v.setUint32(4, arg, true);
                await this.adb.writeSocket(this.sock, data);
            }
        }

        async readBytes(len) {
            while (this._len < len) {
                const data = await this.adb.readSocket(this.sock);
                if (!data) {
                    throw new ADBError('Sync connection closed unexpectedly', ErrorType.CONNECTION_LOST);
                }
                this._chunks.push(data);
                this._len += data.length;
            }
            const out = new Uint8Array(len);
            let off = 0;
            while (off < len) {
                const c = this._chunks[0];
                const take = Math.min(c.length, len - off);
                out.set(c.subarray(0, take), off);
                off += take;
                if (take === c.length) this._chunks.shift();
                else this._chunks[0] = c.subarray(take);
            }
            this._len -= len;
            return out;
        }

        async _readFail(len) {
            return decoder.decode(await this.readBytes(len));
        }

        /** STAT (v1): returns { mode, size, mtime, exists }. */
        async stat(path) {
            await this.writeCmd('STAT', path);
            const resp = await this.readBytes(16);
            const v = new DataView(resp.buffer, resp.byteOffset);
            if (syncIdStr(v.getUint32(0, true)) !== 'STAT') {
                throw new ADBError('Unexpected STAT response', ErrorType.PROTOCOL_ERROR);
            }
            const mode = v.getUint32(4, true);
            return { mode, size: v.getUint32(8, true), mtime: new Date(v.getUint32(12, true) * 1000), exists: mode !== 0 };
        }

        async list(path) {
            await this.writeCmd('LIST', path);
            const entries = [];

            while (true) {
                const idBytes = await this.readBytes(4);
                const idVal = new DataView(idBytes.buffer, idBytes.byteOffset).getUint32(0, true);
                const id = syncIdStr(idVal);

                if (id === 'DENT') {
                    const meta = await this.readBytes(16);
                    const mv = new DataView(meta.buffer, meta.byteOffset);
                    const mode = mv.getUint32(0, true);
                    const size = mv.getUint32(4, true);
                    const mtime = mv.getUint32(8, true);
                    const nameLen = mv.getUint32(12, true);
                    const nameBytes = await this.readBytes(nameLen);
                    const name = decoder.decode(nameBytes);
                    if (name !== '.' && name !== '..') {
                        const type = mode & 0o170000;
                        entries.push({
                            name, mode, size,
                            mtime: new Date(mtime * 1000),
                            isDirectory: type === 0o040000,
                            isFile: type === 0o100000,
                            isLink: type === 0o120000
                        });
                    }
                } else if (id === 'DONE') {
                    break;
                } else if (id === 'FAIL') {
                    const lenBytes = await this.readBytes(4);
                    const msgLen = new DataView(lenBytes.buffer, lenBytes.byteOffset).getUint32(0, true);
                    const msg = await this._readFail(msgLen);
                    throw new ADBError('Directory access denied: ' + msg, ErrorType.PERMISSION_DENIED);
                } else {
                    throw new ADBError('Unexpected sync response: ' + id, ErrorType.PROTOCOL_ERROR);
                }
            }

            log(`Listed ${entries.length} entries in ${path}`);
            return entries;
        }

        async pull(path, onProgress = null) {
            log('RECV:', path);
            await this.writeCmd('RECV', path);
            const chunks = [];
            let totalSize = 0;

            while (true) {
                const header = await this.readBytes(8);
                const hv = new DataView(header.buffer, header.byteOffset);
                const idVal = hv.getUint32(0, true);
                const len = hv.getUint32(4, true);
                const id = syncIdStr(idVal);

                if (id === 'DATA') {
                    const chunk = await this.readBytes(len);
                    chunks.push(chunk);
                    totalSize += len;
                    if (onProgress) onProgress(totalSize);
                } else if (id === 'DONE') {
                    log('Pull complete, total size:', totalSize);
                    break;
                } else if (id === 'FAIL') {
                    const msg = await this._readFail(len);
                    throw new ADBError('File read failed: ' + msg, ErrorType.PERMISSION_DENIED);
                } else {
                    throw new ADBError('Unexpected response: ' + id, ErrorType.PROTOCOL_ERROR);
                }
            }

            const result = new Uint8Array(totalSize);
            let off = 0;
            for (const c of chunks) { result.set(c, off); off += c.length; }
            return result;
        }

        async push(path, data, mode, onProgress = null) {
            log('SEND:', path, 'size:', data.length);
            await this.writeCmd('SEND', `${path},${mode}`);

            // each DATA packet (8-byte header + chunk) must fit in one ADB WRTE payload
            const chunkSize = Math.max(1, Math.min(SYNC_MAX_CHUNK, this.adb.maxPayload - 8));
            let off = 0;
            while (off < data.length) {
                const chunk = data.subarray(off, off + chunkSize);
                const pkt = new Uint8Array(8 + chunk.length);
                const v = new DataView(pkt.buffer);
                v.setUint32(0, syncId('DATA'), true);
                v.setUint32(4, chunk.length, true);
                pkt.set(chunk, 8);
                if (!(await this.adb.writeSocket(this.sock, pkt))) {
                    throw new ADBError('Device closed the connection during upload', ErrorType.CONNECTION_LOST);
                }
                off += chunk.length;
                if (onProgress) onProgress(off, data.length);
            }

            const done = new Uint8Array(8);
            const dv = new DataView(done.buffer);
            dv.setUint32(0, syncId('DONE'), true);
            dv.setUint32(4, Math.floor(Date.now() / 1000), true);
            await this.adb.writeSocket(this.sock, done);

            const header = await this.readBytes(8);
            const hv = new DataView(header.buffer, header.byteOffset);
            const id = syncIdStr(hv.getUint32(0, true));
            const len = hv.getUint32(4, true);

            if (id === 'FAIL') {
                throw new ADBError('File write failed: ' + await this._readFail(len), ErrorType.PERMISSION_DENIED);
            }

            log('Push complete');
            return true;
        }
    }

    global.ADBConnection = ADBConnection;
    global.ADBError = ADBError;
    global.ADBErrorType = ErrorType;
    global.DeviceManager = DeviceManager;
    global.USBWatcher = USBWatcher;
    global.ADBInternals = { makePacket, parseHeader, signAdbToken, generatePublicKey, parsePkcs8Rsa, pkcs1Sha1Block, bytesToBigInt, modPow, ADB };
    global.USBDeviceDescriptor = USBDeviceDescriptor;
    global.WebSocketDeviceDescriptor = WebSocketDeviceDescriptor;
    global.TCPDeviceDescriptor = TCPDeviceDescriptor;
})(window);
