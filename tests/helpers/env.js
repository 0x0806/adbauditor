'use strict';
// Loads the browser scripts into a Node vm context with just enough browser shims.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');

const ROOT = path.resolve(__dirname, '..', '..');

function makeStorage() {
    const m = new Map();
    return {
        getItem: k => (m.has(k) ? m.get(k) : null),
        setItem: (k, v) => m.set(k, String(v)),
        removeItem: k => m.delete(k),
        clear: () => m.clear()
    };
}

function createContext(extra = {}) {
    const sandbox = {
        console, setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
        TextEncoder, TextDecoder, URL, Blob, Date, Promise, Map, Set, BigInt,
        atob: s => Buffer.from(s, 'base64').toString('binary'),
        btoa: s => Buffer.from(s, 'binary').toString('base64'),
        crypto: webcrypto,
        navigator: {},
        localStorage: makeStorage(),
        ...extra
    };
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    return vm.createContext(sandbox);
}

function load(ctx, files) {
    for (const f of files) {
        const file = path.join(ROOT, f);
        vm.runInContext(fs.readFileSync(file, 'utf8'), ctx, { filename: file });
    }
    return ctx;
}

function loadLibs(extra = {}) {
    const ctx = createContext(extra);
    return load(ctx, ['js/utils.js', 'js/adb-core.js', 'js/security-auditor.js']);
}

module.exports = { ROOT, createContext, load, loadLibs };
