'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createContext, load } = require('./helpers/env');

function setup(initial = []) {
    const listeners = { connect: [], disconnect: [] };
    const state = { devices: initial };
    const usb = {
        getDevices: async () => state.devices,
        requestDevice: async () => state.devices[0],
        addEventListener: (t, f) => listeners[t].push(f),
        removeEventListener: (t, f) => { const i = listeners[t].indexOf(f); if (i >= 0) listeners[t].splice(i, 1); }
    };
    const ctx = load(createContext({ navigator: { usb } }), ['js/utils.js', 'js/adb-core.js']);
    return { ctx, listeners, state };
}
const dev = (serial, pid = 1) => ({ serialNumber: serial, vendorId: 0x18d1, productId: pid, productName: 'Pixel' });

test('devices without a serial number get a stable fallback id', () => {
    const { ctx } = setup();
    assert.equal(ctx.usbSerial(dev(null, 7)), 'usb-6353-7');
    assert.equal(ctx.usbSerial(dev('ABC')), 'ABC');
});

test('refresh lists paired devices once, with consistent keys, and drops unplugged ones', async () => {
    const { ctx, state } = setup([dev('A'), dev(null, 9)]);
    const dm = new ctx.DeviceManager();
    await dm.refreshUSBDevices();
    assert.deepEqual(JSON.parse(JSON.stringify(dm.getDeviceList().map(d => d.serial).sort())), ['A', 'usb-6353-9']);
    await dm.refreshUSBDevices();                       // idempotent
    assert.equal(dm.getDeviceList().length, 2);
    state.devices = [dev('A')];
    await dm.refreshUSBDevices();
    assert.deepEqual(JSON.parse(JSON.stringify(dm.getDeviceList().map(d => d.serial))), ['A']);
});

test('USB connect/disconnect events add and REMOVE devices (unplugged device used to stay listed)', async () => {
    const { ctx, listeners } = setup([]);
    const dm = new ctx.DeviceManager();
    const events = [];
    dm.addEventListener((e, d) => events.push(e));
    await dm.initialize();
    listeners.connect.forEach(f => f({ device: dev('X') }));
    listeners.connect.forEach(f => f({ device: dev(null, 3) }));
    assert.equal(dm.getDeviceList().length, 2);
    listeners.disconnect.forEach(f => f({ device: dev('X') }));
    listeners.disconnect.forEach(f => f({ device: dev(null, 3) }));      // serial-less device must match its own key
    await new Promise(r => setImmediate(r));
    assert.equal(dm.getDeviceList().length, 0);
    assert.ok(events.includes('deviceAdded') && events.includes('deviceRemoved'));
});

test('a throwing listener does not break event delivery', async () => {
    const { ctx, listeners } = setup([]);
    const dm = new ctx.DeviceManager();
    let got = 0;
    dm.addEventListener(() => { throw new Error('boom'); });
    dm.addEventListener(() => { got++; });
    await dm.initialize();
    listeners.connect.forEach(f => f({ device: dev('Y') }));
    assert.ok(got > 0);
});

test('saving devices survives unavailable storage', () => {
    const { ctx } = setup();
    ctx.localStorage.setItem = () => { throw new Error('quota'); };
    const dm = new ctx.DeviceManager();
    assert.doesNotThrow(() => dm.addTCPDevice('10.0.0.1', 5555));
    assert.equal(dm.getDeviceList().length, 1);
});

test('dispose removes the USB listeners', async () => {
    const { ctx, listeners } = setup([]);
    const dm = new ctx.DeviceManager();
    await dm.initialize();
    assert.equal(listeners.connect.length, 1);
    dm.dispose();
    assert.equal(listeners.connect.length, 0);
    assert.equal(listeners.disconnect.length, 0);
});

test('two identical serial-less devices: unplugging one keeps the other listed', async () => {
    const a = dev(null, 5), b = dev(null, 5);
    const { ctx, listeners, state } = setup([a, b]);
    const dm = new ctx.DeviceManager();
    await dm.initialize();
    assert.equal(dm.getDeviceList().length, 1);               // indistinguishable: they share one key
    state.devices = [b];                                      // A unplugged, B still present
    listeners.disconnect.forEach(f => f({ device: a }));
    await new Promise(r => setImmediate(r));
    assert.equal(dm.getDeviceList().length, 1, 'device B must not vanish');
    state.devices = [];
    listeners.disconnect.forEach(f => f({ device: b }));
    await new Promise(r => setImmediate(r));
    assert.equal(dm.getDeviceList().length, 0);
});

test('ADBConnection reports the same fallback serial as the device manager', () => {
    const { ctx } = setup();
    const adb = new ctx.ADBConnection();
    adb.device = dev(null, 11); adb.connected = true; adb.device.opened = true;
    assert.equal(adb.getDeviceInfo().serial, 'usb-6353-11');
});
