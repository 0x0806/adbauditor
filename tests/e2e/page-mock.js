// Runs INSIDE the page before any app script: installs a fake WebUSB stack backed by MockAdbDevice.
(function () {
    const { MockAdbDevice } = window.__MOCK_MODULE;
    const FIX = window.__FIXTURES;
    const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
    const EVIL = '<img src=x onerror="window.__pwned=(window.__pwned||0)+1">';
    const props = {
        model: 'Pixel <b>E2E</b>', brand: 'google', manufacturer: 'Google', device: 'e2e', androidVersion: '14', sdkVersion: '34',
        serial: 'MOCK123', buildId: 'UQ1A.240105', securityPatch: '2026-10-05', fingerprint: 'google/e2e/e2e:14/UQ1A/1:user/release-keys',
        cpuAbi: 'arm64-v8a', buildType: 'user', buildTags: 'release-keys', bootloaderLocked: '1', verifiedBoot: 'green', debuggable: '0', selinuxMode: ''
    };
    const files = {
        '/storage/emulated/0': [
            ['drwxrwx--x', 'DCIM'], ['drwxrwx--x', EVIL], ['-rw-rw----', 'notes $(reboot).txt', 1234], ['-rw-rw----', "it's.txt", 5]
        ]
    };
    const lsLine = ([perm, name, size]) => `${perm} 2 u0_a123 sdcard_rw ${size || 4096} 2024-03-04 11:30 ${name}`;
    const dev = new MockAdbDevice({
        maxdata: 4096,
        outChunk: 777,
        shell: async (cmd) => {
            window.__shellLog.push(cmd);
            if (cmd.includes('getprop') && cmd.includes('echo "model=')) return [...cmd.matchAll(/echo "(\w+)=/g)].map(m => `${m[1]}=${props[m[1]] ?? ''}`).join('\n');
            if (cmd.startsWith('dumpsys battery')) return 'level: 88\ntemperature: 283\nstatus: 2';
            if (cmd.startsWith('df /data')) return '/dev/block/dm-9 100 50 50 50% /data\n@@\nMemTotal: 8000000 kB\nMemAvailable: 4000000 kB\n@@\n86400.55';
            if (cmd.startsWith('pm list packages')) return 'package:com.example.app\npackage:com.bad.debuggable\npackage:com.evil.<b>x';
            if (cmd.startsWith('pm path')) return 'package:/data/app/base.apk';
            if (cmd.startsWith('dumpsys package com.bad.debuggable')) return FIX.dump.replace(/com\.example\.app/g, 'com.bad.debuggable').replace('flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]', 'flags=[ DEBUGGABLE HAS_CODE ]');
            if (cmd.startsWith('dumpsys package')) return FIX.dump;
            if (cmd.startsWith('ls -la ')) {
                const m = cmd.match(/^ls -la '(.*)'/);
                const entries = files[m && m[1]];
                return entries ? 'total 8\n' + entries.map(lsLine).join('\n') : 'ls: no such dir: No such file or directory';
            }
            if (cmd.includes('su -c') ) return '/system/bin/sh: su: inaccessible or not found';
            if (cmd.startsWith('run-as')) return 'run-as: package not debuggable: x';
            if (cmd.startsWith('screencap')) return PNG;
            if (cmd.startsWith('echo ping')) return 'ping';
            if (cmd.startsWith('pidof')) return '';
            if (cmd.startsWith('logcat')) return new Promise(() => {});   // stays open like a real stream
            if (cmd.includes('ro.build.version.security_patch')) return 'ro.build.version.security_patch=2026-10-05\nro.boot.flash.locked=1\nro.boot.verifiedbootstate=green\nro.debuggable=0\nro.build.type=user\nservice.adb.tcp.port=\npersist.adb.tcp.port=\nro.secure=1\nselinux=Enforcing';
            if (cmd.startsWith('echo hello')) return 'hello-from-device';
            return '';
        }
    });
    window.__dev = dev;
    window.__shellLog = [];
    const listeners = { connect: [], disconnect: [] };
    const usb = {
        getDevices: async () => (dev.unplugged ? [] : [dev]),
        requestDevice: async () => dev,
        addEventListener(type, fn) { (listeners[type] || []).push(fn); },
        removeEventListener(type, fn) { const l = listeners[type] || []; const i = l.indexOf(fn); if (i >= 0) l.splice(i, 1); }
    };
    const origUnplug = dev.unplug.bind(dev);
    dev.unplug = () => { origUnplug(); listeners.disconnect.forEach(fn => fn({ device: dev })); };
    Object.defineProperty(navigator, 'usb', { value: usb, configurable: true });
})();
