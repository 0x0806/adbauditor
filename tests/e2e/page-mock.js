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
    const b64 = (t) => Uint8Array.from(atob(t), c => c.charCodeAt(0));
    const dev = new MockAdbDevice({
        maxdata: 4096,
        outChunk: 777,
        files: { '/data/app/base.apk': b64(window.__APK_B64), '/data/app/evil.apk': b64(window.__APK_EVIL_B64), '/sdcard/test.db': b64(window.__DB_B64), '/sdcard/evil.db': b64(window.__DB_EVIL_B64),
            '/data/app/split_a.apk': b64(window.__APK_B64), '/data/app/split_b.apk': Uint8Array.from([80, 75, 3, 4, 1, 2, 3]),
            '/storage/emulated/0/dl.bin': Uint8Array.from([1, 2, 3, 4, 5]), '/storage/emulated/0/note.txt': new TextEncoder().encode('hello\npassword=hunter2hunter2\n') },
        shell: async (cmd) => {
            window.__shellLog.push(cmd);
            if (cmd.includes('getprop') && cmd.includes('echo "model=')) return [...cmd.matchAll(/echo "(\w+)=/g)].map(m => `${m[1]}=${props[m[1]] ?? ''}`).join('\n');
            if (cmd.startsWith('dumpsys battery')) return 'level: 88\ntemperature: 283\nstatus: 2';
            if (cmd.startsWith('df /data')) return '/dev/block/dm-9 100 50 50 50% /data\n@@\nMemTotal: 8000000 kB\nMemAvailable: 4000000 kB\n@@\n86400.55';
            if (cmd.includes('--show-versioncode')) return 'package:com.example.app  installer=com.android.vending versionCode:42\npackage:com.bad.debuggable  installer=null versionCode:7';
            if (cmd.startsWith('settings list')) return 'adb_enabled=1\nhttp_proxy=:0\nwifi_on=1\nevil=' + EVIL;
            if (cmd === 'getprop') return '[ro.build.type]: [user]\n[ro.product.model]: [E2E]';
            if (cmd === 'dumpsys -l') return 'Currently running services:\n  battery\n  wifi';
            if (cmd.startsWith("dumpsys 'battery'")) return 'Battery Service state:\n  level: 88';
            if (cmd.includes('echo @@ADDR')) return '@@ADDR\n2: wlan0    inet 192.168.1.20/24 scope global wlan0\n@@ROUTE\ndefault via 192.168.1.1 dev wlan0\n@@DNS\n8.8.8.8\n@@PROXY\nnull\n@@PRIVDNS\noff\nnull';
            if (cmd.startsWith('settings get global http_proxy')) return ':0';
            if (cmd.startsWith('am start') || cmd.startsWith('am broadcast')) return 'Starting: Intent { act=android.intent.action.VIEW }';
            if (cmd.startsWith('logcat -b')) return '01-02 10:00:00.000  1  1 I Tag: snapshot line\n';
            if (cmd.startsWith("cd '/sdcard/DCIM'") && cmd.endsWith('pwd')) return '/sdcard/DCIM';
            if (cmd.includes('ls -1p')) return 'DCIM/\nDocuments/\nDownload/';
            if (cmd.startsWith('stat ')) return 'File: x\nSize: 10';
            if (cmd.startsWith('md5sum') || cmd.startsWith('sha1sum') || cmd.startsWith('sha256sum')) return 'deadbeef  file';
            if (cmd.startsWith('find ')) return cmd.includes('-iname') ? '/storage/emulated/0/DCIM/photo.jpg\n/storage/emulated/0/notes.txt' : '/storage/emulated/0/DCIM/a.txt\n/storage/emulated/0/DCIM/b.txt';
            if (cmd.startsWith('pm list packages')) return 'package:com.example.app\npackage:com.bad.debuggable\npackage:com.evil.<b>x';
            if (cmd.startsWith('pm install')) return 'Success';
            if (cmd.startsWith('pm path') && cmd.includes('com.split.app')) return 'package:/data/app/split_a.apk\npackage:/data/app/split_b.apk';
            if (cmd.includes('ping -c')) return new Promise(() => {});
            if (cmd.startsWith('pm path')) return cmd.includes('com.bad.debuggable') ? 'package:/data/app/evil.apk' : 'package:/data/app/base.apk';
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
            if (cmd.startsWith('logcat -v threadtime -T')) return new Promise(() => {});   // the live stream stays open like a real one
            if (cmd.startsWith('logcat')) return '';
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
