/* ADB Auditor service worker - offline support. Enhanced by 0x0806 (original project by Sandeep Wawdane). */
const CACHE = 'adbauditor-v2.1.0';
const ASSETS = ['./', 'index.html', 'js/utils.js', 'js/adb-core.js', 'js/security-auditor.js', 'js/sqlite-reader.js', 'js/apk-analyzer.js', 'js/toolkit.js', 'js/app.js', 'js/tools-ui.js', 'js/register-sw.js', 'img/logo.svg', 'manifest.webmanifest', '404.html'];

self.addEventListener('install', (event) => {
    event.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
    event.waitUntil(caches.keys()
        .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
        .then(() => self.clients.claim()));
});

// network first (so updates are picked up), cache as the offline fallback; same-origin GETs only
self.addEventListener('fetch', (event) => {
    const req = event.request;
    if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
    event.respondWith(fetch(req).then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
        return res;
    }).catch(() => caches.match(req).then((hit) => hit || caches.match('index.html'))));
});
