/** Registers the offline service worker (http/https only). Enhanced by 0x0806. */
if ('serviceWorker' in navigator && /^https?:$/.test(location.protocol)) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('sw.js').catch((e) => console.warn('Service worker not registered:', e.message));
    });
}
