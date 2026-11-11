'use strict';
/**
 * Interface behaviour only - no device, ADB or audit logic lives here.
 * Sidebar collapse, command-palette button, pointer spotlight and count-up.
 * Spotlight and count-up are small vanilla ports of the ideas behind React Bits'
 * SpotlightCard and CountUp, because this app ships no framework or build step.
 *
 * Original project by Sandeep Wawdane; interface enhancements by 0x0806.
 */
(function () {
    const reduceMotion = () => !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    const read = (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } };
    const write = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* storage unavailable */ }  };

    /* ---- sidebar: collapse / expand, remembered per browser ---- */
    const toggle = document.getElementById('navToggle');
    function setCollapsed(on) {
        document.body.classList.toggle('nav-collapsed', on);
        if (toggle) {
            toggle.setAttribute('aria-pressed', String(on));
            toggle.title = on ? 'Expand sidebar' : 'Collapse sidebar';
            const label = toggle.querySelector('.dock-tooltip');
            if (label) label.textContent = on ? 'Expand' : 'Collapse';
        }
    }
    setCollapsed(read('ab.navCollapsed') === '1');
    if (toggle) toggle.addEventListener('click', () => {
        const on = !document.body.classList.contains('nav-collapsed');
        setCollapsed(on);
        write('ab.navCollapsed', on ? '1' : '0');
    });

    /* ---- command palette button (the palette itself opens on Ctrl/Cmd+K) ---- */
    const paletteBtn = document.getElementById('paletteBtn');
    if (paletteBtn) {
        if (/Mac|iPhone|iPad/.test(navigator.platform || '')) {
            const key = paletteBtn.querySelector('.dock-key');
            if (key) key.textContent = '⌘ K';
        }
        paletteBtn.addEventListener('click', () => {
            document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true, cancelable: true }));
        });
    }

    /* ---- pointer spotlight (CSS reads --mx / --my) ---- */
    let frame = 0;
    document.addEventListener('pointermove', (e) => {
        if (e.pointerType === 'touch' || frame) return;
        const target = e.target.closest ? e.target.closest('.cap, .stat-card, .hero') : null;
        if (!target) return;
        frame = requestAnimationFrame(() => {
            frame = 0;
            const r = target.getBoundingClientRect();
            const host = target.classList.contains('hero') ? target.querySelector('.hero-bg') : target;
            if (!host) return;
            host.style.setProperty('--mx', (e.clientX - r.left) + 'px');
            host.style.setProperty('--my', (e.clientY - r.top) + 'px');
        });
    }, { passive: true });

    /* ---- count-up for [data-count] (landing sample report), once ---- */
    function countUp(node) {
        const end = parseInt(node.dataset.count, 10);
        if (!isFinite(end) || node.dataset.counted) return;
        node.dataset.counted = '1';
        if (reduceMotion()) return;
        const t0 = performance.now(), dur = 1100;
        const step = (now) => {
            const p = Math.min(1, (now - t0) / dur);
            node.textContent = String(Math.round(end * (1 - Math.pow(1 - p, 4))));
            if (p < 1) requestAnimationFrame(step); else node.textContent = String(end);
        };
        node.textContent = '0';
        setTimeout(() => requestAnimationFrame(step), 450);
    }
    const area = document.getElementById('contentArea');
    if (area && window.MutationObserver) {
        const scan = () => area.querySelectorAll('[data-count]').forEach(countUp);
        new MutationObserver(scan).observe(area, { childList: true });
        scan();
    }
})();
