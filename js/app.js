/**
 * ADB Auditor - application UI.
 * @preserve
 * @author Sandeep Wawdane (original creator of ADB Auditor)
 * @contributor 0x0806 (security hardening, new features, accessibility)
 * @license See LICENSE (CC BY-NC-ND 4.0, (c) Sandeep Wawdane)
 */
(function() {
    'use strict';

    const CONFIG = { buildKey: 'c2FuZGVlcHdhd2RhbmU=', version: 2026 };   // original-author watermark - do not remove
    const U = window.ABUtils;

    const state = {
        connected: false,
        currentSection: 'overview',
        deviceInfo: {},
        apps: [],
        appFilter: '',
        currentPath: '/storage/emulated/0',
        files: [],
        fileFilter: '',
        fileSort: { key: 'name', dir: 1 },
        shellHistory: [],
        shellHistoryIndex: -1,
        shellCwd: '',
        shellRootMode: false,
        showSystemApps: false,
        securityApps: [],
        currentSecurityTab: 'localStorage',
        screenshotBlob: null,
        screenshotUrl: null,
        devices: [],
        selectedDeviceSerial: null,
        addMenuOpen: false,
        rootMode: false,
        tcpModalOpen: false
    };

    const store = {
        get(key, fallback) {
            try { const v = localStorage.getItem('ab.' + key); return v === null ? fallback : JSON.parse(v); } catch (e) { return fallback; }
        },
        set(key, value) {
            try { localStorage.setItem('ab.' + key, JSON.stringify(value)); } catch (e) { /* storage may be unavailable */ }
        }
    };

    const escapeHtml = U.escapeHtml;
    const escapeAttr = U.escapeAttr;
    const shQuote = U.shQuote;
    const safeEncode = (str) => {
        try { return btoa(unescape(encodeURIComponent(str))); } catch (e) { return btoa(str); }
    };
    const safeDecode = (str) => {
        try { return decodeURIComponent(escape(atob(str))); } catch (e) { return atob(str); }
    };
    const base64ToBytes = U.base64ToBytes;
    let adb = null;
    let deviceManager = null;

    const tmpName = () => `/data/local/tmp/.adbaud_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    /** Read a file as root: copy to a temp file the shell user can read, pull it over sync, clean up. */
    async function pullAsRoot(path, onProgress) {
        const tmp = tmpName();
        const r = await adb.shell(U.suWrap(`cp ${shQuote(path)} ${shQuote(tmp)} && chmod 644 ${shQuote(tmp)}`) + ' 2>&1');
        if (r.trim()) throw new Error(r.trim().split('\n')[0]);
        try {
            return await adb.pullFile(tmp, onProgress);
        } finally {
            adb.shell(`rm -f ${shQuote(tmp)}`).catch(() => {});
        }
    }

    /** Write a file as root: push to a temp file, then `su cp` it into place. */
    async function pushAsRoot(dest, bytes, onProgress) {
        const tmp = tmpName();
        await adb.pushFile(tmp, bytes, 0o644, onProgress);
        try {
            const r = await adb.shell(U.suWrap(`cp ${shQuote(tmp)} ${shQuote(dest)}`) + ' 2>&1');
            if (r.trim()) throw new Error(r.trim().split('\n')[0]);
        } finally {
            adb.shell(`rm -f ${shQuote(tmp)}`).catch(() => {});
        }
    }

    const isSdcardPath = (p) => p.startsWith('/sdcard/') || p.startsWith('/storage/') || p === '/sdcard';

    /** Read any device path: plain sync pull where possible, root copy otherwise. */
    async function readDeviceFile(path, onProgress, forceRoot = false) {
        if (forceRoot || state.rootMode) {
            if (isSdcardPath(path) && !forceRoot) return adb.pullFile(path, onProgress);
            return pullAsRoot(path, onProgress);
        }
        try {
            return await adb.pullFile(path, onProgress);
        } catch (e) {
            if (!isSdcardPath(path) && /denied|permission/i.test(e.message)) {
                try { return await pullAsRoot(path, onProgress); } catch (e2) { /* fall through to original error */ }
            }
            throw e;
        }
    }

    const el = {
        connectBtn: document.getElementById('connectBtn'),
        disconnectBtn: document.getElementById('disconnectBtn'),
        statusDot: document.getElementById('statusDot'),
        statusText: document.getElementById('statusText'),
        statusPill: document.getElementById('statusPill'),
        contentArea: document.getElementById('contentArea'),
        toastContainer: document.getElementById('toastContainer'),
        loadingOverlay: document.getElementById('loadingOverlay'),
        loadingText: document.getElementById('loadingText'),
        loadingSubtext: document.getElementById('loadingSubtext'),
        deviceSelect: document.getElementById('deviceSelect'),
        addDeviceBtn: document.getElementById('addDeviceBtn'),
        addDeviceMenu: document.getElementById('addDeviceMenu'),
        deviceListContainer: document.getElementById('deviceListContainer')
    };
    function setAmbientActive(active) {
        document.querySelectorAll('.ambient-orb').forEach(orb => {
            orb.classList.toggle('active', active);
        });
    }
    const sectionHooks = {};
    const extraCommands = [];

    /* ---------- activity log (local audit trail of what was done in this session) ---------- */
    const activity = {
        entries: store.get('activityLog', []),
        add(action, detail = '') {
            this.entries.push({ t: new Date().toISOString(), action, detail: String(detail).slice(0, 500) });
            if (this.entries.length > 300) this.entries.splice(0, this.entries.length - 300);
            store.set('activityLog', this.entries);
        },
        clear() { this.entries = []; store.set('activityLog', []); },
        toText() { return this.entries.map(e => `${e.t}  ${e.action}${e.detail ? '  ' + e.detail : ''}`).join('\n'); }
    };

    const templates = {
        welcome: `
            <div class="landing-page">
                <section class="hero-section">
                    <div class="hero-canvas">
                        <div class="hero-glow glow-primary active"></div>
                        <div class="hero-glow glow-secondary active"></div>
                        <div class="hero-glow glow-tertiary active"></div>
                        <div class="hero-grid"></div>
                        <div class="hero-particles">
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                            <div class="particle"></div>
                        </div>
                    </div>
                    <div class="hero-content">
                        <h1 class="hero-title">
                            <span class="title-line title-gradient">Android Security</span>
                            <span class="title-line title-accent">Reimagined</span>
                        </h1>
                        <p class="hero-tagline">
                            The most advanced <strong>client-side</strong> Android auditing platform. 
                            Analyze apps, extract data, and perform deep security assessments, 
                            all without your data ever leaving your device.
                        </p>
                        <div class="hero-trust">
                            <div class="trust-item">
                                <div class="trust-icon">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                                </div>
                                <div class="trust-text">
                                    <span class="trust-label">Privacy</span>
                                    <span class="trust-value">100% Client-Side</span>
                                </div>
                            </div>
                            <div class="trust-item">
                                <div class="trust-icon">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/></svg>
                                </div>
                                <div class="trust-text">
                                    <span class="trust-label">Data Storage</span>
                                    <span class="trust-value">Zero Upload</span>
                                </div>
                            </div>
                            <div class="trust-item">
                                <div class="trust-icon">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                                </div>
                                <div class="trust-text">
                                    <span class="trust-label">Protocol</span>
                                    <span class="trust-value">WebUSB + ADB</span>
                                </div>
                            </div>
                        </div>
                        <div class="hero-cta">
                            <button class="btn-hero btn-hero-primary" onclick="document.getElementById('connectBtn').click()">
                                <span>
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                                    Connect Device
                                </span>
                            </button>
                            <a href="https://github.com/0x0806/adbauditor" target="_blank" rel="noopener" class="btn-hero btn-hero-secondary">
                                <span>
                                    <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                                    View Source
                                </span>
                            </a>
                        </div>
                    </div>
                    <div class="hero-scroll" onclick="document.querySelector('.features-section').scrollIntoView({behavior:'smooth'})">
                        <div class="scroll-indicator">
                            <div class="scroll-dot"></div>
                        </div>
                        <span>Explore</span>
                    </div>
                </section>

                <div class="section-divider"></div>

                <section class="features-section">
                    <div class="features-header">
                        <span class="section-label">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z"/></svg>
                            Capabilities
                        </span>
                        <h2 class="section-title">Powerful Security Tools</h2>
                        <p class="section-desc">Everything you need for comprehensive Android security assessments, built right into your browser.</p>
                    </div>
                    <div class="features-grid">
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>
                            </div>
                            <h3>App Analysis</h3>
                            <p>Deep dive into installed applications. Extract APKs, analyze permissions, signatures, and package metadata.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                            </div>
                            <h3>File System</h3>
                            <p>Full filesystem access with root support. Navigate, upload, download, and manage device files securely.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                            </div>
                            <h3>Security Audit</h3>
                            <p>OWASP MASTG aligned tests. Analyze storage, backup configs, exported components, and permissions.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                            </div>
                            <h3>Shell Access</h3>
                            <p>Direct ADB shell with command history. Execute commands, scripts, and interact with the device in real-time.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                            </div>
                            <h3>Screenshot</h3>
                            <p>Instant screen capture for documentation. Perfect for evidence collection and audit reporting.</p>
                        </div>
                        <div class="feature-card">
                            <div class="feature-glow"></div>
                            <div class="feature-icon">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/></svg>
                            </div>
                            <h3>Multi-Device</h3>
                            <p>Connect and manage multiple devices simultaneously. Switch between targets seamlessly during assessments.</p>
                        </div>
                    </div>
                </section>

                <section class="setup-section">
                    <div class="setup-header">
                        <span class="section-label">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                            Quick Start
                        </span>
                        <h2 class="section-title">Ready in Seconds</h2>
                        <p class="section-desc">No installation required. Connect your device and start auditing immediately.</p>
                    </div>
                    <div class="setup-steps">
                        <div class="setup-step">
                            <div class="step-number">1</div>
                            <div class="step-content">
                                <h4>Enable USB Debugging</h4>
                                <p>Settings → Developer Options → USB Debugging</p>
                            </div>
                        </div>
                        <div class="setup-step">
                            <div class="step-number">2</div>
                            <div class="step-content">
                                <h4>Connect Device</h4>
                                <p>Use a data-capable USB cable to connect</p>
                            </div>
                        </div>
                        <div class="setup-step">
                            <div class="step-number">3</div>
                            <div class="step-content">
                                <h4>Authorize Access</h4>
                                <p>Accept the USB debugging prompt on device</p>
                            </div>
                        </div>
                        <div class="setup-step">
                            <div class="step-number">4</div>
                            <div class="step-content">
                                <h4>Start Auditing</h4>
                                <p>Click Connect and select your device</p>
                            </div>
                        </div>
                    </div>
                </section>

                <section class="tech-section">
                    <div class="tech-header">
                        <span class="section-label">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/></svg>
                            Technology
                        </span>
                        <h2 class="section-title">Built Different</h2>
                    </div>
                    <div class="tech-grid">
                        <div class="tech-item">
                            <span class="tech-label">Protocol</span>
                            <span class="tech-value">WebUSB + ADB</span>
                        </div>
                        <div class="tech-item">
                            <span class="tech-label">Processing</span>
                            <span class="tech-value">100% Browser</span>
                        </div>
                        <div class="tech-item">
                            <span class="tech-label">Data Upload</span>
                            <span class="tech-value">None</span>
                        </div>
                        <div class="tech-item">
                            <span class="tech-label">Requirements</span>
                            <span class="tech-value">Chrome / Edge</span>
                        </div>
                    </div>
                </section>

                <footer class="landing-footer">
                    <a href="https://github.com/0x0806/adbauditor" target="_blank" rel="noopener noreferrer" class="github-link">
                        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                        <span>Star on GitHub</span>
                    </a>
                    <span class="footer-divider"></span>
                    <span>Created by</span>
                    <a href="https://github.com/thecybersandeep/adbauditor" target="_blank" rel="noopener noreferrer">Sandeep Wawdane</a>
                    <span class="footer-divider"></span>
                    <span>Enhanced &amp; maintained by</span>
                    <a href="https://github.com/0x0806" target="_blank" rel="noopener noreferrer">0x0806</a>
                </footer>
            </div>`,
        overview: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Device Overview</h1>
                    <div class="page-actions">
                        <button class="btn btn-ghost" onclick="app.exportDeviceInfo()" title="Export device info as JSON">
                            Export
                        </button>
                        <button class="btn btn-ghost" onclick="app.loadOverview()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Refresh
                        </button>
                    </div>
                </div>
                <div class="stats-grid" id="statsGrid">
                    <div class="stat-card"><div class="stat-label">Loading</div><div class="stat-value">...</div></div>
                    <div class="stat-card"><div class="stat-label">Loading</div><div class="stat-value">...</div></div>
                    <div class="stat-card"><div class="stat-label">Loading</div><div class="stat-value">...</div></div>
                    <div class="stat-card"><div class="stat-label">Loading</div><div class="stat-value">...</div></div>
                </div>
                <div class="card">
                    <div class="card-header"><span class="card-title">Device Properties</span></div>
                    <div class="prop-list" id="propList"></div>
                </div>
            </div>`,
        apps: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Applications <span class="badge" id="appCount" aria-live="polite"></span></h1>
                    <div class="page-actions">
                        <button class="btn btn-ghost" id="toggleSystemApps">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                            System Apps
                        </button>
                        <button class="btn btn-ghost" onclick="app.loadApps()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Refresh
                        </button>
                    </div>
                </div>
                <div class="drop-zone" id="dropZone" role="button" tabindex="0" aria-label="Install APK: drop files or press Enter to browse" onclick="document.getElementById('apkInput').click()">
                    <input type="file" id="apkInput" accept=".apk" multiple onchange="app.handleApkSelect(event)">
                    <div class="drop-icon">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                    </div>
                    <h3>Install APK</h3>
                    <p>Drop file(s) or click to browse &mdash; select several APKs to install split APKs together</p>
                </div>
                <div class="search-box">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                    <input type="text" class="search-input" id="appSearch" placeholder="Search applications...">
                </div>
                <div class="card">
                    <div class="app-list" id="appList">
                        <div class="empty-state"><p>Loading applications...</p></div>
                    </div>
                </div>
            </div>`,
        files: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">File Browser</h1>
                    <div class="page-actions">
                        <label class="root-toggle">
                            <input type="checkbox" id="rootToggle" onchange="app.toggleRootMode()">
                            <span class="toggle-slider"></span>
                            <span class="toggle-label">Root</span>
                        </label>
                        <button class="btn btn-ghost" onclick="document.getElementById('fileUploadInput').click()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                            Upload
                        </button>
                        <input type="file" id="fileUploadInput" multiple style="display:none" onchange="app.handleFileUpload(event)">
                        <button class="btn btn-ghost" onclick="app.searchFiles()" title="Search subfolders by name">
                            Search
                        </button>
                        <button class="btn btn-ghost" onclick="app.makeDirectory()" title="Create folder">
                            New folder
                        </button>
                        <button class="btn btn-ghost" onclick="app.navigateUp()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18"/></svg>
                            Up
                        </button>
                        <button class="btn btn-ghost" onclick="app.refreshFiles()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                            Refresh
                        </button>
                    </div>
                </div>
                <div class="card file-card" id="fileCard">
                    <div class="path-bar" id="pathBar"></div>
                    <div class="file-toolbar">
                        <input type="text" class="search-input" id="fileFilter" placeholder="Filter this folder..." aria-label="Filter files">
                        <select id="fileSort" aria-label="Sort files">
                            <option value="name:1">Name A-Z</option><option value="name:-1">Name Z-A</option>
                            <option value="size:-1">Largest first</option><option value="size:1">Smallest first</option>
                            <option value="date:-1">Newest first</option><option value="date:1">Oldest first</option>
                        </select>
                        <span class="badge" id="fileCount" aria-live="polite"></span>
                    </div>
                    <div class="file-bookmarks" id="fileBookmarks">
                        <button class="btn btn-sm btn-ghost" data-path="/storage/emulated/0">Internal</button>
                        <button class="btn btn-sm btn-ghost" data-path="/storage/emulated/0/Download">Downloads</button>
                        <button class="btn btn-sm btn-ghost" data-path="/storage/emulated/0/Android/data">Android/data</button>
                        <button class="btn btn-sm btn-ghost" data-path="/data/local/tmp">/data/local/tmp</button>
                        <button class="btn btn-sm btn-ghost" data-path="/data/data">/data/data</button>
                        <button class="btn btn-sm btn-ghost" data-path="/system">/system</button>
                        <button class="btn btn-sm btn-ghost" data-path="/proc">/proc</button>
                    </div>
                    <div class="file-drop-zone" id="fileDropZone">
                        <div class="drop-indicator">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
                            <span>Drop files here to upload</span>
                        </div>
                        <div class="file-list" id="fileList" role="list">
                            <div class="empty-state"><p>Loading...</p></div>
                        </div>
                    </div>
                </div>
            </div>`,
        screenshot: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Screenshot</h1>
                    <div class="page-actions">
                        <button class="btn btn-primary" onclick="app.captureScreenshot()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z"/></svg>
                            Capture
                        </button>
                        <button class="btn btn-ghost" id="liveScreenshotBtn" aria-pressed="false" onclick="app.toggleLiveScreenshot()" title="Refresh the screenshot every 1.5 s">
                            Live
                        </button>
                        <button class="btn btn-ghost" id="copyScreenshotBtn" disabled onclick="app.copyScreenshot()">
                            Copy
                        </button>
                        <button class="btn btn-ghost" id="saveScreenshotBtn" disabled onclick="app.saveScreenshot()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                            Save
                        </button>
                    </div>
                </div>
                <div class="screenshot-area" id="screenshotArea">
                    <div class="screenshot-placeholder">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                        <p>Click Capture to take a screenshot</p>
                    </div>
                </div>
            </div>`,
        shell: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Shell</h1>
                    <div class="page-actions">
                        <label class="root-toggle">
                            <input type="checkbox" id="shellRootToggle" onchange="app.toggleShellRoot()">
                            <span class="toggle-slider"></span>
                            <span class="toggle-label">Root</span>
                        </label>
                        <button class="btn btn-ghost" onclick="app.downloadShellTranscript()" title="Save transcript">
                            Save
                        </button>
                        <button class="btn btn-ghost" onclick="app.clearShell()">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                            Clear
                        </button>
                    </div>
                </div>
                <div class="shell-container">
                    <div class="shell-header">
                        <div class="shell-dot r"></div>
                        <div class="shell-dot y"></div>
                        <div class="shell-dot g"></div>
                        <span class="shell-title">ADB Shell</span>
                    </div>
                    <div class="shell-output" id="shellOutput">
                        <div class="shell-line" style="color: var(--lum-50);">Type commands and press Enter. Tab completes, Up/Down browse history. Type 'help' for details.</div>
                    </div>
                    <div class="shell-input-row">
                        <span class="shell-prompt-char" id="shellPrompt">$</span>
                        <input type="text" class="shell-input" id="shellInput" placeholder="Enter command..." aria-label="Shell command" autocomplete="off" autocapitalize="off" spellcheck="false">
                    </div>
                </div>
            </div>`,
        security: `
            <div class="page">
                <div class="page-header">
                    <h1 class="page-title">Security Analysis</h1>
                </div>
                <div class="tab-bar" role="tablist" aria-label="Security tools">
                    <button class="tab-btn active" data-tab="localStorage" onclick="app.switchSecurityTab('localStorage')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/></svg>
                        Storage
                    </button>
                    <button class="tab-btn" data-tab="backup" onclick="app.switchSecurityTab('backup')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>
                        Backup
                    </button>
                    <button class="tab-btn" data-tab="exported" onclick="app.switchSecurityTab('exported')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                        Components
                    </button>
                    <button class="tab-btn" data-tab="debuggable" onclick="app.switchSecurityTab('debuggable')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        Debug
                    </button>
                    <button class="tab-btn" data-tab="permissions" onclick="app.switchSecurityTab('permissions')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                        Permissions
                    </button>
                    <button class="tab-btn" data-tab="logcat" onclick="app.switchSecurityTab('logcat')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/></svg>
                        Logcat
                    </button>
                    <button class="tab-btn" data-tab="appInfo" onclick="app.switchSecurityTab('appInfo')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        App Info
                    </button>
                    <button class="tab-btn" data-tab="device" onclick="app.switchSecurityTab('device')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                        Device
                    </button>
                    <button class="tab-btn" data-tab="triage" onclick="app.switchSecurityTab('triage')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                        Triage
                    </button>
                    <button class="tab-btn" data-tab="network" onclick="app.switchSecurityTab('network')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/></svg>
                        Network
                    </button>
                    <button class="tab-btn" data-tab="fullScan" onclick="app.switchSecurityTab('fullScan')">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                        Full Scan
                    </button>
                </div>
                <div id="securityTabContent"></div>
            </div>`
    };
    const SELECT_MAP = {
        localStorage: 'storageSelect',
        backup: 'backupSelect',
        exported: 'exportedSelect',
        debuggable: 'debugSelect',
        permissions: 'permSelect',
        appInfo: 'appInfoSelect',
        fullScan: 'fullScanSelect',
        network: 'networkSelect'
    };
    const securityTabs = {
        localStorage: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/></svg>
                        Local Storage Analyzer
                    </div>
                    <span class="badge warning">Root Required</span>
                </div>
                <p class="panel-desc">Analyze app storage using root access. Extracts SharedPreferences, databases, and internal files.</p>
                <div class="form-row">
                    <select id="storageSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.analyzeStorage()">Analyze</button>
                </div>
                <div id="storageResults"></div>
            </div>`,
        backup: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>
                        Backup Configuration
                    </div>
                </div>
                <p class="panel-desc">Check if allowBackup is enabled. Apps with backup enabled may expose sensitive data.</p>
                <div class="form-row">
                    <select id="backupSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.checkBackup()">Check</button>
                </div>
                <div id="backupResults"></div>
            </div>`,
        exported: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                        Exported Components
                    </div>
                </div>
                <p class="panel-desc">Find exported Activities, Services, Receivers, and Providers accessible by other apps.</p>
                <div class="form-row">
                    <select id="exportedSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.analyzeExported()">Analyze</button>
                </div>
                <div id="exportedResults"></div>
            </div>`,
        debuggable: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        Debuggable Check
                    </div>
                </div>
                <p class="panel-desc">Check if the debuggable flag is enabled, allowing debugger attachment.</p>
                <div class="form-row">
                    <select id="debugSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.checkDebuggable()">Check</button>
                </div>
                <div id="debugResults"></div>
            </div>`,
        permissions: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                        Dangerous Permissions
                    </div>
                </div>
                <p class="panel-desc">Analyze dangerous runtime permissions granted to the application.</p>
                <div class="form-row">
                    <select id="permSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.analyzePermissions()">Analyze</button>
                </div>
                <div id="permResults"></div>
            </div>`,
        device: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">Device Security Posture</div>
                    <span class="badge">No app needed</span>
                </div>
                <p class="panel-desc">Checks the device itself: patch level, bootloader lock, verified boot, SELinux, ADB exposure, root and emulator indicators, accessibility services.</p>
                <div class="form-row">
                    <button class="btn btn-primary" onclick="app.runDeviceAudit()">Audit device</button>
                    <span id="deviceAuditStatus" style="color:var(--lum-50);font-size:12px"></span>
                </div>
                <div id="deviceAuditResults"></div>
            </div>`,
        triage: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">App Triage</div>
                    <span class="badge warning">All apps</span>
                </div>
                <p class="panel-desc">Quickly rank every installed app by risk: debuggable, backup, outdated SDK levels, installer and dangerous permissions. Click a row to run a full scan.</p>
                <div class="form-row">
                    <label class="root-toggle"><input type="checkbox" id="triageSystem"><span class="toggle-slider"></span><span class="toggle-label">Include system apps</span></label>
                    <button class="btn btn-primary" onclick="app.runTriage()">Run triage</button>
                    <select id="triagePerm" aria-label="Filter by granted permission" onchange="app.renderTriage()"><option value="">All permissions</option></select>
                    <span id="triageStatus" style="color:var(--lum-50);font-size:12px"></span>
                </div>
                <div style="background:var(--surface-2);border-radius:4px;height:4px;overflow:hidden;margin-top:8px"><div id="triageBar" style="background:var(--primary);height:100%;width:0%;transition:width 0.3s"></div></div>
                <div id="triageResults"></div>
            </div>`,
        network: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">Network &amp; Processes</div>
                </div>
                <p class="panel-desc">Open TCP/UDP sockets and running processes, optionally filtered to one application.</p>
                <div class="form-row">
                    <select id="networkSelect"><option value="">All apps</option></select>
                    <button class="btn btn-primary" onclick="app.loadNetwork()">Refresh</button>
                </div>
                <div id="networkResults"></div>
            </div>`,
        logcat: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/></svg>
                        Live Logcat
                    </div>
                    <div style="display:flex;gap:8px;align-items:center">
                        <span class="badge" id="logcatStatus">Stopped</span>
                        <button class="btn btn-ghost" onclick="app.downloadLogcat()" title="Download Logs">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:16px;height:16px"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                        </button>
                    </div>
                </div>
                <p class="panel-desc">Live stream of the device log. Filter by text or /regex/, and by minimum level. The device log buffer is never cleared.</p>
                <div class="logcat-controls">
                    <input type="text" id="logcatFilter" class="logcat-input" placeholder="Filter: text or /regex/ (e.g. ActivityManager, /error|fatal/)" aria-label="Log filter">
                    <select id="logcatLevel" aria-label="Minimum level"><option value="V">Verbose+</option><option value="D">Debug+</option><option value="I">Info+</option><option value="W">Warn+</option><option value="E">Error+</option></select>
                    <button class="btn btn-ghost" id="logcatPauseBtn" onclick="app.toggleLogcatPause()">Pause</button>
                    <button class="btn btn-ghost" onclick="app.toggleLogcatWrap()" title="Toggle line wrapping">Wrap</button>
                    <button class="btn btn-primary" id="logcatStartBtn" onclick="app.startLogcat()">Start</button>
                    <button class="btn btn-danger hidden" id="logcatStopBtn" onclick="app.stopLogcat()">Stop</button>
                    <button class="btn btn-ghost" onclick="app.clearLogcat()" title="Clear Logs">Clear</button>
                </div>
                <div id="logcatOutput" class="logcat-output"></div>
            </div>`,
        appInfo: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        Application Details
                    </div>
                </div>
                <p class="panel-desc">View detailed metadata, flags, install dates, signing info, and resource usage for any installed app.</p>
                <div class="form-row">
                    <select id="appInfoSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.loadAppInfo()">Inspect</button>
                </div>
                <div id="appInfoResults"></div>
            </div>`,
        fullScan: `
            <div class="security-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                        Full Security Scan
                    </div>
                    <span class="badge warning">Comprehensive</span>
                </div>
                <p class="panel-desc">Run all security tests against a single application. Checks storage, backup, components, signing, network, permissions, and more.</p>
                <div class="form-row">
                    <select id="fullScanSelect"><option value="">Select application...</option></select>
                    <button class="btn btn-primary" onclick="app.runFullScan()">Run Full Scan</button>
                </div>
                <div id="fullScanProgress" class="hidden" style="margin-top:12px">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                        <div class="spinner-sm"></div>
                        <span id="fullScanStatus" style="color:var(--lum-60);font-size:13px">Starting...</span>
                    </div>
                    <div style="background:var(--surface-2);border-radius:4px;height:4px;overflow:hidden"><div id="fullScanBar" style="background:var(--primary);height:100%;width:0%;transition:width 0.3s"></div></div>
                </div>
                <div id="fullScanResults"></div>
            </div>`
    };

    function showToast(message, type = 'info') {
        const icons = {
            success: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>',
            error: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>',
            warning: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>',
            info: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>'
        };
        const text = String(message);
        // collapse identical toasts instead of stacking them
        for (const t of Array.from(el.toastContainer.children)) {      // copy: removing while iterating a live collection skips items
            if (t.dataset.msg === text) t.remove();
        }
        while (el.toastContainer.children.length >= 5) el.toastContainer.firstChild.remove();
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.dataset.msg = text;
        toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
        toast.innerHTML = `<svg class="toast-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">${icons[type] || icons.info}</svg><span class="toast-text"></span>`;
        toast.querySelector('.toast-text').textContent = text;
        el.toastContainer.appendChild(toast);
        setTimeout(() => toast.remove(), type === 'error' ? 8000 : 4000);
    }
    function showLoading(text = 'Loading...', subtext = '') {
        el.loadingText.textContent = text;
        el.loadingSubtext.textContent = subtext;
        el.loadingOverlay.classList.add('visible');
    }
    function hideLoading() {
        el.loadingOverlay.classList.remove('visible');
    }
    const formatSize = U.formatSize;

    /* ---------- tiny modal toolkit (replaces confirm()/prompt()) ---------- */

    function openModal({ title, body, buttons = [], wide = false }) {
        const prevFocus = document.activeElement;
        const overlay = document.createElement('div');
        overlay.className = 'ab-modal-overlay';
        overlay.innerHTML = `<div class="ab-modal${wide ? ' wide' : ''}" role="dialog" aria-modal="true" aria-label="${escapeAttr(title)}">
            <div class="ab-modal-head"><strong></strong><button class="ab-modal-x" aria-label="Close">&times;</button></div>
            <div class="ab-modal-body"></div><div class="ab-modal-foot"></div></div>`;
        overlay.querySelector('strong').textContent = title;
        const bodyEl = overlay.querySelector('.ab-modal-body');
        if (typeof body === 'string') bodyEl.textContent = body; else if (body) bodyEl.appendChild(body);
        const close = (result) => { overlay.remove(); document.removeEventListener('keydown', onKey, true); if (prevFocus && prevFocus.focus) prevFocus.focus(); return result; };
        const onKey = (e) => {
            if (e.key === 'Escape') { e.stopPropagation(); close(); if (onClose) onClose(); }
            if (e.key === 'Tab') {                       // keep focus inside the dialog
                const f = overlay.querySelectorAll('button, input, select, textarea, [tabindex]:not([tabindex="-1"])');
                if (!f.length) return;
                const first = f[0], last = f[f.length - 1];
                if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
                else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
            }
        };
        let onClose = null;
        const foot = overlay.querySelector('.ab-modal-foot');
        for (const b of buttons) {
            const btn = document.createElement('button');
            btn.className = 'btn ' + (b.danger ? 'btn-danger' : b.primary ? 'btn-primary' : 'btn-ghost');
            btn.textContent = b.label;
            btn.addEventListener('click', () => { const keep = b.onClick ? b.onClick() : undefined; if (keep !== false) close(); });
            foot.appendChild(btn);
        }
        overlay.querySelector('.ab-modal-x').addEventListener('click', () => { close(); if (onClose) onClose(); });
        overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) { close(); if (onClose) onClose(); } });
        document.addEventListener('keydown', onKey, true);
        document.body.appendChild(overlay);
        const focusTarget = overlay.querySelector('input, textarea') || foot.querySelector('.btn-primary, .btn-danger') || foot.lastElementChild || overlay.querySelector('.ab-modal-x');
        if (focusTarget) focusTarget.focus();
        return { close, el: overlay, setOnClose: (fn) => { onClose = fn; } };
    }

    function askConfirm(message, { title = 'Confirm', confirmText = 'Confirm', danger = false } = {}) {
        return new Promise((resolve) => {
            const m = openModal({ title, body: message, buttons: [
                { label: 'Cancel', onClick: () => resolve(false) },
                { label: confirmText, danger, primary: !danger, onClick: () => resolve(true) }
            ] });
            m.setOnClose(() => resolve(false));
        });
    }

    function askInput(label, { title = 'Input', value = '', confirmText = 'OK' } = {}) {
        return new Promise((resolve) => {
            const wrap = document.createElement('div');
            const lab = document.createElement('label');
            lab.textContent = label; lab.style.cssText = 'display:block;margin-bottom:8px;color:var(--lum-60);font-size:13px';
            const input = document.createElement('input');
            input.type = 'text'; input.className = 'text-input'; input.value = value; input.spellcheck = false; input.autocomplete = 'off';
            wrap.append(lab, input);
            const submit = () => { const v = input.value.trim(); resolve(v || null); };
            const m = openModal({ title, body: wrap, buttons: [
                { label: 'Cancel', onClick: () => resolve(null) },
                { label: confirmText, primary: true, onClick: () => { if (!input.value.trim()) { input.focus(); return false; } submit(); } }
            ] });
            input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && input.value.trim()) { submit(); m.close(); } });
            m.setOnClose(() => resolve(null));
        });
    }

    function showTextModal(title, subtitle, text) {
        const wrap = document.createElement('div');
        if (subtitle) {
            const sub = document.createElement('div');
            sub.textContent = subtitle; sub.style.cssText = 'font-size:11px;color:var(--lum-40);margin-bottom:8px;word-break:break-all;font-family:monospace';
            wrap.appendChild(sub);
        }
        const pre = document.createElement('pre');
        pre.className = 'ab-pre'; pre.textContent = text || '[Empty file]';
        wrap.appendChild(pre);
        return openModal({ title, body: wrap, wide: true, buttons: [
            { label: 'Copy', onClick: () => { navigator.clipboard?.writeText(text || '').then(() => showToast('Copied', 'success'), () => showToast('Copy failed', 'error')); return false; } },
            { label: 'Close', primary: true }
        ] });
    }

    function hexPreview(bytes, max = 2048) {
        const lines = [];
        for (let i = 0; i < Math.min(bytes.length, max); i += 16) {
            const row = bytes.subarray(i, i + 16);
            const hex = Array.from(row, b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47);
            const ascii = Array.from(row, b => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
            lines.push(i.toString(16).padStart(8, '0') + '  ' + hex + '  ' + ascii);
        }
        if (bytes.length > max) lines.push(`... ${bytes.length - max} more bytes`);
        return lines.join('\n');
    }

    /** Show a pulled file: text if it looks like text, otherwise a hex dump. */
    function previewBytes(name, path, bytes) {
        const sample = bytes.subarray(0, 4096);
        const binary = sample.some(b => b === 0);
        if (binary) showTextModal(name + ' (binary - hex preview)', path + ' - ' + formatSize(bytes.length), hexPreview(bytes));
        else {
            const raw = new TextDecoder().decode(bytes.subarray(0, 2 * 1024 * 1024));
            let text = raw, title = name;
            if (/\.xml$/i.test(name) && /<map[\s>]/.test(raw)) {      // SharedPreferences: show key = value first
                text = '# Parsed SharedPreferences\n' + window.SecurityAuditor.prefsToText(raw) + '\n\n# Raw XML\n' + raw;
                title = name + ' (SharedPreferences)';
            }
            const secrets = window.SecurityAuditor.scanForSecrets(window.SecurityAuditor.prefsToText(raw));
            if (secrets.length) text = `[!] Possible secrets (masked): ${secrets.map(x => `${x.type} x${x.count}`).join(', ')}\n\n` + text;
            showTextModal(title, path + ' - ' + formatSize(bytes.length), text);
        }
    }
    function setupLandingInteractivity() {
        const featureCards = document.querySelectorAll('.feature-card');
        featureCards.forEach(card => {
            card.addEventListener('mousemove', (e) => {
                const rect = card.getBoundingClientRect();
                const x = ((e.clientX - rect.left) / rect.width) * 100;
                const y = ((e.clientY - rect.top) / rect.height) * 100;
                card.style.setProperty('--mouse-x', x + '%');
                card.style.setProperty('--mouse-y', y + '%');
            });
        });
        const heroContent = document.querySelector('.hero-content');
        if (heroContent) {
            document.addEventListener('mousemove', (e) => {
                const x = (e.clientX / window.innerWidth - 0.5) * 20;
                const y = (e.clientY / window.innerHeight - 0.5) * 20;
                const glows = document.querySelectorAll('.hero-glow');
                glows.forEach((glow, i) => {
                    const factor = (i + 1) * 0.5;
                    glow.style.transform = `translate(${x * factor}px, ${y * factor}px)`;
                });
            });
        }
    }
    function navigate(section) {
        if (section !== 'overview' && !state.connected) return;
        if (section !== state.currentSection && typeof app !== 'undefined') {
            app.stopLogcat();                        // streams must not outlive their UI
            app.stopLiveScreenshot();
            if (app.shellStream) app.shellStream.stop();
        }
        state.currentSection = section;
        document.querySelectorAll('.dock-item').forEach(item => {
            item.classList.toggle('active', item.dataset.section === section);
            if (item.dataset.section === section) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
        });
        const dock = document.querySelector('.dock');
        const main = document.querySelector('.main');
        if (!state.connected && section === 'overview') {
            el.contentArea.innerHTML = templates.welcome;
            if (dock) dock.style.display = 'none';
            if (main) {
                main.style.marginLeft = 'auto';
                main.style.marginRight = 'auto';
            }
            setupLandingInteractivity();
            return;
        }
        if (dock) dock.style.display = '';
        if (main) {
            main.style.marginLeft = '';
            main.style.marginRight = '';
        }
        el.contentArea.innerHTML = templates[section] || templates.welcome;
        switch (section) {
            case 'overview': app.loadOverview(); break;
            case 'apps': setupApps(); break;
            case 'files': app.loadFiles(state.currentPath); break;
            case 'shell': setupShell(); break;
            case 'security': setupSecurity(); break;
            default: if (sectionHooks[section]) sectionHooks[section](); break;
        }
    }
    function setupApps() {
        app.loadApps();
        const dropZone = document.getElementById('dropZone');
        if (dropZone) {
            dropZone.addEventListener('dragover', e => {
                e.preventDefault();
                dropZone.classList.add('drag-over');
            });
            dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
            dropZone.addEventListener('drop', e => {
                e.preventDefault();
                dropZone.classList.remove('drag-over');
                const files = Array.from(e.dataTransfer.files).filter(f => /\.apk$/i.test(f.name));
                if (files.length) app.installApks(files);
                else showToast('Please drop a valid APK file', 'warning');
            });
            dropZone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); document.getElementById('apkInput').click(); } });
        }
        const search = document.getElementById('appSearch');
        if (search) {
            search.value = state.appFilter;
            search.addEventListener('input', U.debounce(() => app.filterApps(search.value), 120));
        }
        const toggleBtn = document.getElementById('toggleSystemApps');
        if (toggleBtn) {
            toggleBtn.setAttribute('aria-pressed', String(state.showSystemApps));
            if (state.showSystemApps) toggleBtn.classList.add('active');
            toggleBtn.addEventListener('click', () => {
                state.showSystemApps = !state.showSystemApps;
                toggleBtn.setAttribute('aria-pressed', String(state.showSystemApps));
                toggleBtn.style.background = state.showSystemApps ? 'var(--pulse-subtle)' : '';
                toggleBtn.style.color = state.showSystemApps ? 'var(--pulse)' : '';
                app.loadApps();
            });
        }
        const list = document.getElementById('appList');
        if (list) {
            list.addEventListener('click', (e) => {
                const btn = e.target.closest('[data-act]');
                if (!btn) return;
                app.appAction(btn.dataset.act, btn.dataset.pkg);
            });
        }
    }

    const SHELL_COMMANDS = ['am', 'cat', 'cd', 'chmod', 'chown', 'clear', 'cp', 'date', 'df', 'dmesg', 'du', 'dumpsys', 'echo', 'find', 'getevent', 'getprop',
        'grep', 'head', 'help', 'history', 'id', 'ifconfig', 'ip', 'logcat', 'ls', 'md5sum', 'mkdir', 'monkey', 'mv', 'netstat', 'pm', 'ps', 'pwd', 'rm',
        'screencap', 'setprop', 'settings', 'sha1sum', 'sha256sum', 'sleep', 'stat', 'tail', 'top', 'touch', 'uname', 'uptime', 'wc', 'whoami'];
    const STREAMING_RE = /^\s*(logcat|ping|getevent|dmesg\s+-w|tail\s+-[a-zA-Z]*f|top(?!\s+-n\s*1)(?!\s+-b))\b/;

    function setupShell() {
        const input = document.getElementById('shellInput');
        const prompt = document.getElementById('shellPrompt');
        const shellRootToggle = document.getElementById('shellRootToggle');
        if (state.shellHistory.length === 0) state.shellHistory = store.get('shellHistory', []);
        if (shellRootToggle) {
            shellRootToggle.checked = state.shellRootMode;
        }
        if (prompt) {
            const p = state.shellRootMode ? '#' : '$';
            prompt.textContent = state.shellCwd ? state.shellCwd + ' ' + p : p;
        }
        if (input) {
            input.addEventListener('keydown', async e => {
                if (e.key === 'Enter' && input.value.trim()) {
                    const cmd = input.value.trim();
                    input.value = '';
                    await app.executeCommand(cmd);
                    const pr = document.getElementById('shellPrompt');
                    if (pr) {
                        const ch = state.shellRootMode ? '#' : '$';
                        pr.textContent = state.shellCwd ? state.shellCwd + ' ' + ch : ch;
                    }
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    if (state.shellHistoryIndex < state.shellHistory.length - 1) {
                        state.shellHistoryIndex++;
                        input.value = state.shellHistory[state.shellHistory.length - 1 - state.shellHistoryIndex];
                    }
                } else if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    if (state.shellHistoryIndex > 0) {
                        state.shellHistoryIndex--;
                        input.value = state.shellHistory[state.shellHistory.length - 1 - state.shellHistoryIndex];
                    } else {
                        state.shellHistoryIndex = -1;
                        input.value = '';
                    }
                } else if (e.key === 'Tab') {
                    e.preventDefault();
                    app.shellComplete(input);
                } else if (e.ctrlKey && e.key.toLowerCase() === 'c') {
                    if (app.shellStream) { e.preventDefault(); app.shellStream.stop(); }
                    else if (!window.getSelection().toString()) { input.value = ''; }
                } else if (e.ctrlKey && e.key.toLowerCase() === 'l') {
                    e.preventDefault();
                    app.clearShell();
                }
            });
            input.focus();
        }
    }
    async function setupSecurity() {
        app.switchSecurityTab('localStorage');
        await loadSecurityApps();
    }
    async function loadSecurityApps() {
        const selectMap = SELECT_MAP;
        const currentSelectId = selectMap[state.currentSecurityTab];
        const currentSelect = document.getElementById(currentSelectId);
        if (currentSelect) {
            currentSelect.innerHTML = '<option value="">Loading applications...</option>';
            currentSelect.disabled = true;
        }
        try {
            state.securityApps = await adb.listPackages(false);
            Object.values(selectMap).forEach(id => populateSelect(id));
        } catch (e) {
            console.error('Failed to load apps:', e);
            state.securityApps = [];
            if (currentSelect) {
                currentSelect.innerHTML = '<option value="">Failed to load apps</option>';
            }
        }
    }
    function populateSelect(selectId) {
        const select = document.getElementById(selectId);
        if (!select) return;
        select.disabled = false;
        if (state.securityApps.length > 0) {
            select.innerHTML = `<option value="">${selectId === 'networkSelect' ? 'All apps' : 'Select application...'}</option>` +
                state.securityApps.map(p => `<option value="${escapeAttr(p)}">${escapeHtml(p)}</option>`).join('');
        } else {
            select.innerHTML = '<option value="">No applications found</option>';
        }
    }
    const app = {
        async initDeviceManager() {
            if (typeof DeviceManager === 'undefined') {
                console.warn('DeviceManager not available');
                return;
            }
            deviceManager = new DeviceManager();
            deviceManager.addEventListener((event, data) => {
                switch (event) {
                    case 'devicesChanged':
                        this.updateDeviceList(data);
                        break;
                    case 'activeDeviceDisconnected':
                        this.handleDeviceDisconnected(data);
                        break;
                    case 'deviceAdded':
                        showToast(`Device detected: ${data.displayName}`, 'info');
                        break;
                    case 'deviceRemoved':
                        if (data.serial === state.selectedDeviceSerial && state.connected) {
                            this.handleDeviceDisconnected(data);
                        }
                        break;
                }
            });
            await deviceManager.initialize();
            this.updateDeviceList(deviceManager.getDeviceList());
        },
        updateDeviceList(devices) {
            state.devices = devices || [];
            if (el.deviceSelect) {
                if (state.devices.length === 0) {
                    el.deviceSelect.innerHTML = '<option value="">No devices found</option>';
                    el.deviceSelect.disabled = true;
                } else {
                    el.deviceSelect.innerHTML = state.devices.map(d => 
                        `<option value="${escapeAttr(d.serial)}" ${d.serial === state.selectedDeviceSerial ? 'selected' : ''}>${escapeHtml(d.displayName)}</option>`
                    ).join('');
                    el.deviceSelect.disabled = false;
                    if (!state.selectedDeviceSerial && state.devices.length > 0) {
                        state.selectedDeviceSerial = state.devices[0].serial;
                    }
                }
            }
            if (el.connectBtn && !state.connected) {
                el.connectBtn.disabled = false;
            }
        },
        onDeviceSelect(serial) {
            state.selectedDeviceSerial = serial;
        },
        toggleAddMenu() {
            state.addMenuOpen = !state.addMenuOpen;
            if (el.addDeviceMenu) {
                el.addDeviceMenu.classList.toggle('show', state.addMenuOpen);
            }
        },
        closeAddMenu() {
            state.addMenuOpen = false;
            if (el.addDeviceMenu) {
                el.addDeviceMenu.classList.remove('show');
            }
        },
        async addUSBDevice() {
            this.closeAddMenu();
            try {
                const device = await deviceManager.requestUSBDevice();
                if (device) {
                    state.selectedDeviceSerial = device.serial;
                    showToast(`Device paired: ${device.displayName}`, 'success');
                }
            } catch (e) {
                if (e.message !== 'No device selected') {
                    showToast('Failed to add device: ' + e.message, 'error');
                }
            }
        },
        showWebSocketModal() {
            this.closeAddMenu();
            showToast('WebSocket connection coming soon!', 'info');
        },
        showTCPModal() {
            this.closeAddMenu();
            showToast('WebSocket connection coming soon!', 'info');
        },
        closeTCPModal() {
            state.tcpModalOpen = false;
            document.getElementById('tcpModal').classList.remove('show');
            document.getElementById('tcpIpInput').value = '';
            document.getElementById('tcpPortInput').value = '5555';
        },
        addTCPDeviceFromModal() {
            const ipInput = document.getElementById('tcpIpInput');
            const portInput = document.getElementById('tcpPortInput');
            const host = ipInput.value.trim();
            const port = parseInt(portInput.value) || 5555;
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (!ipRegex.test(host)) {
                showToast('Invalid IP address format', 'error');
                ipInput.focus();
                return;
            }
            if (port < 1 || port > 65535) {
                showToast('Invalid port number', 'error');
                portInput.focus();
                return;
            }
            deviceManager.addTCPDevice(host, port, `ADB WiFi (${host})`);
            showToast(`Device added: ${host}:${port}`, 'success');
            this.closeTCPModal();
        },
        removeDevice(serial) {
            if (confirm('Remove this device from the list?')) {
                deviceManager.removeDevice(serial);
                if (state.selectedDeviceSerial === serial) {
                    state.selectedDeviceSerial = null;
                }
                showToast('Device removed', 'info');
            }
        },
        handleDeviceDisconnected(device) {
            this.stopLogcat();
            if (state.connected) {
                state.connected = false;
                state.shellCwd = '';
                state.shellRootMode = false;
                setAmbientActive(false);
                el.connectBtn.classList.remove('hidden');
                el.disconnectBtn.classList.add('hidden');
                el.statusDot.classList.remove('active');
                el.statusText.textContent = 'Disconnected';
                el.statusPill.classList.remove('connected');
                if (el.deviceSelect) el.deviceSelect.disabled = false;
                document.querySelectorAll('.dock-item').forEach(item => {
                    if (item.dataset.section !== 'overview') item.classList.add('disabled');
                });
                navigate('overview');
                showToast('Device disconnected', 'warning');
            }
        },
        _connecting: false,
        async connect() {
            if (this._connecting || state.connected) return;      // ignore double clicks
            this._connecting = true;
            try {
                showLoading('Connecting...', 'Checking for paired devices...');
                if (typeof ADBConnection === 'undefined') {
                    throw new Error('ADB library not loaded. Refresh the page.');
                }
                adb = new ADBConnection();
                if (deviceManager) {
                    await deviceManager.refreshUSBDevices();
                    this.updateDeviceList(deviceManager.getDeviceList());
                }
                let selectedDevice = null;
                if (deviceManager && state.selectedDeviceSerial) {
                    selectedDevice = deviceManager.getDevice(state.selectedDeviceSerial);
                    
                }
                if (!selectedDevice && deviceManager) {
                    const devices = deviceManager.getDeviceList();
                    const usbDevice = devices.find(d => d.type === 'usb');
                    if (usbDevice) {
                        selectedDevice = usbDevice;
                        state.selectedDeviceSerial = usbDevice.serial;
                        if (el.deviceSelect) el.deviceSelect.value = usbDevice.serial;
                    }
                }
                if (selectedDevice && selectedDevice.type === 'usb' && selectedDevice.usbDevice) {
                    
                    showLoading('Connecting...', 'Accept USB debugging prompt on device');
                    adb.device = selectedDevice.usbDevice;
                    adb.deviceDescriptor = selectedDevice;
                    await adb.openDevice();
                    await adb.authenticate();
                } else if (selectedDevice && selectedDevice.type === 'tcp') {
                    hideLoading();
                    showToast('WebSocket connection coming soon! Please use USB connection for now.', 'info');
                    return;
                } else {
                    showLoading('Waiting...', 'Select device from browser dialog');
                    await adb.connect();
                    if (deviceManager && adb.device) {
                        await deviceManager.refreshUSBDevices();
                        this.updateDeviceList(deviceManager.getDeviceList());
                        state.selectedDeviceSerial = window.usbSerial(adb.device);
                        if (el.deviceSelect) el.deviceSelect.value = state.selectedDeviceSerial;
                    }
                }
                state.connected = true;
                activity.add('connect', [adb.device?.productName, adb.device?.serialNumber].filter(Boolean).join(' '));
                setAmbientActive(true);
                if (adb.device) {
                    state.selectedDeviceSerial = window.usbSerial(adb.device);
                }
                el.connectBtn.classList.add('hidden');
                el.disconnectBtn.classList.remove('hidden');
                el.statusDot.classList.add('active');
                el.statusText.textContent = 'Connected';
                el.statusPill.classList.add('connected');
                if (el.deviceSelect) el.deviceSelect.disabled = true;
                document.querySelectorAll('.dock-item.disabled').forEach(item => item.classList.remove('disabled'));
                adb.onDisconnect = (reason) => {
                    
                    this.handleDeviceDisconnected({ serial: state.selectedDeviceSerial });
                };
                hideLoading();
                showToast('Device connected successfully', 'success');
                navigate('overview');
            } catch (e) {
                hideLoading();
                // release the USB interface so the next attempt does not fail with "already in use"
                if (adb) { try { await adb.disconnect(); } catch (err) { /* ignore */ } }
                showToast('Connection failed: ' + (e.getUserMessage ? e.getUserMessage() : e.message), 'error');
                console.error('Connection error:', e);
            } finally {
                this._connecting = false;
            }
        },
        async disconnect() {
            activity.add('disconnect');
            this.stopLogcat();
            if (adb) {
                try { await adb.disconnect(); } catch (e) {}
                adb = null;
            }
            state.connected = false;
            state.shellCwd = '';
            state.shellRootMode = false;
            setAmbientActive(false);
            el.connectBtn.classList.remove('hidden');
            el.disconnectBtn.classList.add('hidden');
            el.statusDot.classList.remove('active');
            el.statusText.textContent = 'Disconnected';
            el.statusPill.classList.remove('connected');
            if (el.deviceSelect) el.deviceSelect.disabled = false;
            document.querySelectorAll('.dock-item').forEach(item => {
                if (item.dataset.section !== 'overview') item.classList.add('disabled');
            });
            navigate('overview');
            showToast('Device disconnected', 'info');
        },
        async loadOverview() {
            const statsGrid = document.getElementById('statsGrid');
            const propList = document.getElementById('propList');
            if (!statsGrid || !propList) return;
            try {
                const [props, apps, extra] = await Promise.all([
                    adb.getDeviceProps(),
                    adb.listPackages(false),
                    adb.shell('df /data | tail -1; echo @@; grep -E "MemTotal|MemAvailable" /proc/meminfo; echo @@; cut -d" " -f1 /proc/uptime').catch(() => '')
                ]);
                const [dfPart = '', memPart = '', upPart = ''] = extra.split('@@');
                const dfCols = dfPart.trim().split(/\s+/);
                const storagePercent = (dfCols[4] || '').replace('%', '') || '-';
                const memTotal = parseInt((memPart.match(/MemTotal:\s*(\d+)/) || [])[1], 10);
                const memAvail = parseInt((memPart.match(/MemAvailable:\s*(\d+)/) || [])[1], 10);
                const ramPercent = memTotal ? Math.round(((memTotal - memAvail) / memTotal) * 100) : '-';
                const uptimeSec = parseFloat(upPart.trim());
                const uptime = isFinite(uptimeSec) ? `${Math.floor(uptimeSec / 86400)}d ${Math.floor(uptimeSec % 86400 / 3600)}h` : '-';
                state.deviceInfo = { ...props, apps: apps.length, storagePercent, ramPercent, uptime };

                const card = (label, value, sub = '') => `
                    <div class="stat-card">
                        <div class="stat-label">${escapeHtml(label)}</div>
                        <div class="stat-value">${escapeHtml(value)}</div>${sub ? `<div class="stat-sub">${escapeHtml(sub)}</div>` : ''}
                    </div>`;
                statsGrid.innerHTML = [
                    card('Android', props.androidVersion || '-'),
                    card('SDK Level', props.sdkVersion || '-'),
                    card('User Apps', apps.length),
                    card('Storage', storagePercent + '%'),
                    card('RAM Used', ramPercent + '%', memTotal ? formatSize(memTotal * 1024) + ' total' : ''),
                    card('Battery', props.batteryLevel != null ? props.batteryLevel + '%' : '-', props.charging ? 'charging' : (props.batteryTemp != null ? props.batteryTemp + ' °C' : '')),
                    card('Uptime', uptime),
                    card('Security Patch', props.securityPatch && props.securityPatch !== 'Unknown' ? props.securityPatch : '-')
                ].join('');

                const flag = (v, bad) => (v === bad ? v + ' ⚠' : v);
                propList.innerHTML = [
                    ['Model', props.model], ['Brand', props.brand], ['Manufacturer', props.manufacturer], ['Device', props.device],
                    ['Serial', props.serial], ['CPU ABI', props.cpuAbi], ['Build ID', props.buildId], ['Build Type', flag(props.buildType, 'userdebug')],
                    ['Fingerprint', props.fingerprint], ['Bootloader Locked', flag(props.bootloaderLocked, '0')],
                    ['Verified Boot', props.verifiedBoot], ['Debuggable Build', flag(props.debuggable, '1')]
                ].map(([label, value]) => `
                    <div class="prop-item">
                        <span class="prop-label">${escapeHtml(label)}</span>
                        <span class="prop-value">${escapeHtml(value || '-')}</span>
                    </div>
                `).join('');
            } catch (e) {
                showToast('Failed to load device info: ' + e.message, 'error');
                console.error('Overview error:', e);
            }
        },
        exportDeviceInfo() {
            if (!state.deviceInfo || !state.deviceInfo.model) { showToast('Load the overview first', 'warning'); return; }
            const blob = new Blob([JSON.stringify(state.deviceInfo, null, 2)], { type: 'application/json' });
            U.downloadBlob(blob, `device_${U.safeFileName(state.deviceInfo.model)}_${U.timestampForFile()}.json`);
            showToast('Device info exported', 'success');
        },
        async loadApps() {
            const list = document.getElementById('appList');
            if (!list) return;
            list.innerHTML = '<div class="empty-state"><p>Loading...</p></div>';
            try {
                const packages = await adb.listPackages(state.showSystemApps);
                state.apps = packages.map(pkg => ({
                    package: pkg,
                    name: pkg.split('.').pop()
                })).sort((a, b) => a.name.localeCompare(b.name));
                this.filterApps(state.appFilter);
            } catch (e) {
                list.innerHTML = '<div class="empty-state"><p>Failed to load applications</p></div>';
                showToast('Failed to load apps: ' + e.message, 'error');
            }
        },
        renderApps(apps) {
            const list = document.getElementById('appList');
            if (!list) return;
            const count = document.getElementById('appCount');
            if (count) count.textContent = `${apps.length} of ${state.apps.length}`;
            if (apps.length === 0) {
                list.innerHTML = '<div class="empty-state"><p>No applications found</p></div>';
                return;
            }
            const icon = (d) => `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${d}"/></svg>`;
            const pinned = new Set(store.get('pinnedApps', []));
            apps = [...apps].sort((a, b) => (pinned.has(b.package) - pinned.has(a.package)));
            list.innerHTML = apps.map(a => `
                <div class="app-item">
                    <div class="app-icon">${escapeHtml(a.name.charAt(0).toUpperCase())}</div>
                    <div class="app-details">
                        <div class="app-name">${escapeHtml(a.name)}</div>
                        <div class="app-package">${escapeHtml(a.package)}</div>
                    </div>
                    <div class="app-actions">
                        <button class="btn btn-sm btn-ghost" data-act="pin" data-pkg="${escapeAttr(a.package)}" aria-pressed="${pinned.has(a.package)}" title="${pinned.has(a.package) ? 'Unpin' : 'Pin to top'}" aria-label="${pinned.has(a.package) ? 'Unpin' : 'Pin'} ${escapeAttr(a.package)}" style="${pinned.has(a.package) ? 'color:var(--warning)' : ''}">${icon('M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z')}</button>
                        <button class="btn btn-sm btn-ghost" data-act="audit" data-pkg="${escapeAttr(a.package)}" title="Run security scan" aria-label="Scan ${escapeAttr(a.package)}">${icon('M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z')}</button>
                        <button class="btn btn-sm btn-ghost" data-act="info" data-pkg="${escapeAttr(a.package)}" title="App info" aria-label="Info for ${escapeAttr(a.package)}">${icon('M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z')}</button>
                        <button class="btn btn-sm btn-ghost" data-act="dl" data-pkg="${escapeAttr(a.package)}" title="Download APK" aria-label="Download APK of ${escapeAttr(a.package)}">${icon('M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4')}</button>
                        <button class="btn btn-sm btn-ghost" data-act="more" data-pkg="${escapeAttr(a.package)}" title="More actions" aria-label="More actions for ${escapeAttr(a.package)}">${icon('M5 12h.01M12 12h.01M19 12h.01')}</button>
                    </div>
                </div>
            `).join('');
        },
        filterApps(query) {
            state.appFilter = query || '';
            const q = state.appFilter.toLowerCase();
            const filtered = state.apps.filter(a => a.name.toLowerCase().includes(q) || a.package.toLowerCase().includes(q));
            this.renderApps(filtered);
        },
        async appAction(act, pkg) {
            if (!U.isValidPackageName(pkg)) return;
            switch (act) {
                case 'pin': {
                    const pins = new Set(store.get('pinnedApps', []));
                    if (pins.has(pkg)) pins.delete(pkg); else pins.add(pkg);
                    store.set('pinnedApps', [...pins]);
                    return this.filterApps(state.appFilter);
                }
                case 'dl': return this.downloadApk(pkg);
                case 'audit': return this.openAudit(pkg, 'fullScan');
                case 'info': return this.openAudit(pkg, 'appInfo');
                case 'more': return this.showAppActions(pkg);
            }
        },
        async openAudit(pkg, tab) {
            navigate('security');
            this.switchSecurityTab(tab);
            await loadSecurityApps();
            const selectIds = { fullScan: 'fullScanSelect', appInfo: 'appInfoSelect' };
            const sel = document.getElementById(selectIds[tab]);
            if (sel) {
                if (![...sel.options].some(o => o.value === pkg)) sel.add(new Option(pkg, pkg));
                sel.value = pkg;
                if (tab === 'appInfo') this.loadAppInfo(); else this.runFullScan();
            }
        },
        showAppActions(pkg) {
            const run = async (label, cmd, { confirmMsg, danger } = {}) => {
                if (confirmMsg && !(await askConfirm(confirmMsg, { title: label, confirmText: label, danger }))) return;
                showLoading(label + '...', pkg);
                try {
                    const out = await adb.shell(cmd, 60000);
                    hideLoading();
                    showToast(`${label}: ${out.split('\n').filter(Boolean).pop() || 'done'}`, /Failure|Error|Exception/i.test(out) ? 'error' : 'success');
                    if (label === 'Uninstall') this.loadApps();
                } catch (e) { hideLoading(); showToast(`${label} failed: ${e.message}`, 'error'); }
            };
            openModal({ title: pkg, body: 'Choose an action for this application.', buttons: [
                { label: 'Launch', onClick: () => { run('Launch', `monkey -p ${pkg} -c android.intent.category.LAUNCHER 1`); } },
                { label: 'Force stop', onClick: () => { run('Force stop', `am force-stop ${pkg}`); } },
                { label: 'Copy name', onClick: () => { navigator.clipboard?.writeText(pkg).then(() => showToast('Copied', 'success')); } },
                { label: 'Clear data', danger: true, onClick: () => { run('Clear data', `pm clear ${pkg}`, { confirmMsg: `Delete ALL data of ${pkg}? This cannot be undone.`, danger: true }); } },
                { label: 'Uninstall', danger: true, onClick: () => { run('Uninstall', `pm uninstall ${pkg}`, { confirmMsg: `Uninstall ${pkg}?`, danger: true }); } }
            ] });
        },
        handleApkSelect(event) {
            const files = Array.from(event.target.files || []).filter(f => /\.apk$/i.test(f.name));
            event.target.value = '';
            if (files.length) this.installApks(files);
        },
        async installApk(file) { return this.installApks([file]); },
        /** Install one APK, or several (split APKs) with `pm install-multiple`. */
        async installApks(files) {
            for (const f of files) {
                if (f.size > 1024 * 1024 * 1024) { showToast(`${f.name} is too large (max 1GB)`, 'error'); return; }
            }
            const remotes = [];
            showLoading('Installing APK...', files.map(f => f.name).join(', '));
            try {
                for (let i = 0; i < files.length; i++) {
                    const bytes = new Uint8Array(await files[i].arrayBuffer());
                    if (bytes.length < 4 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) throw new Error(`${files[i].name} is not a valid APK (bad ZIP header)`);
                    const remote = `${tmpName()}.apk`;
                    remotes.push(remote);
                    await adb.pushFile(remote, bytes, 0o644, (n, total) => showLoading(`Uploading ${files[i].name}`, `${Math.round(n / total * 100)}% (${i + 1}/${files.length})`));
                }
                showLoading('Installing...', 'Please wait');
                const quoted = remotes.map(shQuote).join(' ');
                const result = await adb.shell(files.length > 1 ? `pm install-multiple -r ${quoted}` : `pm install -r ${quoted}`, 180000);
                hideLoading();
                if (result.includes('Success')) {
                    activity.add('install', files.map(f => f.name).join(', '));
                    showToast('APK installed successfully', 'success');
                    this.loadApps();
                } else {
                    const error = result.match(/Failure \[(.+?)\]/);
                    showToast('Install failed: ' + (error?.[1] || result), 'error');
                }
            } catch (e) {
                hideLoading();
                showToast('Install failed: ' + e.message, 'error');
            } finally {
                if (remotes.length) adb.shell(`rm -f ${remotes.map(shQuote).join(' ')}`).catch(() => {});
            }
        },
        async downloadApk(pkg) {
            showLoading('Downloading APK...', '0 MB');
            try {
                const paths = await adb.getApkPaths(pkg);
                if (paths.length === 1) {
                    const bytes = await adb.pullFile(paths[0], (n, total) => showLoading('Downloading APK...', total ? `${formatSize(n)} / ${formatSize(total)}` : formatSize(n)));
                    U.downloadBlob(new Blob([bytes], { type: 'application/vnd.android.package-archive' }), `${pkg}.apk`);
                    hideLoading();
                    showToast(`APK downloaded (${formatSize(bytes.length)})`, 'success');
                } else {
                    const files = [];
                    for (let i = 0; i < paths.length; i++) {
                        showLoading('Downloading split APKs...', `${i + 1}/${paths.length}`);
                        files.push({ name: paths[i].split('/').pop(), data: await adb.pullFile(paths[i]) });
                    }
                    U.downloadBlob(new Blob([U.buildZip(files)], { type: 'application/zip' }), `${pkg}_splits.zip`);
                    hideLoading();
                    showToast(`${paths.length} split APKs downloaded as ZIP`, 'success');
                }
            } catch (e) {
                hideLoading();
                showToast('Download failed: ' + e.message, 'error');
            }
        },
        async loadFiles(path) {
            path = U.normalizePath(path);
            state.currentPath = path;
            const pathBar = document.getElementById('pathBar');
            const fileList = document.getElementById('fileList');
            const rootToggle = document.getElementById('rootToggle');
            if (rootToggle) {
                rootToggle.checked = state.rootMode;
            }
            this.setupFileDragDrop();
            this.setupFileToolbar();
            if (pathBar) {
                const segments = path.split('/').filter(s => s);
                pathBar.innerHTML = `
                    <span class="path-segment root" data-path="/" role="button" tabindex="0" aria-label="Root">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:14px;height:14px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>
                    </span>
                    ${segments.map((seg, i) => {
                        const segPath = '/' + segments.slice(0, i + 1).join('/');
                        return `<span class="path-sep">/</span><span class="path-segment" role="button" tabindex="0" data-path="${escapeAttr(segPath)}">${escapeHtml(seg)}</span>`;
                    }).join('')}
                `;
                pathBar.querySelectorAll('.path-segment').forEach(seg => {
                    seg.onclick = () => this.loadFiles(seg.dataset.path);
                    seg.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); this.loadFiles(seg.dataset.path); } };
                });
            }
            if (!fileList) return;
            const token = ++this._filesToken;
            fileList.innerHTML = '<div class="empty-state"><p>Loading...</p></div>';
            try {
                const lsCmd = `ls -la ${shQuote(path)} 2>&1`;
                const output = await adb.shell(state.rootMode ? U.suWrap(lsCmd) : lsCmd);
                if (token !== this._filesToken) return;           // a newer navigation superseded this one
                state.files = output.split('\n').map(U.parseLsLine).filter(Boolean).map(e => ({
                    name: e.name, size: e.size, isDir: e.isDir, isLink: e.isLink, perms: e.perms, date: e.date, owner: e.owner, target: e.target
                }));
                if (state.files.length === 0 && /denied|not permitted/i.test(output)) throw new Error('denied');
                if (state.files.length === 0 && /No such file|not found/i.test(output)) throw new Error('missing');
                this.renderFileList();
            } catch (e) {
                if (token !== this._filesToken) return;
                const errorMsg = e.message === 'missing' ? 'Directory does not exist'
                    : state.rootMode ? 'Cannot access (device may not be rooted)' : 'Cannot access directory (permission denied - try Root mode)';
                fileList.innerHTML = `
                    <div class="empty-state">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:48px;height:48px;color:var(--alert);margin-bottom:12px;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <p>${escapeHtml(errorMsg)}</p>
                    </div>`;
            }
        },
        _filesToken: 0,
        renderFileList() {
            const fileList = document.getElementById('fileList');
            if (!fileList) return;
            const q = state.fileFilter.toLowerCase();
            const { key, dir } = state.fileSort;
            const rows = state.files.map((f, idx) => ({ f, idx })).filter(({ f }) => !q || f.name.toLowerCase().includes(q));
            rows.sort((a, b) => {
                if (a.f.isDir !== b.f.isDir) return a.f.isDir ? -1 : 1;
                const av = a.f[key], bv = b.f[key];
                const c = typeof av === 'number' ? av - bv : String(av).localeCompare(String(bv), undefined, { numeric: true });
                return c * dir;
            });
            const counter = document.getElementById('fileCount');
            if (counter) counter.textContent = `${rows.length} item${rows.length === 1 ? '' : 's'}`;
            if (rows.length === 0) {
                fileList.innerHTML = `
                    <div class="empty-state">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:48px;height:48px;color:var(--lum-30);margin-bottom:12px;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                        </svg>
                        <p>${q ? 'No matching files' : 'Empty directory'}</p>
                    </div>`;
                return;
            }
            const ico = (d) => `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${d}"/></svg>`;
            fileList.innerHTML = rows.map(({ f, idx }) => `
                <div class="file-item" data-index="${idx}" role="listitem">
                    <div class="file-info">
                        <div class="file-icon ${f.isDir ? 'folder' : ''}">
                            ${f.isDir
                                ? ico('M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z')
                                : ico('M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z')}
                        </div>
                        <span class="file-name">${escapeHtml(f.name)}${f.target ? `<span class="file-link"> &rarr; ${escapeHtml(f.target)}</span>` : ''}</span>
                    </div>
                    <span class="file-size">${f.isDir ? '-' : escapeHtml(formatSize(f.size))}</span>
                    <span class="file-perms" title="${escapeAttr(f.owner || '')} ${escapeAttr(f.date || '')}">${escapeHtml(f.perms.substring(0, 10))}</span>
                    <div class="file-actions">
                        ${!f.isDir ? `<button class="file-action-btn" data-act="view" title="Preview" aria-label="Preview ${escapeAttr(f.name)}">${ico('M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z')}</button>
                        <button class="file-action-btn" data-act="download" title="Download" aria-label="Download ${escapeAttr(f.name)}">${ico('M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4')}</button>` : ''}
 <button class="file-action-btn" data-act="more" title="More actions" aria-label="More actions for ${escapeAttr(f.name)}">${ico('M5 12h.01M12 12h.01M19 12h.01')}</button>
                        <button class="file-action-btn" data-act="rename" title="Rename" aria-label="Rename ${escapeAttr(f.name)}">${ico('M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z')}</button>
                        <button class="file-action-btn danger" data-act="delete" title="Delete" aria-label="Delete ${escapeAttr(f.name)}">${ico('M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16')}</button>
                    </div>
                </div>
            `).join('');
            fileList.onclick = (e) => this.onFileListClick(e);
        },
        async onFileListClick(e) {
            const item = e.target.closest('.file-item');
            if (!item) return;
            const file = state.files[parseInt(item.dataset.index, 10)];
            if (!file) return;
            const fullPath = U.joinPath(state.currentPath, file.name);
            const act = e.target.closest('[data-act]')?.dataset.act;
            if (act === 'view') return this.viewFile(fullPath);
            if (act === 'download') return this.downloadFile(fullPath);
            if (act === 'more') return this.showFileActions(fullPath, file);
            if (act === 'rename') return this.renameFile(fullPath, file);
            if (act === 'delete') return this.deleteFile(fullPath, file);
            let isDir = file.isDir;
            if (file.isLink) {
                try {
                    const probe = `[ -d ${shQuote(fullPath)} ] && echo d || echo f`;
                    isDir = (await adb.shell(state.rootMode ? U.suWrap(probe) : probe)).trim() === 'd';
                } catch (err) { isDir = false; }
            }
            if (isDir) this.loadFiles(fullPath); else this.downloadFile(fullPath);
        },
        setupFileToolbar() {
            const filter = document.getElementById('fileFilter');
            if (filter && !filter.dataset.init) {
                filter.dataset.init = '1';
                filter.value = state.fileFilter;
                filter.addEventListener('input', U.debounce(() => { state.fileFilter = filter.value; this.renderFileList(); }, 100));
            }
            const sort = document.getElementById('fileSort');
            if (sort && !sort.dataset.init) {
                sort.dataset.init = '1';
                sort.value = state.fileSort.key + ':' + state.fileSort.dir;
                sort.addEventListener('change', () => {
                    const [k, d] = sort.value.split(':');
                    state.fileSort = { key: k, dir: parseInt(d, 10) };
                    this.renderFileList();
                });
            }
            const marks = document.getElementById('fileBookmarks');
            if (marks && !marks.dataset.init) {
                marks.dataset.init = '1';
                marks.addEventListener('click', (e) => {
                    const b = e.target.closest('[data-path]');
                    if (b) this.loadFiles(b.dataset.path);
                });
            }
        },
        async asShell(cmd) {
            const out = await adb.shell(state.rootMode ? U.suWrap(cmd) + ' 2>&1' : cmd + ' 2>&1');
            if (/denied|not permitted|Read-only|No such file|cannot/i.test(out)) throw new Error(out.split('\n')[0]);
            return out;
        },
        async makeDirectory() {
            const name = await askInput('Folder name', { title: 'New folder', confirmText: 'Create' });
            if (!name) return;
            if (/[\/\x00]/.test(name)) { showToast('Folder name cannot contain "/"', 'error'); return; }
            try {
                await this.asShell(`mkdir -p ${shQuote(U.joinPath(state.currentPath, name))}`);
                showToast('Folder created', 'success');
                this.loadFiles(state.currentPath);
            } catch (e) { showToast('Create failed: ' + e.message, 'error'); }
        },
        async renameFile(fullPath, file) {
            const name = await askInput('New name', { title: 'Rename', value: file.name, confirmText: 'Rename' });
            if (!name || name === file.name) return;
            if (/[\/\x00]/.test(name)) { showToast('Name cannot contain "/"', 'error'); return; }
            try {
                await this.asShell(`mv ${shQuote(fullPath)} ${shQuote(U.joinPath(state.currentPath, name))}`);
                activity.add('rename', `${fullPath} -> ${name}`);
                showToast('Renamed', 'success');
                this.loadFiles(state.currentPath);
            } catch (e) { showToast('Rename failed: ' + e.message, 'error'); }
        },
        async deleteFile(fullPath, file) {
            const ok = await askConfirm(`Delete ${file.isDir ? 'folder' : 'file'} "${file.name}"${file.isDir ? ' and everything inside it' : ''}? This cannot be undone.`, { title: 'Delete', confirmText: 'Delete', danger: true });
            if (!ok) return;
            try {
                await this.asShell(`rm -${file.isDir ? 'rf' : 'f'} ${shQuote(fullPath)}`);
                activity.add('delete', fullPath);
                showToast('Deleted', 'success');
                this.loadFiles(state.currentPath);
            } catch (e) { showToast('Delete failed: ' + e.message, 'error'); }
        },
        /** Run a command as the file browser would (root when Root mode is on); returns raw output. */
        shellMaybeRoot(cmd, timeout) {
            return adb.shell(state.rootMode ? U.suWrap(cmd) : cmd, timeout);
        },
        showFileActions(fullPath, file) {
            const isDb = /\.(db|sqlite3?|db3)$/i.test(file.name), isApk = /\.apk$/i.test(file.name);
            const buttons = [];
            if (!file.isDir) {
                buttons.push({ label: 'Checksums', onClick: () => { this.showChecksums(fullPath); } });
                buttons.push({ label: 'Edit as text', onClick: () => { this.editFile(fullPath, file); } });
                if (isDb) buttons.push({ label: 'Open in DB viewer', primary: true, onClick: () => { window.__AB.openDatabase(fullPath); } });
                if (isApk) buttons.push({ label: 'Analyze APK', primary: true, onClick: () => { window.__AB.analyzeDevicePath(fullPath); } });
            } else buttons.push({ label: 'Download as ZIP', primary: true, onClick: () => { this.downloadFolderZip(fullPath); } });
            buttons.push({ label: 'File info', onClick: () => { this.showStat(fullPath); } });
            buttons.push({ label: 'Copy path', onClick: () => { navigator.clipboard?.writeText(fullPath).then(() => showToast('Copied', 'success')); } });
            openModal({ title: file.name, body: fullPath, buttons });
        },
        async showStat(path) {
            try { showTextModal('File info', path, await this.shellMaybeRoot(`stat ${shQuote(path)} 2>&1`)); } catch (e) { showToast(e.message, 'error'); }
        },
        async showChecksums(path) {
            showLoading('Hashing...', path.split('/').pop());
            try {
                const out = [];
                for (const tool of ['md5sum', 'sha1sum', 'sha256sum']) out.push(await this.shellMaybeRoot(`${tool} ${shQuote(path)} 2>&1`, 120000));
                hideLoading();
                activity.add('checksum', path);
                showTextModal('Checksums', path, out.join('\n'));
            } catch (e) { hideLoading(); showToast('Hashing failed: ' + e.message, 'error'); }
        },
        async downloadFolderZip(dir) {
            const MAX_FILES = 2000, MAX_TOTAL = 300 * 1024 * 1024, MAX_ONE = 100 * 1024 * 1024;
            showLoading('Collecting files...', dir);
            try {
                const listing = await this.shellMaybeRoot(`find ${shQuote(dir)} -type f 2>/dev/null | head -${MAX_FILES + 1}`, 120000);
                const paths = listing.split('\n').map(x => x.trim()).filter(x => x.startsWith('/'));
                if (!paths.length) { hideLoading(); showToast('No readable files in this folder', 'warning'); return; }
                const truncated = paths.length > MAX_FILES;
                const files = []; let total = 0, skipped = 0;
                const prefix = dir.replace(/\/$/, '') + '/';
                for (let i = 0; i < Math.min(paths.length, MAX_FILES); i++) {
                    showLoading('Zipping...', `${i + 1}/${Math.min(paths.length, MAX_FILES)} - ${paths[i].split('/').pop()}`);
                    try {
                        const bytes = await readDeviceFile(paths[i]);
                        if (bytes.length > MAX_ONE || total + bytes.length > MAX_TOTAL) { skipped++; continue; }
                        total += bytes.length;
                        files.push({ name: paths[i].startsWith(prefix) ? paths[i].slice(prefix.length) : paths[i].replace(/^\//, ''), data: bytes });
                    } catch (e) { skipped++; }
                }
                if (!files.length) { hideLoading(); showToast('Nothing could be read from this folder', 'error'); return; }
                U.downloadBlob(new Blob([U.buildZip(files)], { type: 'application/zip' }), `${U.safeFileName(dir.split('/').pop() || 'root')}.zip`);
                activity.add('download-folder', `${dir} (${files.length} files)`);
                hideLoading();
                showToast(`ZIP saved: ${files.length} files${skipped ? `, ${skipped} skipped` : ''}${truncated ? ` (first ${MAX_FILES} only)` : ''}`, skipped || truncated ? 'warning' : 'success');
            } catch (e) { hideLoading(); showToast('ZIP failed: ' + e.message, 'error'); }
        },
        async editFile(path, file) {
            const size = state.rootMode ? 0 : (await adb.statFile(path).catch(() => ({ size: 0 }))).size;
            if (size > 1024 * 1024) { showToast('Files over 1 MB cannot be edited here', 'warning'); return; }
            showLoading('Loading...', file.name);
            let bytes;
            try { bytes = await readDeviceFile(path); } catch (e) { hideLoading(); showToast('Cannot read file: ' + e.message, 'error'); return; }
            hideLoading();
            if (bytes.subarray(0, 4096).some(b => b === 0)) { showToast('This looks like a binary file - not opening the text editor', 'warning'); return; }
            const ta = document.createElement('textarea');
            ta.className = 'text-input'; ta.style.cssText = 'width:100%;min-height:50vh;font-family:monospace;font-size:12px'; ta.spellcheck = false;
            ta.value = new TextDecoder().decode(bytes);
            openModal({ title: 'Edit ' + file.name, body: ta, wide: true, buttons: [
                { label: 'Cancel' },
                { label: 'Save to device', primary: true, onClick: () => {
                    askConfirm(`Overwrite ${path} on the device?`, { title: 'Save file', confirmText: 'Overwrite', danger: true }).then(async (ok) => {
                        if (!ok) return;
                        try {
                            const data = new TextEncoder().encode(ta.value);
                            if (state.rootMode) await pushAsRoot(path, data); else await adb.pushFile(path, data, 0o644);
                            activity.add('edit-file', path);
                            showToast('Saved', 'success');
                        } catch (e) { showToast('Save failed: ' + e.message, 'error'); }
                    });
                } }] });
        },
        async searchFiles() {
            const pat = await askInput(`Find files whose name contains... (searches inside ${state.currentPath})`, { title: 'Search subfolders', confirmText: 'Search' });
            if (!pat) return;
            showLoading('Searching...', pat);
            try {
                const out = await this.shellMaybeRoot(`find ${shQuote(state.currentPath)} -iname ${shQuote('*' + pat + '*')} 2>/dev/null | head -301`, 120000);
                hideLoading();
                const hits = out.split('\n').map(x => x.trim()).filter(x => x.startsWith('/'));
                const list = document.createElement('div');
                list.style.cssText = 'display:grid;gap:4px';
                if (!hits.length) list.textContent = 'No matches';
                for (const h of hits.slice(0, 300)) {
                    const b = document.createElement('button');
                    b.className = 'btn btn-ghost btn-sm'; b.style.cssText = 'justify-content:flex-start;text-align:left;font-family:monospace;font-size:12px;word-break:break-all;white-space:normal';
                    b.textContent = h;
                    b.addEventListener('click', () => { m.close(); this.loadFiles(h.slice(0, h.lastIndexOf('/')) || '/'); });
                    list.appendChild(b);
                }
                const m = openModal({ title: `${Math.min(hits.length, 300)}${hits.length > 300 ? '+' : ''} match(es) for "${pat}"`, body: list, wide: true, buttons: [{ label: 'Close', primary: true }] });
            } catch (e) { hideLoading(); showToast('Search failed: ' + e.message, 'error'); }
        },
        async viewFile(path) {
            const name = path.split('/').pop();
            showLoading('Loading file...', name);
            try {
                const size = state.rootMode ? 0 : (await adb.statFile(path).catch(() => ({ size: 0 }))).size;
                if (size > 5 * 1024 * 1024) { hideLoading(); showToast('File is larger than 5 MB - download it instead', 'warning'); return; }
                const bytes = await readDeviceFile(path);
                hideLoading();
                previewBytes(name, path, bytes);
            } catch (e) { hideLoading(); showToast('Cannot read file: ' + e.message, 'error'); }
        },
        setupFileDragDrop() {
            const dropZone = document.getElementById('fileDropZone');
            if (!dropZone || dropZone.dataset.initialized) return;
            dropZone.dataset.initialized = 'true';
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                });
            });
            ['dragenter', 'dragover'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => {
                    dropZone.classList.add('drag-active');
                });
            });
            ['dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => {
                    dropZone.classList.remove('drag-active');
                });
            });
            dropZone.addEventListener('drop', (e) => {
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    Array.from(files).forEach(file => this.uploadFile(file));
                }
            });
        },
        async toggleRootMode() {
            const wasOn = state.rootMode;
            const toggle = document.getElementById('rootToggle');
            if (!wasOn) {
                showLoading('Checking root access...', 'Grant the superuser prompt on the device if it appears');
                let ok = false;
                try { ok = /uid=0/.test(await adb.shell(U.suWrap('id') + ' 2>&1', 15000)); } catch (e) { ok = false; }
                hideLoading();
                if (!ok) {
                    showToast('Root access is not available on this device', 'error');
                    if (toggle) toggle.checked = false;
                    return;
                }
            }
            state.rootMode = !wasOn;
            showToast(state.rootMode ? 'Root mode enabled' : 'Root mode disabled', 'info');
            this.loadFiles(state.currentPath);
        },
        navigateUp() {
            const parts = state.currentPath.split('/').filter(s => s);
            if (parts.length > 0) {
                parts.pop();
                this.loadFiles('/' + parts.join('/'));
            }
        },
        refreshFiles() {
            this.loadFiles(state.currentPath);
        },
        async downloadFile(path) {
            const fileName = path.split('/').pop();
            showLoading('Downloading...', fileName);
            try {
                if (!state.rootMode) {
                    const st = await adb.statFile(path).catch(() => null);
                    if (st && st.size > 512 * 1024 * 1024) {
                        hideLoading();
                        if (!(await askConfirm(`${fileName} is ${formatSize(st.size)}. It will be held in browser memory - continue?`, { title: 'Large file', confirmText: 'Download' }))) return;
                        showLoading('Downloading...', fileName);
                    }
                }
                const bytes = await readDeviceFile(path, (n, total) => showLoading('Downloading...', total ? `${fileName} - ${formatSize(n)} / ${formatSize(total)}` : `${fileName} - ${formatSize(n)}`));
                U.downloadBlob(new Blob([bytes]), fileName);
                activity.add('download', path);
                hideLoading();
                showToast(`Downloaded: ${fileName} (${formatSize(bytes.length)})`, 'success');
            } catch (e) {
                hideLoading();
                showToast('Download failed: ' + e.message, 'error');
            }
        },
        handleFileUpload(event) {
            const files = event.target.files;
            if (!files || files.length === 0) return;
            this.uploadFiles(Array.from(files));
            event.target.value = '';
        },
        async uploadFiles(files) {
            for (const f of files) await this.uploadFile(f, true);
            this.loadFiles(state.currentPath);
        },
        async uploadFile(file, skipReload = false) {
            const destPath = U.joinPath(state.currentPath, file.name);
            showLoading('Uploading...', file.name);
            try {
                const bytes = new Uint8Array(await file.arrayBuffer());
                const progress = (n, total) => showLoading('Uploading...', `${file.name} - ${Math.round(n / total * 100)}%`);
                if (state.rootMode) await pushAsRoot(destPath, bytes, progress);
                else await adb.pushFile(destPath, bytes, 0o644, progress);
                hideLoading();
                activity.add('upload', destPath);
                showToast(`Uploaded: ${file.name}`, 'success');
                if (!skipReload) this.loadFiles(state.currentPath);
            } catch (e) {
                hideLoading();
                let errMsg = 'Upload failed: ' + e.message;
                if (/not permitted|Permission denied|Read-only/i.test(e.message)) {
                    errMsg += '. Try enabling Root Mode toggle above to write to system directories.';
                }
                showToast(errMsg, 'error');
            }
        },
        async captureScreenshot(silent = false) {
            if (!silent) showLoading('Capturing...');
            try {
                const blob = await adb.takeScreenshot();
                state.screenshotBlob = blob;
                if (state.screenshotUrl) URL.revokeObjectURL(state.screenshotUrl);
                state.screenshotUrl = URL.createObjectURL(blob);
                const area = document.getElementById('screenshotArea');
                if (!area) return;
                area.innerHTML = `<img class="screenshot-preview" alt="Device screenshot">`;
                area.querySelector('img').src = state.screenshotUrl;
                for (const id of ['saveScreenshotBtn', 'copyScreenshotBtn']) {
                    const b = document.getElementById(id); if (b) b.disabled = false;
                }
                if (!silent) { hideLoading(); showToast('Screenshot captured', 'success'); }
            } catch (e) {
                hideLoading();
                this.stopLiveScreenshot();
                showToast('Capture failed: ' + e.message, 'error');
            }
        },
        liveTimer: null,
        toggleLiveScreenshot() {
            if (this.liveTimer) { this.stopLiveScreenshot(); return; }
            const btn = document.getElementById('liveScreenshotBtn');
            if (btn) { btn.classList.add('active'); btn.setAttribute('aria-pressed', 'true'); }
            let busy = false;
            const tick = async () => {
                if (busy || !document.getElementById('screenshotArea')) { if (!document.getElementById('screenshotArea')) this.stopLiveScreenshot(); return; }
                busy = true;
                try { await this.captureScreenshot(true); } finally { busy = false; }
            };
            tick();
            this.liveTimer = setInterval(tick, 1500);
        },
        stopLiveScreenshot() {
            if (this.liveTimer) { clearInterval(this.liveTimer); this.liveTimer = null; }
            const btn = document.getElementById('liveScreenshotBtn');
            if (btn) { btn.classList.remove('active'); btn.setAttribute('aria-pressed', 'false'); }
        },
        async copyScreenshot() {
            if (!state.screenshotBlob) return;
            try {
                await navigator.clipboard.write([new ClipboardItem({ 'image/png': state.screenshotBlob })]);
                showToast('Screenshot copied to clipboard', 'success');
            } catch (e) { showToast('Clipboard copy is not available in this browser', 'error'); }
        },
        saveScreenshot() {
            if (state.screenshotBlob) {
                U.downloadBlob(state.screenshotBlob, `screenshot_${U.safeFileName(state.deviceInfo.model || 'device')}_${U.timestampForFile()}.png`);
                showToast('Screenshot saved', 'success');
            }
        },
        shellStream: null,
        shellLines: 0,
        appendShell(kind, text) {
            const output = document.getElementById('shellOutput');
            if (!output) return null;
            const div = document.createElement('div');
            div.className = kind;
            div.textContent = text;
            output.appendChild(div);
            // keep the DOM bounded
            if (++this.shellLines > 2000) { output.firstChild?.remove(); this.shellLines--; }
            output.scrollTop = output.scrollHeight;
            return div;
        },
        async shellComplete(input) {
            const value = input.value;
            const m = /(^|\s)([^\s]*)$/.exec(value);
            const word = m ? m[2] : '';
            const isFirst = !/\s/.test(value.trimStart());
            let matches = [];
            if (isFirst) {
                matches = SHELL_COMMANDS.filter(c => c.startsWith(word));
            } else if (/^[\w./@+-]*$/.test(word)) {
                const dir = word.includes('/') ? word.slice(0, word.lastIndexOf('/') + 1) : '';
                const base = word.slice(dir.length);
                const cwd = dir.startsWith('/') ? '' : (state.shellCwd ? `cd ${shQuote(state.shellCwd)} && ` : '');
                const target = dir ? shQuote(dir) : '.';
                try {
                    const out = await adb.shell(`${cwd}ls -1p ${target} 2>/dev/null | head -200`, 5000);
                    matches = out.split('\n').filter(n => n && n.startsWith(base)).map(n => dir + n);
                } catch (e) { matches = []; }
            }
            if (matches.length === 1) {
                input.value = value.slice(0, value.length - word.length) + matches[0] + (matches[0].endsWith('/') ? '' : ' ');
            } else if (matches.length > 1) {
                let common = matches[0];
                for (const mm of matches) { while (!mm.startsWith(common)) common = common.slice(0, -1); }
                if (common.length > word.length) input.value = value.slice(0, value.length - word.length) + common;
                else this.appendShell('shell-result', matches.slice(0, 60).join('  '));
            }
        },
        async executeCommand(cmd) {
            const input = document.getElementById('shellInput');
            state.shellHistory.push(cmd);
            if (state.shellHistory.length > 200) state.shellHistory.shift();
            store.set('shellHistory', state.shellHistory.slice(-50));
            state.shellHistoryIndex = -1;
            const promptChar = state.shellRootMode ? '#' : '$';
            const line = this.appendShell('shell-line', '');
            if (line) {
                const pr = document.createElement('span');
                pr.className = 'shell-prompt'; pr.textContent = promptChar + ' ';
                line.append(pr, document.createTextNode(cmd));
            }
            const done = () => { const o = document.getElementById('shellOutput'); if (o) o.scrollTop = o.scrollHeight; if (input) input.focus(); };
            if (cmd === 'clear') { this.clearShell(); done(); return; }
            if (cmd === 'history') { this.appendShell('shell-result', state.shellHistory.map((h, i) => `${String(i + 1).padStart(4)}  ${h}`).join('\n')); done(); return; }
            if (cmd === 'help') {
                const rootNote = state.shellRootMode ? ' (root mode active - commands run via su)' : '';
                this.appendShell('shell-result', `Built-ins: clear, history, help, cd\nTab completes commands and paths; Up/Down browse history; Ctrl+C stops streaming commands (logcat, ping, getevent...); Ctrl+L clears.\nAny other command runs on the device shell${rootNote}.`);
                done(); return;
            }
            const isAlreadySu = /^\s*su\b/.test(cmd);
            const useRoot = state.shellRootMode && !isAlreadySu;
            const wrapRoot = (shellCmd) => (useRoot ? U.suWrap(shellCmd) : shellCmd);
            const cwdPrefix = state.shellCwd ? `cd ${shQuote(state.shellCwd)} && ` : '';
            try {
                activity.add('shell', cmd);
            const cdMatch = cmd.match(/^\s*cd(?:\s+(.*))?$/);
                if (cdMatch) {
                    const target = (cdMatch[1] || '').trim().replace(/^(["'])(.*)\1$/, '$2');
                    let resolveCmd;
                    if (target === '~' || target === '') resolveCmd = useRoot ? 'echo /' : 'echo /storage/emulated/0';
                    else if (target.startsWith('/')) resolveCmd = `cd ${shQuote(target)} 2>&1 && pwd`;
                    else resolveCmd = `${cwdPrefix}cd ${shQuote(target)} 2>&1 && pwd`;
                    const trimmed = (await adb.shell(wrapRoot(resolveCmd))).trim();
                    if (trimmed.startsWith('/')) {
                        state.shellCwd = trimmed.split('\n').pop();
                        this.appendShell('shell-result', state.shellCwd);
                    } else {
                        this.appendShell('shell-error', trimmed || 'No such directory');
                    }
                } else if (STREAMING_RE.test(cmd)) {
                    const base = isAlreadySu ? cmd : wrapRoot(cwdPrefix + cmd);
                    const target = this.appendShell('shell-result', '');
                    let buffered = '';
                    this.shellStream = await adb.streamShell(base, (text) => {
                        buffered += text;
                        if (buffered.length > 200000) buffered = buffered.slice(-100000);
                        if (target) { target.textContent = buffered; const o = document.getElementById('shellOutput'); if (o) o.scrollTop = o.scrollHeight; }
                    });
                    this.appendShell('shell-line', '(streaming - press Ctrl+C to stop)').style.color = 'var(--lum-50)';
                    try { await this.shellStream.done; } finally { this.shellStream = null; }
                } else {
                    const full = isAlreadySu ? (state.shellCwd ? `cd ${shQuote(state.shellCwd)} 2>/dev/null; ${cmd}` : cmd) : wrapRoot(cwdPrefix + cmd);
                    const result = await adb.shell(full, 120000);
                    if (result) this.appendShell('shell-result', result);
                }
            } catch (e) {
                this.appendShell('shell-error', 'Error: ' + e.message);
            }
            done();
        },
        toggleShellRoot() {
            state.shellRootMode = !state.shellRootMode;
            const prompt = document.getElementById('shellPrompt');
            const ch = state.shellRootMode ? '#' : '$';
            if (prompt) {
                prompt.textContent = state.shellCwd ? state.shellCwd + ' ' + ch : ch;
            }
            const note = this.appendShell('shell-line', state.shellRootMode ? 'Root mode enabled - commands will run via su' : 'Root mode disabled');
            if (note) note.style.color = state.shellRootMode ? 'var(--warning)' : 'var(--lum-50)';
            showToast(state.shellRootMode ? 'Shell root mode enabled' : 'Shell root mode disabled', 'info');
        },
        clearShell() {
            const output = document.getElementById('shellOutput');
            if (output) output.innerHTML = '';
            this.shellLines = 0;
        },
        downloadShellTranscript() {
            const output = document.getElementById('shellOutput');
            if (!output || !output.textContent.trim()) { showToast('Nothing to save', 'warning'); return; }
            const text = Array.from(output.children).map(c => c.textContent).join('\n');
            U.downloadBlob(new Blob([text], { type: 'text/plain' }), `shell_${U.timestampForFile()}.txt`);
        },
        switchSecurityTab(tab) {
            if (tab !== 'logcat') this.stopLogcat();
            state.currentSecurityTab = tab;
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.tab === tab);
                btn.setAttribute('role', 'tab');
                btn.setAttribute('aria-selected', String(btn.dataset.tab === tab));
            });
            const content = document.getElementById('securityTabContent');
            if (content) {
                content.innerHTML = securityTabs[tab] || '';
                const selectMap = SELECT_MAP;
                const selectId = selectMap[tab];
                if (selectId) {
                    const select = document.getElementById(selectId);
                    if (select) {
                        if (state.securityApps && state.securityApps.length > 0) {
                            populateSelect(selectId);
                        } else {
                            select.innerHTML = '<option value="">Loading applications...</option>';
                            select.disabled = true;
                        }
                    }
                }
            }
        },
        logcatStream: null,
        logcatPaused: false,
        logcatPending: [],
        logcatTimer: null,
        get logcatRunning() { return !!this.logcatStream; },
        async startLogcat() {
            if (this.logcatStream) return;
            const raw = document.getElementById('logcatFilter')?.value.trim() || '';
            const minLevel = document.getElementById('logcatLevel')?.value || 'V';
            const output = document.getElementById('logcatOutput');
            const startBtn = document.getElementById('logcatStartBtn');
            const stopBtn = document.getElementById('logcatStopBtn');
            const status = document.getElementById('logcatStatus');
            if (!output) return;
            // filter: plain text (case-insensitive) or /regex/
            let matcher = null;
            const rx = raw.match(/^\/(.+)\/([a-z]*)$/);
            try {
                if (rx) { const re = new RegExp(rx[1], rx[2].includes('i') ? rx[2] : rx[2] + 'i'); matcher = (l) => re.test(l); }
                else if (raw) { const low = raw.toLowerCase(); matcher = (l) => l.toLowerCase().includes(low); }
            } catch (e) { showToast('Invalid regular expression', 'error'); return; }
            const order = 'VDIWEF';
            this.logcatPaused = false;
            this.logcatPending = [];
            output.innerHTML = '';
            startBtn.classList.add('hidden');
            stopBtn.classList.remove('hidden');
            status.textContent = 'Running';
            status.className = 'badge success';
            let partial = '';
            const flush = () => {
                if (this.logcatPaused || !this.logcatPending.length) return;
                const near = output.scrollHeight - output.scrollTop - output.clientHeight < 40;
                const frag = document.createDocumentFragment();
                for (const line of this.logcatPending.splice(0)) {
                    const div = document.createElement('div');
                    const lvl = this.getLogLevel(line);
                    div.className = 'logcat-line ' + lvl;
                    div.textContent = line;
                    frag.appendChild(div);
                }
                output.appendChild(frag);
                while (output.childElementCount > 5000) output.firstChild.remove();
                if (near) output.scrollTop = output.scrollHeight;
            };
            this.logcatTimer = setInterval(flush, 120);
            try {
                this.logcatStream = await adb.streamShell('logcat -v threadtime -T 100', (text) => {
                    partial += text;
                    const lines = partial.split('\n');
                    partial = lines.pop();
                    for (const line of lines) {
                        if (!line.trim()) continue;
                        const lvl = this.getLogLevel(line);
                        if (lvl && minLevel !== 'V' && order.indexOf(({ verbose: 'V', debug: 'D', info: 'I', warn: 'W', error: 'E', fatal: 'F' })[lvl]) < order.indexOf(minLevel)) continue;
                        if (matcher && !matcher(line)) continue;
                        this.logcatPending.push(line);
                        if (this.logcatPending.length > 20000) this.logcatPending.splice(0, 10000);
                    }
                });
                this.logcatStream.done.catch(() => {}).finally(() => this.stopLogcat());
            } catch (e) {
                this.stopLogcat();
                showToast('Logcat failed: ' + e.message, 'error');
            }
        },
        stopLogcat() {
            const stream = this.logcatStream;
            this.logcatStream = null;
            if (stream) stream.stop().catch(() => {});
            if (this.logcatTimer) { clearInterval(this.logcatTimer); this.logcatTimer = null; }
            const startBtn = document.getElementById('logcatStartBtn');
            const stopBtn = document.getElementById('logcatStopBtn');
            const status = document.getElementById('logcatStatus');
            if (startBtn) startBtn.classList.remove('hidden');
            if (stopBtn) stopBtn.classList.add('hidden');
            if (status) {
                status.textContent = 'Stopped';
                status.className = 'badge';
            }
        },
        toggleLogcatPause() {
            this.logcatPaused = !this.logcatPaused;
            const btn = document.getElementById('logcatPauseBtn');
            if (btn) btn.textContent = this.logcatPaused ? 'Resume' : 'Pause';
            const status = document.getElementById('logcatStatus');
            if (status && this.logcatRunning) { status.textContent = this.logcatPaused ? 'Paused' : 'Running'; }
        },
        toggleLogcatWrap() {
            const out = document.getElementById('logcatOutput');
            if (out) out.classList.toggle('nowrap');
        },
        clearLogcat() {
            const output = document.getElementById('logcatOutput');
            if (output) output.innerHTML = '';
            this.logcatPending = [];
        },
        downloadLogcat() {
            const output = document.getElementById('logcatOutput');
            if (!output || !output.textContent.trim()) {
                showToast('No logs to download', 'warning');
                return;
            }
            const lines = Array.from(output.querySelectorAll('.logcat-line')).map(el => el.textContent);
            U.downloadBlob(new Blob([lines.join('\n')], { type: 'text/plain' }), `logcat_${U.timestampForFile()}.txt`);
            showToast('Logs downloaded', 'success');
        },
        getLogLevel(line) {
            const m = /^\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+\s+\d+\s+\d+\s+([VDIWEF])\s/.exec(line) || /^([VDIWEF])\//.exec(line);
            if (!m) return '';
            return ({ V: 'verbose', D: 'debug', I: 'info', W: 'warn', E: 'error', F: 'fatal' })[m[1]];
        },
        async analyzeStorage() {
            const pkg = document.getElementById('storageSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('storageResults');
            results.innerHTML = '<div class="empty-state"><p>Analyzing with root...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const data = await auditor.getLocalStorageFiles(pkg);
                let html = '';
                const sections = [
                    { key: 'sharedPrefs', title: 'SharedPreferences', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
                    { key: 'databases', title: 'Databases', icon: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4' },
                    { key: 'files', title: 'Internal Files', icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z' },
                    { key: 'external', title: 'External Storage', icon: 'M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8' }
                ];
                const encodedPkg = safeEncode(pkg);
                for (const section of sections) {
                    if (data[section.key]?.length > 0) {
                        html += `<div class="result-box"><div class="result-header"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:16px;height:16px;opacity:0.6"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${section.icon}"/></svg><strong>${section.title} (${data[section.key].length})</strong></div><div class="file-grid">`;
                        for (const f of data[section.key]) {
                            const encodedPath = safeEncode(f.path);
                            const encodedName = safeEncode(f.name);
                            const sizeStr = f.size && f.size !== '-' ? `<span class="file-row-size">${escapeHtml(f.size)}B</span>` : '';
                            html += `<div class="file-row">
                                <div class="file-row-info">
                                    <div class="file-row-icon"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg></div>
                                    <span class="file-row-name">${escapeHtml(f.name)}</span>${sizeStr}
                                </div>
                                <div class="file-row-actions">
                                    <button class="btn btn-sm btn-ghost" onclick="window.viewStorageFile('${encodedPath}')">View</button>
                                    <button class="btn btn-sm btn-ghost" onclick="window.downloadStorageFile('${encodedPkg}','${encodedPath}','${encodedName}')">Download</button>
                                </div>
                            </div>`;
                        }
                        html += '</div></div>';
                    }
                }
                if (!html) {
                    html = '<div class="empty-state"><p>No files found. Device may need root.</p></div>';
                }
                results.innerHTML = html;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        renderCheck(results, result, labels) {
            const badge = result.status === 'pass' ? 'pass' : result.status === 'fail' ? 'fail' : result.status === 'error' ? 'fail' : 'warning';
            const label = result.status === 'error' ? '! Error' : (labels[result.status] || labels.review);
            let html = `<div class="result-box"><div class="result-header"><span class="badge ${badge}">${escapeHtml(label)}</span></div>`;
            html += `<p style="margin-top:12px;color:var(--lum-70)">${escapeHtml(result.error || result.description)}</p>`;
            for (const f of result.findings || []) {
                html += `<div style="padding:4px 0;font-size:12px;color:var(--lum-60)">&bull; ${escapeHtml(f.note || f.type)}${f.recommendation ? `<br><em style="color:var(--lum-50)">${escapeHtml(f.recommendation)}</em>` : ''}</div>`;
            }
            results.innerHTML = html + '</div>';
        },
        async checkBackup() {
            const pkg = document.getElementById('backupSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('backupResults');
            results.innerHTML = '<div class="empty-state"><p>Checking...</p></div>';
            try {
                const result = await new SecurityAuditor(adb).testBackupEnabled(pkg);
                this.renderCheck(results, result, { pass: '✓ Secure', fail: '✗ Vulnerable', review: '⚠ Review' });
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async analyzeExported() {
            const pkg = document.getElementById('exportedSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('exportedResults');
            results.innerHTML = '<div class="empty-state"><p>Analyzing...</p></div>';
            try {
                const result = await new SecurityAuditor(adb).testExportedComponents(pkg);
                let html = '<div class="result-box"><div class="result-header"><strong>Exported Components</strong></div><div class="component-list">';
                let hasComponents = false;
                for (const f of result.findings || []) {
                    if (!f.components) continue;
                    const type = f.type.replace('exported_', '');
                    for (const c of f.components) {
                        hasComponents = true;
                        html += `<div class="component-item"><span class="component-type ${escapeAttr(type)}">${escapeHtml(type)}</span><span class="component-name">${escapeHtml(c)}</span></div>`;
                    }
                }
                if (!hasComponents) html += '<div style="padding:12px;color:var(--lum-50)">No exported components found</div>';
                html += '</div></div>';
                results.innerHTML = html;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async checkDebuggable() {
            const pkg = document.getElementById('debugSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('debugResults');
            results.innerHTML = '<div class="empty-state"><p>Checking...</p></div>';
            try {
                const result = await new SecurityAuditor(adb).testDebuggable(pkg);
                this.renderCheck(results, result, { pass: '✓ Not Debuggable', fail: '✗ Debuggable', review: '⚠ Review' });
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async analyzePermissions() {
            const pkg = document.getElementById('permSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('permResults');
            results.innerHTML = '<div class="empty-state"><p>Analyzing...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const result = await auditor.testDangerousPermissionsOnly(pkg);
                const permFinding = result.findings?.find(f => f.type === 'granted_dangerous_permissions');
                const perms = permFinding?.permissions || [];
                let html = '<div class="result-box"><div class="result-header"><strong>Dangerous Permissions</strong></div>';
                if (perms.length > 0) {
                    html += '<div class="perm-list" style="margin-top:12px">';
                    for (const p of perms) {
                        const name = (p.permission || p).replace('android.permission.', '');
                        html += `<span class="perm-tag">${escapeHtml(name)}</span>`;
                    }
                    html += '</div>';
                } else {
                    html += '<p style="margin-top:12px;color:var(--lum-50)">No dangerous permissions granted</p>';
                }
                html += '</div>';
                results.innerHTML = html;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async loadAppInfo() {
            const pkg = document.getElementById('appInfoSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('appInfoResults');
            results.innerHTML = '<div class="empty-state"><p>Loading info...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const info = await auditor.getAppInfo(pkg);
                let flagsHtml = '';
                if (info.flags && info.flags.length > 0) {
                    flagsHtml = info.flags.map(f => {
                        const danger = ['DEBUGGABLE', 'ALLOW_BACKUP', 'CLEARTEXT_TRAFFIC'].includes(f);
                        return `<span class="badge ${danger ? 'fail' : 'pass'}" style="margin:2px">${escapeHtml(f)}</span>`;
                    }).join('');
                }
                let html = '<div class="result-box">';
                html += `<div class="result-header"><strong>${escapeHtml(pkg)}</strong></div>`;
                html += '<div class="prop-list" style="margin-top:8px">';
                const rows = [
                    ['Version', (info.versionName || '?') + ' (' + (info.versionCode || '?') + ')'],
                    ['Target SDK', info.targetSdk ? 'API ' + info.targetSdk + ' (Android ' + (new SecurityAuditor(adb)).sdkToAndroidVersion(parseInt(info.targetSdk)) + ')' : '?'],
                    ['Min SDK', info.minSdk ? 'API ' + info.minSdk : '?'],
                    ['Signing', info.signingVersion || '?'],
                    ['UID', info.uid || '?'],
                    ['Data Dir', info.dataDir || '?'],
                    ['APK Path', info.apkPath || '?'],
                    ['Data Size', info.dataSize || '?'],
                    ['APK Size', info.apkSize || '?'],
                    ['Installed', info.firstInstall || '?'],
                    ['Last Updated', info.lastUpdate || '?']
                ];
                for (const [label, val] of rows) {
                    html += `<div class="prop-row"><span class="prop-key">${escapeHtml(label)}</span><span class="prop-val" style="font-family:monospace;font-size:12px">${escapeHtml(val)}</span></div>`;
                }
                html += '</div>';
                if (flagsHtml) {
                    html += `<div style="margin-top:12px;padding-top:12px;border-top:1px solid rgba(255,255,255,0.06)"><strong style="font-size:12px;color:var(--lum-50)">Flags</strong><div style="margin-top:6px">${flagsHtml}</div></div>`;
                }
                html += '</div>';
                results.innerHTML = html;
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        lastReport: null,
        renderReportHtml(report) {
            const e = escapeHtml;
            const sevColor = (sev) => ({ critical: 'var(--danger)', high: 'var(--danger)', medium: 'var(--warning)' })[U.normalizeSeverity(sev)] || 'var(--lum-60)';
            const score = report.riskScore ?? U.computeRiskScore(report);
            const scoreColor = score >= 45 ? 'var(--danger)' : score >= 20 ? 'var(--warning)' : 'var(--success)';
            const tile = (n, label, color, bg) => `<div style="padding:8px 16px;border-radius:8px;background:${bg};text-align:center"><div style="font-size:20px;font-weight:700;color:${color}">${n}</div><div style="font-size:11px;color:var(--lum-50)">${label}</div></div>`;
            let html = '<div class="result-box" style="margin-top:12px">';
            html += `<div class="result-header"><strong>Scan Report: ${e(report.packageName)}</strong><span style="color:var(--lum-40);font-size:12px;margin-left:auto">${e(report.timestamp)}</span></div>`;
            html += '<div style="display:flex;gap:12px;margin-top:12px;flex-wrap:wrap">';
            html += tile(`${score}<span style="font-size:11px">/100</span>`, 'Risk: ' + U.riskLabel(score), scoreColor, 'rgba(255,255,255,0.05)');
            html += tile(report.summary.pass, 'Pass', 'var(--success)', 'rgba(76,175,80,0.1)');
            html += tile(report.summary.fail, 'Fail', 'var(--danger)', 'rgba(244,67,54,0.1)');
            html += tile(report.summary.review, 'Review', 'var(--warning)', 'rgba(255,152,0,0.1)');
            html += tile(report.summary.error, 'Error', 'var(--lum-50)', 'rgba(255,255,255,0.05)');
            html += '</div>';
            if (report.diff) {
                const d = report.diff;
                const parts = [];
                if (d.newFailures.length) parts.push(`<span style="color:var(--danger)">${d.newFailures.length} new failure(s): ${e(d.newFailures.join(', '))}</span>`);
                if (d.fixed.length) parts.push(`<span style="color:var(--success)">${d.fixed.length} fixed: ${e(d.fixed.join(', '))}</span>`);
                if (!parts.length) parts.push('<span style="color:var(--lum-50)">No change in failing tests</span>');
                html += `<div style="margin-top:10px;font-size:12px">Since last scan (${e(d.previous)}): ${parts.join(' &middot; ')}</div>`;
            }
            html += `<div class="report-actions" style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
                ${['json:JSON', 'md:Markdown', 'html:HTML', 'csv:CSV'].map(x => { const [k, l] = x.split(':'); return `<button class="btn btn-sm btn-ghost" data-export="${k}">Export ${l}</button>`; }).join('')}
                <button class="btn btn-sm btn-ghost" data-export="copy">Copy summary</button></div></div>`;
            for (const test of report.tests) {
                const badge = test.status === 'pass' ? 'pass' : test.status === 'fail' ? 'fail' : test.status === 'review' ? 'warning' : '';
                const label = test.status === 'pass' ? '✓ Pass' : test.status === 'fail' ? '✗ Fail' : test.status === 'review' ? '⚠ Review' : '? Error';
                html += `<div class="result-box" style="margin-top:8px"><div class="result-header"><span class="badge ${badge}">${label}</span><strong style="margin-left:8px">${e(test.title || test.id)}</strong>${test.category ? `<span style="margin-left:auto;font-size:11px;color:var(--lum-40)">${e(test.category)}</span>` : ''}</div>`;
                if (test.description) html += `<p style="margin-top:6px;color:var(--lum-50);font-size:12px">${e(test.description)}</p>`;
                if (test.findings && test.findings.length > 0) {
                    html += '<div style="margin-top:8px">';
                    for (const f of test.findings) {
                        html += `<div style="padding:4px 0;font-size:12px;color:${sevColor(f.severity)}">&bull; ${e(f.note || f.type || '')}${f.recommendation ? `<div style="color:var(--lum-50);margin-left:12px">Fix: ${e(f.recommendation)}</div>` : ''}</div>`;
                    }
                    html += '</div>';
                }
                if (test.error) html += `<p style="margin-top:6px;color:var(--danger);font-size:12px">${e(test.error)}</p>`;
                html += '</div>';
            }
            return html;
        },
        recordScan(report) {
            const failed = report.tests.filter(t => t.status === 'fail').map(t => t.id);
            const history = store.get('scanHistory', []);
            const prev = history.find(h => h.pkg === report.packageName);
            if (prev) {
                report.diff = {
                    previous: prev.ts.slice(0, 19).replace('T', ' '),
                    newFailures: failed.filter(id => !prev.failed.includes(id)),
                    fixed: prev.failed.filter(id => !failed.includes(id))
                };
            }
            history.unshift({ pkg: report.packageName, ts: report.timestamp, failed, risk: report.riskScore, summary: report.summary });
            store.set('scanHistory', history.filter((h, i, a) => a.findIndex(x => x.pkg === h.pkg) === i).slice(0, 30));
        },
        showReport(report, container) {
            this.lastReport = report;
            container.innerHTML = this.renderReportHtml(report);
            container.querySelector('.report-actions')?.addEventListener('click', (ev) => {
                const b = ev.target.closest('[data-export]');
                if (b) this.exportReport(b.dataset.export);
            });
        },
        exportReport(kind) {
            const r = this.lastReport;
            if (!r) return;
            const meta = { device: [state.deviceInfo.brand, state.deviceInfo.model, state.deviceInfo.androidVersion ? 'Android ' + state.deviceInfo.androidVersion : ''].filter(Boolean).join(' ') };
            const base = `${U.safeFileName(r.packageName)}_${U.timestampForFile()}`;
            if (kind === 'json') U.downloadBlob(new Blob([JSON.stringify({ generator: 'ADB Auditor (created by Sandeep Wawdane, enhanced by 0x0806)', device: meta.device, ...r }, null, 2)], { type: 'application/json' }), base + '.json');
            else if (kind === 'md') U.downloadBlob(new Blob([U.reportToMarkdown(r, meta)], { type: 'text/markdown' }), base + '.md');
            else if (kind === 'html') U.downloadBlob(new Blob([U.reportToHtml(r, meta)], { type: 'text/html' }), base + '.html');
            else if (kind === 'csv') U.downloadBlob(new Blob([U.reportToCSV(r)], { type: 'text/csv' }), base + '.csv');
            else if (kind === 'copy') {
                const failing = r.tests.filter(t => t.status === 'fail').map(t => `- ${t.title}`).join('\n') || '- none';
                navigator.clipboard?.writeText(`${r.packageName}: risk ${r.riskScore}/100 (${U.riskLabel(r.riskScore)}); pass ${r.summary.pass}, fail ${r.summary.fail}, review ${r.summary.review}\nFailing:\n${failing}`)
                    .then(() => showToast('Summary copied', 'success'), () => showToast('Copy failed', 'error'));
                return;
            }
            showToast('Report exported', 'success');
        },
        async runFullScan() {
            const pkg = document.getElementById('fullScanSelect')?.value;
            if (!pkg) { showToast('Select an application', 'warning'); return; }
            const results = document.getElementById('fullScanResults');
            const progress = document.getElementById('fullScanProgress');
            const statusEl = document.getElementById('fullScanStatus');
            const bar = document.getElementById('fullScanBar');
            results.innerHTML = '';
            progress.classList.remove('hidden');
            try {
                const auditor = new SecurityAuditor(adb);
                const report = await auditor.runFullAudit(pkg, (name, current, total) => {
                    statusEl.textContent = `Running: ${name} (${current}/${total})`;
                    bar.style.width = Math.round((current / total) * 100) + '%';
                });
                progress.classList.add('hidden');
                this.recordScan(report);
                activity.add('scan', `${pkg} risk=${report.riskScore} fail=${report.summary.fail}`);
                this.showReport(report, results);
            } catch (e) {
                progress.classList.add('hidden');
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        async runDeviceAudit() {
            const results = document.getElementById('deviceAuditResults');
            const status = document.getElementById('deviceAuditStatus');
            results.innerHTML = '<div class="empty-state"><p>Auditing device...</p></div>';
            try {
                const body = await new SecurityAuditor(adb).runDeviceAudit((name, i, t) => { if (status) status.textContent = `${name} (${i}/${t})`; });
                const report = { packageName: 'Device', timestamp: new Date().toISOString(), ...body };
                report.riskScore = U.computeRiskScore(report);
                this.showReport(report, results);
                if (status) status.textContent = '';
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        triageRows: [],
        triageSort: { key: 'risk', dir: -1 },
        async runTriage() {
            const results = document.getElementById('triageResults');
            const bar = document.getElementById('triageBar');
            const status = document.getElementById('triageStatus');
            const includeSystem = document.getElementById('triageSystem')?.checked;
            results.innerHTML = '<div class="empty-state"><p>Listing applications...</p></div>';
            try {
                const pkgs = await adb.listPackages(!!includeSystem);
                const auditor = new SecurityAuditor(adb);
                const sel = document.getElementById('triagePerm'); if (sel) sel.innerHTML = '<option value="">All permissions</option>';
                this.triageRows = await auditor.triageApps(pkgs, (pkg, i, t) => {
                    if (status) status.textContent = `${i}/${t} - ${pkg}`;
                    if (bar) bar.style.width = Math.round(i / t * 100) + '%';
                });
                this.renderTriage();
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        },
        renderTriage() {
            const results = document.getElementById('triageResults');
            if (!results) return;
            const { key, dir } = this.triageSort;
            const permSel = document.getElementById('triagePerm');
            if (permSel && permSel.options.length <= 1) {
                const all = [...new Set(this.triageRows.flatMap(r => r.permissions || []))].sort();
                permSel.innerHTML = '<option value="">All permissions</option>' + all.map(p => `<option value="${escapeAttr(p)}">${escapeHtml(p)}</option>`).join('');
            }
            const wantPerm = permSel ? permSel.value : '';
            const rows = this.triageRows.filter(r => !wantPerm || (r.permissions || []).includes(wantPerm)).sort((a, b) => {
                const av = a[key], bv = b[key];
                if (typeof av === 'string' || typeof bv === 'string') return String(av ?? '').localeCompare(String(bv ?? '')) * dir;
                return ((av === true ? 1 : av === false ? 0 : av ?? -1) - (bv === true ? 1 : bv === false ? 0 : bv ?? -1)) * dir;
            });
            const cols = [['package', 'Package'], ['risk', 'Risk'], ['debuggable', 'Debug'], ['allowBackup', 'Backup'], ['targetSdk', 'Target'], ['minSdk', 'Min'], ['dangerousPerms', 'Perms'], ['installer', 'Installer']];
            const yes = (v) => v ? '<span class="badge fail">yes</span>' : '<span style="color:var(--lum-40)">no</span>';
            let html = `<div class="result-box" style="margin-top:12px;overflow-x:auto"><div class="result-header"><strong>${rows.length} apps</strong>
                <button class="btn btn-sm btn-ghost" style="margin-left:auto" data-triage-csv="1">Export CSV</button></div>
                <table class="ab-table"><thead><tr>${cols.map(([k, l]) => `<th data-sort="${k}" tabindex="0" role="button" aria-label="Sort by ${l}">${l}${key === k ? (dir > 0 ? ' ▲' : ' ▼') : ''}</th>`).join('')}</tr></thead><tbody>`;
            for (const r of rows) {
                const riskColor = r.risk >= 40 ? 'var(--danger)' : r.risk >= 20 ? 'var(--warning)' : 'var(--lum-60)';
                html += `<tr data-pkg="${escapeAttr(r.package)}" tabindex="0" title="Click to run a full scan"><td class="mono">${escapeHtml(r.package)}</td>`;
                html += r.error ? `<td colspan="7" style="color:var(--danger)">${escapeHtml(r.error)}</td>`
                    : `<td style="color:${riskColor};font-weight:600">${r.risk}</td><td>${yes(r.debuggable)}</td><td>${yes(r.allowBackup)}</td><td>${escapeHtml(r.targetSdk ?? '-')}</td><td>${escapeHtml(r.minSdk ?? '-')}</td><td>${r.dangerousPerms}</td><td class="mono">${escapeHtml(r.installer)}</td>`;
                html += '</tr>';
            }
            results.innerHTML = html + '</tbody></table></div>';
            results.onclick = (ev) => {
                const th = ev.target.closest('th[data-sort]');
                if (th) { const k = th.dataset.sort; this.triageSort = { key: k, dir: this.triageSort.key === k ? -this.triageSort.dir : (k === 'package' ? 1 : -1) }; this.renderTriage(); return; }
                if (ev.target.closest('[data-triage-csv]')) { this.exportTriageCsv(); return; }
                const tr = ev.target.closest('tr[data-pkg]');
                if (tr) this.openAudit(tr.dataset.pkg, 'fullScan');
            };
        },
        exportTriageCsv() {
            const header = ['package', 'risk', 'debuggable', 'allowBackup', 'cleartext', 'targetSdk', 'minSdk', 'dangerousPerms', 'installer', 'permissions'];
            const rows = [header, ...this.triageRows.filter(r => !r.error).map(r => header.map(h => (h === 'permissions' ? (r.permissions || []).join(';') : r[h])))];
            const cell = (v) => { const s = String(v ?? ''); return '"' + (/^[=+\-@]/.test(s) ? "'" + s : s).replace(/"/g, '""') + '"'; };
            U.downloadBlob(new Blob([rows.map(r => r.map(cell).join(',')).join('\r\n')], { type: 'text/csv' }), `app_triage_${U.timestampForFile()}.csv`);
        },
        async loadNetwork() {
            const pkg = document.getElementById('networkSelect')?.value || '';
            const results = document.getElementById('networkResults');
            results.innerHTML = '<div class="empty-state"><p>Collecting...</p></div>';
            try {
                const auditor = new SecurityAuditor(adb);
                const [conns, procs] = await Promise.all([auditor.getActiveConnections(pkg || undefined), auditor.getRunningProcesses(pkg || undefined)]);
                const stateBadge = (s) => `<span class="badge ${s === 'ESTABLISHED' ? 'pass' : s === 'LISTEN' ? 'warning' : ''}">${escapeHtml(s)}</span>`;
                let html = `<div class="result-box" style="overflow-x:auto"><div class="result-header"><strong>Connections (${conns.length})</strong></div>`;
                html += conns.length ? `<table class="ab-table"><thead><tr><th>Local</th><th>Remote</th><th>State</th><th>UID</th></tr></thead><tbody>${conns.map(c => `<tr><td class="mono">${escapeHtml(c.local)}</td><td class="mono">${escapeHtml(c.remote)}</td><td>${stateBadge(c.state)}</td><td>${escapeHtml(c.uid)}</td></tr>`).join('')}</tbody></table>` : '<p style="color:var(--lum-50);margin-top:8px">No connections found</p>';
                html += `</div><div class="result-box" style="margin-top:8px;overflow-x:auto"><div class="result-header"><strong>Processes (${procs.length})</strong></div>`;
                html += procs.length ? `<table class="ab-table"><thead><tr><th>PID</th><th>User</th><th>RSS</th><th>Name</th></tr></thead><tbody>${procs.slice(0, 500).map(p => `<tr><td>${escapeHtml(p.pid)}</td><td>${escapeHtml(p.user)}</td><td>${escapeHtml(p.rss)}</td><td class="mono">${escapeHtml(p.name)}</td></tr>`).join('')}</tbody></table>` : '<p style="color:var(--lum-50);margin-top:8px">No processes found</p>';
                results.innerHTML = html + '</div>';
            } catch (e) {
                results.innerHTML = `<div class="result-box"><span class="badge fail">Error</span><p style="margin-top:8px">${escapeHtml(e.message)}</p></div>`;
            }
        }
    };
    el.connectBtn.addEventListener('click', () => app.connect());
    el.disconnectBtn.addEventListener('click', () => app.disconnect());
    if (el.deviceSelect) {
        el.deviceSelect.addEventListener('change', (e) => app.onDeviceSelect(e.target.value));
    }
    if (el.addDeviceBtn) {
        el.addDeviceBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            app.toggleAddMenu();
        });
    }
    document.addEventListener('click', (e) => {
        if (el.addDeviceMenu && !el.addDeviceMenu.contains(e.target) && e.target !== el.addDeviceBtn) {
            app.closeAddMenu();
        }
    });
    const sectionOrder = ['overview', 'apps', 'files', 'screenshot', 'shell', 'security', 'tools'];
    document.querySelectorAll('.dock-item').forEach(item => {
        item.setAttribute('role', 'button');
        item.setAttribute('tabindex', '0');
        item.setAttribute('aria-label', item.getAttribute('title') || item.dataset.section);
        const activate = () => { if (!item.classList.contains('disabled')) navigate(item.dataset.section); };
        item.addEventListener('click', activate);
        item.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); } });
    });

    /* ---------- environment checks ---------- */

    function showBanner(message) {
        const bar = document.createElement('div');
        bar.className = 'ab-banner';
        bar.setAttribute('role', 'alert');
        bar.textContent = message;
        document.body.prepend(bar);
    }
    if (!navigator.usb) {
        showBanner('WebUSB is not available in this browser. Use Chrome, Edge or Opera (desktop) over HTTPS or localhost.');
    } else if (window.isSecureContext === false) {
        showBanner('WebUSB requires a secure context. Open this page over HTTPS or from http://localhost.');
    }

    /* ---------- keep-alive: detect a sleeping / stale device ---------- */

    let keepAlive = null;
    function startKeepAlive() {
        stopKeepAlive();
        let failures = 0;
        keepAlive = setInterval(async () => {
            if (!adb || !state.connected || document.hidden) return;
            if (Date.now() - adb.lastActivity < 20000) { failures = 0; return; }
            failures = (await adb.ping()) ? 0 : failures + 1;
            if (failures >= 2) { failures = 0; adb.markDisconnected('Device stopped responding'); }
        }, 15000);
    }
    function stopKeepAlive() { if (keepAlive) { clearInterval(keepAlive); keepAlive = null; } }
    const origConnect = app.connect.bind(app);
    app.connect = async function() { await origConnect(); if (state.connected) startKeepAlive(); };
    const origHandleLost = app.handleDeviceDisconnected.bind(app);
    app.handleDeviceDisconnected = function(d) { stopKeepAlive(); app.stopLiveScreenshot(); return origHandleLost(d); };
    const origDisconnect = app.disconnect.bind(app);
    app.disconnect = async function() { stopKeepAlive(); app.stopLiveScreenshot(); return origDisconnect(); };

    window.addEventListener('beforeunload', () => { if (adb && adb.device?.opened) { adb.device.close().catch(() => {}); } });
    window.addEventListener('unhandledrejection', (e) => {
        console.error('Unhandled rejection:', e.reason);
        const msg = e.reason && e.reason.message ? e.reason.message : String(e.reason);
        if (!/ResizeObserver/.test(msg)) showToast('Unexpected error: ' + msg, 'error');
    });

    /* ---------- keyboard shortcuts + command palette ---------- */

    const commands = () => {
        const list = [
            ...sectionOrder.map((s, i) => ({ name: 'Go to ' + s[0].toUpperCase() + s.slice(1), hint: 'Alt+' + (i + 1), run: () => navigate(s), needsDevice: s !== 'overview' })),
            { name: 'Connect device', run: () => app.connect(), when: () => !state.connected },
            { name: 'Disconnect device', hint: 'Alt+D', run: () => app.disconnect(), when: () => state.connected },
            { name: 'Refresh current view', hint: 'Alt+R', run: () => refreshCurrent(), needsDevice: true },
            { name: 'Take screenshot', run: () => { navigate('screenshot'); app.captureScreenshot(); }, needsDevice: true },
            { name: 'Security: full scan', run: () => { navigate('security'); app.switchSecurityTab('fullScan'); loadSecurityApps(); }, needsDevice: true },
            { name: 'Security: device posture audit', run: () => { navigate('security'); app.switchSecurityTab('device'); loadSecurityApps(); }, needsDevice: true },
            { name: 'Security: triage all apps', run: () => { navigate('security'); app.switchSecurityTab('triage'); loadSecurityApps(); }, needsDevice: true },
            { name: 'Security: live logcat', run: () => { navigate('security'); app.switchSecurityTab('logcat'); }, needsDevice: true },
            { name: 'Export device info (JSON)', run: () => app.exportDeviceInfo(), needsDevice: true },
            { name: 'Keyboard shortcuts', hint: '?', run: () => showShortcuts() },
            { name: 'About ADB Auditor', run: () => showAbout() }
        ];
        list.push(...extraCommands);
        return list.filter(c => (!c.needsDevice || state.connected) && (!c.when || c.when()));
    };
    function refreshCurrent() {
        const s = state.currentSection;
        if (s === 'overview') app.loadOverview(); else if (s === 'apps') app.loadApps(); else if (s === 'files') app.refreshFiles();
        else if (s === 'screenshot') app.captureScreenshot(); else if (s === 'security') loadSecurityApps();
    }
    function showShortcuts() {
        const rows = [['Alt + 1 … 7', 'Switch section'], ['Alt + R', 'Refresh current view'], ['Alt + D', 'Disconnect'], ['Ctrl/Cmd + K', 'Command palette'], ['?', 'This help'],
            ['Tab', 'Shell: autocomplete'], ['↑ / ↓', 'Shell: history'], ['Ctrl + C', 'Shell: stop streaming command'], ['Ctrl + L', 'Shell: clear'], ['Esc', 'Close dialogs']];
        const wrap = document.createElement('div');
        wrap.innerHTML = '<table class="ab-table"><tbody>' + rows.map(([k, v]) => `<tr><td class="mono">${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`).join('') + '</tbody></table>';
        openModal({ title: 'Keyboard shortcuts', body: wrap, buttons: [{ label: 'Close', primary: true }] });
    }
    function showAbout() {
        const wrap = document.createElement('div');
        wrap.innerHTML = `<p><strong>ADB Auditor</strong> &mdash; browser-based Android security auditing over WebUSB. 100% client-side.</p>
            <p style="margin-top:10px">Created by <a href="https://github.com/thecybersandeep" target="_blank" rel="noopener noreferrer">Sandeep Wawdane</a> (<a href="https://github.com/thecybersandeep/adbauditor" target="_blank" rel="noopener noreferrer">original project</a>).</p>
            <p style="margin-top:6px">Enhanced &amp; maintained by <a href="https://github.com/0x0806" target="_blank" rel="noopener noreferrer">0x0806</a> (<a href="https://github.com/0x0806/adbauditor" target="_blank" rel="noopener noreferrer">this fork</a>).</p>
            <p style="margin-top:10px;color:var(--lum-50);font-size:12px">Use only on devices you are authorised to test.</p>`;
        openModal({ title: 'About', body: wrap, buttons: [{ label: 'Close', primary: true }] });
    }
    function showPalette() {
        const wrap = document.createElement('div');
        const input = document.createElement('input');
        input.type = 'text'; input.className = 'text-input'; input.placeholder = 'Type a command...'; input.setAttribute('aria-label', 'Command');
        const list = document.createElement('div');
        list.className = 'ab-palette-list'; list.setAttribute('role', 'listbox');
        wrap.append(input, list);
        const all = commands();
        let shown = [], sel = 0;
        const m = openModal({ title: 'Command palette', body: wrap, buttons: [] });
        const draw = () => {
            const q = input.value.toLowerCase();
            shown = all.filter(c => c.name.toLowerCase().includes(q));
            sel = Math.min(sel, Math.max(0, shown.length - 1));
            list.innerHTML = shown.map((c, i) => `<div class="ab-palette-item${i === sel ? ' sel' : ''}" role="option" data-i="${i}"><span>${escapeHtml(c.name)}</span><span class="mono">${escapeHtml(c.hint || '')}</span></div>`).join('') || '<div class="ab-palette-item">No matching command</div>';
        };
        const run = (i) => { const c = shown[i]; if (c) { m.close(); setTimeout(c.run, 0); } };
        input.addEventListener('input', () => { sel = 0; draw(); });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(sel + 1, shown.length - 1); draw(); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(sel - 1, 0); draw(); }
            else if (e.key === 'Enter') { e.preventDefault(); run(sel); }
        });
        list.addEventListener('click', (e) => { const it = e.target.closest('[data-i]'); if (it) run(parseInt(it.dataset.i, 10)); });
        draw();
    }
    document.addEventListener('keydown', (e) => {
        const tag = (e.target.tagName || '').toLowerCase();
        const typing = tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable;
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (!document.querySelector('.ab-modal-overlay')) showPalette(); return; }
        if (document.querySelector('.ab-modal-overlay')) return;
        if (e.altKey && !e.ctrlKey && !e.metaKey) {
            const n = parseInt(e.key, 10);
            if (n >= 1 && n <= 7) { e.preventDefault(); if (n === 1 || state.connected) navigate(sectionOrder[n - 1]); return; }
            if (e.key.toLowerCase() === 'r' && state.connected) { e.preventDefault(); refreshCurrent(); return; }
            if (e.key.toLowerCase() === 'd' && state.connected) { e.preventDefault(); app.disconnect(); return; }
        }
        if (!typing && e.key === '?') { e.preventDefault(); showShortcuts(); }
    });

    app.initDeviceManager().catch(err => {
        console.warn('Device manager initialization failed:', err);
    });
    navigate('overview');
    window.app = app;
    window.__AB = {
        state, app, store, openModal, askConfirm, askInput, showToast, showLoading, hideLoading, navigate, activity,
        getAdb: () => adb, formatSize, readDeviceFile, pullAsRoot, previewBytes, showTextModal, loadSecurityApps, templates, securityTabs,
        registerSection(id, template, onShow) { templates[id] = template; sectionHooks[id] = onShow; },
        registerCommand(cmd) { extraCommands.push(cmd); }
    };
    window.dispatchEvent(new Event('ab-ready'));

    window.viewStorageFile = async function(encodedPath) {
        const path = safeDecode(encodedPath);
        const fileName = path.split('/').pop() || 'file';
        showLoading('Loading file...', fileName);
        try {
            const bytes = await readDeviceFile(path, null, !isSdcardPath(path));
            hideLoading();
            previewBytes(fileName, path, bytes);
        } catch (e) {
            hideLoading();
            showToast('Error: ' + (e.message || 'Unknown'), 'error');
        }
    };
    window.downloadStorageFile = async function(encodedPkg, encodedPath, encodedName) {
        const pkg = safeDecode(encodedPkg);
        const path = safeDecode(encodedPath);
        const name = safeDecode(encodedName);
        showLoading('Downloading...', name);
        try {
            const bytes = await readDeviceFile(path, (n, total) => showLoading('Downloading...', total ? `${formatSize(n)} / ${formatSize(total)}` : formatSize(n)), !isSdcardPath(path));
            U.downloadBlob(new Blob([bytes]), pkg + '_' + name);
            hideLoading();
            showToast('Downloaded: ' + name + ' (' + formatSize(bytes.length) + ')', 'success');
        } catch (e) {
            hideLoading();
            showToast('Download failed: ' + (e.message || 'Unknown'), 'error');
        }
    };
})();
