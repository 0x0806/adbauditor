/**
 * ADB Auditor - shared helpers (pure functions, no device access).
 *
 * @author Sandeep Wawdane (original creator of ADB Auditor)
 * @contributor 0x0806 (enhancements, hardening, tests)
 * @license See LICENSE (CC BY-NC-ND 4.0, (c) Sandeep Wawdane)
 */
(function(global) {
    'use strict';

    /* ---------- Shell quoting ---------- */

    /** POSIX single-quote a string so it is one literal shell word. */
    function shQuote(value) {
        return "'" + String(value).replace(/'/g, "'\\''") + "'";
    }

    /** Wrap a full command line so it runs as root via `su -c`. */
    function suWrap(command) {
        return 'su -c ' + shQuote(command);
    }

    /** Android package-name validation (also blocks shell metacharacters). */
    function isValidPackageName(name) {
        if (!name || typeof name !== 'string' || name.length > 255) return false;
        return /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)*$/.test(name);
    }

    function escapeRegExp(s) {
        return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    /** Normalise a user path: absolute, no duplicate or trailing slashes, no "." / ".." segments. */
    function normalizePath(path) {
        const out = [];
        for (const seg of String('/' + (path || '')).split('/')) {
            if (!seg || seg === '.') continue;
            if (seg === '..') { out.pop(); continue; }
            out.push(seg);
        }
        return '/' + out.join('/');
    }

    function joinPath(dir, name) {
        return (dir === '/' ? '' : dir.replace(/\/+$/, '')) + '/' + name;
    }

    /* ---------- HTML escaping (string based, no DOM needed) ---------- */

    const HTML_ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
    function escapeHtml(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/[&<>"'`]/g, c => HTML_ESC[c]);
    }

    /* ---------- Formatting ---------- */

    function formatSize(bytes) {
        const num = Number(bytes);
        if (!isFinite(num) || bytes === '' || bytes === null || bytes === undefined) return String(bytes ?? '-');
        if (num < 1024) return num + ' B';
        if (num < 1048576) return (num / 1024).toFixed(1) + ' KB';
        if (num < 1073741824) return (num / 1048576).toFixed(1) + ' MB';
        return (num / 1073741824).toFixed(2) + ' GB';
    }

    function formatDuration(ms) {
        if (ms < 1000) return ms + ' ms';
        const s = ms / 1000;
        if (s < 60) return s.toFixed(1) + ' s';
        return Math.floor(s / 60) + 'm ' + Math.round(s % 60) + 's';
    }

    function timestampForFile(date = new Date()) {
        return date.toISOString().slice(0, 19).replace(/[:T]/g, '-');
    }

    /** Make an arbitrary string safe to use as a download file name. */
    function safeFileName(name, fallback = 'file') {
        const cleaned = String(name || '').replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').replace(/^\.+/, '').trim();
        return cleaned.slice(0, 120) || fallback;
    }

    /* ---------- Base64 ---------- */

    function base64ToBytes(b64) {
        const clean = String(b64).replace(/\s/g, '');
        if (!clean) throw new Error('Empty file or access denied');
        const binary = atob(clean);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    function bytesToBase64(bytes) {
        let binary = '';
        const step = 0x8000;
        for (let i = 0; i < bytes.length; i += step) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
        }
        return btoa(binary);
    }

    /* ---------- `ls -l` parsing ---------- */

    const LS_RE_ISO = /^([-dlbcps][-rwxsStT?]{9})[.+@]?\s+(\d+)\s+(\S+)\s+(\S+)\s+(?:(\d+),\s*)?(\d+)\s+(\d{4}-\d{2}-\d{2})\s+(\d{1,2}:\d{2})(?::\d{2})?(?:\.\d+)?(?:\s+[+-]\d{4})?\s+(.+)$/;
    // Android 5-6 (toolbox): no link-count column, e.g. "-rw-rw---- root sdcard_rw 1234 2016-03-04 11:30 name"
    const LS_RE_NOLINK = /^([-dlbcps][-rwxsStT?]{9})[.+@]?\s+(\S+)\s+(\S+)\s+(?:(\d+),\s*)?(?:(\d+)\s+)?(\d{4}-\d{2}-\d{2})\s+(\d{1,2}:\d{2})(?::\d{2})?\s+(.+)$/;
    const LS_RE_OLD = /^([-dlbcps][-rwxsStT?]{9})[.+@]?\s+(\S+)\s+(\S+)\s+(?:(\d+),\s*)?(\d+)\s+([A-Za-z]{3}\s+\d{1,2}\s+(?:\d{4}|\d{1,2}:\d{2}))\s+(.+)$/;

    /** Parse one line of `ls -la` output. Returns null for non-entry lines. */
    function parseLsLine(line) {
        const text = String(line).replace(/\r$/, '').trim();
        if (!text || text.startsWith('total ')) return null;
        let m = LS_RE_ISO.exec(text);
        let perms, owner, group, size, date, rest;
        if (m) {
            [, perms, , owner, group, , size, date, , rest] = m;
            date = date + ' ' + m[8];
        } else if ((m = LS_RE_NOLINK.exec(text))) {
            [, perms, owner, group, , size, date, , rest] = m;
            date = date + ' ' + m[7];
            if (size === undefined) {                // toolbox prints no size for directories and symlinks only
                if (perms[0] !== 'd' && perms[0] !== 'l') return null;
                size = '0';
            }
        } else if ((m = LS_RE_OLD.exec(text))) {
            [, perms, owner, group, , size, date, rest] = m;
        } else {
            return null;
        }
        let name = rest, target = null;
        if (perms[0] === 'l') {
            const idx = rest.indexOf(' -> ');
            if (idx >= 0) { name = rest.slice(0, idx); target = rest.slice(idx + 4); }
        }
        if (name === '.' || name === '..') return null;
        return {
            perms, owner, group, size: Number(size), date, name, target,
            isDir: perms[0] === 'd',
            isLink: perms[0] === 'l'
        };
    }

    /* ---------- CRC32 + minimal ZIP writer (store, no compression) ---------- */

    let CRC_TABLE = null;
    function crc32(bytes, seed = 0) {
        if (!CRC_TABLE) {
            CRC_TABLE = new Uint32Array(256);
            for (let n = 0; n < 256; n++) {
                let c = n;
                for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
                CRC_TABLE[n] = c >>> 0;
            }
        }
        let crc = (seed ^ 0xFFFFFFFF) >>> 0;
        for (let i = 0; i < bytes.length; i++) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }

    /** Build a ZIP archive. files: [{ name: string, data: Uint8Array|string, date?: Date }] */
    function buildZip(files) {
        const enc = new TextEncoder();
        const parts = [];
        const central = [];
        let offset = 0;
        for (const f of files) {
            const nameBytes = enc.encode(f.name);
            const data = typeof f.data === 'string' ? enc.encode(f.data) : f.data;
            const d = f.date || new Date();
            const dosTime = ((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xFFFF;
            const dosDate = (((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xFFFF;
            const crc = crc32(data);

            const local = new Uint8Array(30 + nameBytes.length);
            const lv = new DataView(local.buffer);
            lv.setUint32(0, 0x04034b50, true);
            lv.setUint16(4, 20, true);
            lv.setUint16(6, 0x0800, true);          // UTF-8 names
            lv.setUint16(8, 0, true);               // store
            lv.setUint16(10, dosTime, true);
            lv.setUint16(12, dosDate, true);
            lv.setUint32(14, crc, true);
            lv.setUint32(18, data.length, true);
            lv.setUint32(22, data.length, true);
            lv.setUint16(26, nameBytes.length, true);
            local.set(nameBytes, 30);
            parts.push(local, data);

            const cen = new Uint8Array(46 + nameBytes.length);
            const cv = new DataView(cen.buffer);
            cv.setUint32(0, 0x02014b50, true);
            cv.setUint16(4, 20, true);
            cv.setUint16(6, 20, true);
            cv.setUint16(8, 0x0800, true);
            cv.setUint16(10, 0, true);
            cv.setUint16(12, dosTime, true);
            cv.setUint16(14, dosDate, true);
            cv.setUint32(16, crc, true);
            cv.setUint32(20, data.length, true);
            cv.setUint32(24, data.length, true);
            cv.setUint16(28, nameBytes.length, true);
            cv.setUint32(42, offset, true);
            cen.set(nameBytes, 46);
            central.push(cen);
            offset += local.length + data.length;
        }
        const cenSize = central.reduce((s, c) => s + c.length, 0);
        const end = new Uint8Array(22);
        const ev = new DataView(end.buffer);
        ev.setUint32(0, 0x06054b50, true);
        ev.setUint16(8, files.length, true);
        ev.setUint16(10, files.length, true);
        ev.setUint32(12, cenSize, true);
        ev.setUint32(16, offset, true);
        const all = [...parts, ...central, end];
        const total = all.reduce((s, p) => s + p.length, 0);
        const out = new Uint8Array(total);
        let o = 0;
        for (const p of all) { out.set(p, o); o += p.length; }
        return out;
    }

    /* ---------- dumpsys parsing ---------- */

    /** Extract flag tokens from `flags=[ A B C ]` / `privateFlags=[ ... ]` lines of dumpsys package. */
    function parsePackageFlags(dump) {
        const flags = new Set();
        const re = /(?:^|\s)(?:flags|privateFlags|pkgFlags|privatePkgFlags)=\[\s*([^\]]*?)\s*\]/gm;
        let m;
        while ((m = re.exec(dump || ''))) {
            m[1].split(/\s+/).filter(Boolean).forEach(f => flags.add(f));
        }
        return flags;
    }

    /**
     * Parse the Activity/Service/Receiver "Resolver Table" sections of `dumpsys package <pkg>`.
     * Returns one entry per distinct (kind, component, filter).
     */
    function parseResolverFilters(dump, packageName) {
        const kinds = { Activity: 'activity', Service: 'service', Receiver: 'receiver' };
        const entries = new Map();
        let kind = null, current = null;
        const prefix = packageName ? packageName + '/' : null;
        for (const raw of String(dump || '').split('\n')) {
            const line = raw.replace(/\r$/, '');
            const sec = /^(Activity|Service|Receiver) Resolver Table:/.exec(line);
            if (sec) { kind = kinds[sec[1]]; current = null; continue; }
            if (/^\S[^:]*:\s*$/.test(line) && !sec) { kind = null; current = null; continue; }
            if (!kind) continue;
            const head = /^\s+[0-9a-f]+\s+([\w.]+\/[\w.$]+)\s+filter\s+([0-9a-f]+)(?:\s+permission\s+(\S+))?/.exec(line);
            if (head) {
                if (prefix && !head[1].startsWith(prefix)) { current = null; continue; }
                const key = kind + '|' + head[1] + '|' + head[2];
                if (!entries.has(key)) {
                    entries.set(key, {
                        kind, component: head[1], permission: head[3] || null,
                        actions: [], categories: [], schemes: [], authorities: [], paths: [], mimeTypes: []
                    });
                }
                current = entries.get(key);
                continue;
            }
            if (!current) continue;
            let a;
            const push = (arr, v) => { if (!arr.includes(v)) arr.push(v); };
            if ((a = /^\s+Action:\s*"([^"]*)"/.exec(line))) push(current.actions, a[1]);
            else if ((a = /^\s+Category:\s*"([^"]*)"/.exec(line))) push(current.categories, a[1]);
            else if ((a = /^\s+Scheme:\s*"([^"]*)"/.exec(line))) push(current.schemes, a[1]);
            else if ((a = /^\s+Authority:\s*"([^"]*)"/.exec(line))) push(current.authorities, a[1]);
            else if ((a = /^\s+Path:\s*"([^"]*)"/.exec(line))) push(current.paths, a[1]);
            else if ((a = /^\s+Type:\s*"([^"]*)"/.exec(line))) push(current.mimeTypes, a[1]);
        }
        return Array.from(entries.values());
    }

    /* ---------- Severity helpers ---------- */

    const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
    function normalizeSeverity(sev) {
        const s = String(sev || 'info').toLowerCase();
        if (s === 'warning') return 'medium';
        if (s === 'warn') return 'medium';
        return SEVERITY_ORDER.includes(s) ? s : 'info';
    }
    function maxSeverity(a, b) {
        return SEVERITY_ORDER.indexOf(normalizeSeverity(a)) >= SEVERITY_ORDER.indexOf(normalizeSeverity(b)) ? normalizeSeverity(a) : normalizeSeverity(b);
    }

    /** 0-100 risk score (higher = riskier) from a full-audit report. */
    function computeRiskScore(report) {
        const weights = { info: 0, low: 2, medium: 6, high: 14, critical: 25 };
        let score = 0;
        for (const t of (report && report.tests) || []) {
            if (t.status === 'fail') score += weights[normalizeSeverity(t.severity)] + 4;
            else if (t.status === 'review') score += Math.max(1, weights[normalizeSeverity(t.severity)] / 2);
        }
        return Math.min(100, Math.round(score));
    }
    function riskLabel(score) {
        if (score >= 70) return 'Critical';
        if (score >= 45) return 'High';
        if (score >= 20) return 'Medium';
        if (score > 0) return 'Low';
        return 'Minimal';
    }

    /* ---------- Report exporters ---------- */

    function findingText(f) {
        return f.note || f.type || '';
    }

    function reportToMarkdown(report, meta = {}) {
        const score = computeRiskScore(report);
        const L = [];
        L.push(`# ADB Auditor Report - ${report.packageName}`);
        L.push('');
        L.push(`- **Generated:** ${report.timestamp}`);
        if (meta.device) L.push(`- **Device:** ${meta.device}`);
        L.push(`- **Risk score:** ${score}/100 (${riskLabel(score)})`);
        L.push(`- **Pass / Fail / Review / Error:** ${report.summary.pass} / ${report.summary.fail} / ${report.summary.review} / ${report.summary.error}`);
        L.push('');
        for (const t of report.tests) {
            L.push(`## [${String(t.status).toUpperCase()}] ${t.title || t.id}`);
            if (t.id) L.push(`*${t.id}${t.category ? ' - ' + t.category : ''}* - severity: **${normalizeSeverity(t.severity)}**`);
            if (t.description) L.push('', t.description);
            if (t.error) L.push('', `> Error: ${t.error}`);
            for (const f of t.findings || []) {
                L.push(`- ${findingText(f)}${f.recommendation ? ' - _' + f.recommendation + '_' : ''}`);
            }
            L.push('');
        }
        L.push('---');
        L.push('Generated by ADB Auditor - created by Sandeep Wawdane, enhanced by 0x0806.');
        return L.join('\n');
    }

    function csvCell(v) {
        const s = String(v ?? '');
        const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s; // neutralise spreadsheet formula injection
        return '"' + safe.replace(/"/g, '""') + '"';
    }

    function reportToCSV(report) {
        const rows = [['package', 'test_id', 'title', 'status', 'severity', 'finding', 'recommendation']];
        for (const t of report.tests) {
            const fs = t.findings && t.findings.length ? t.findings : [{}];
            for (const f of fs) {
                rows.push([report.packageName, t.id, t.title, t.status, normalizeSeverity(f.severity || t.severity), findingText(f), f.recommendation || '']);
            }
        }
        return rows.map(r => r.map(csvCell).join(',')).join('\r\n');
    }

    function reportToHtml(report, meta = {}) {
        const score = computeRiskScore(report);
        const e = escapeHtml;
        const color = { pass: '#16a34a', fail: '#dc2626', review: '#d97706', error: '#6b7280' };
        const tests = report.tests.map(t => `
          <section style="border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;margin:10px 0">
            <h3 style="margin:0 0 4px"><span style="color:${color[t.status] || '#6b7280'}">[${e(String(t.status).toUpperCase())}]</span> ${e(t.title || t.id)}</h3>
            <div style="color:#6b7280;font-size:12px">${e(t.id)} ${t.category ? '&middot; ' + e(t.category) : ''} &middot; severity ${e(normalizeSeverity(t.severity))}</div>
            ${t.description ? `<p>${e(t.description)}</p>` : ''}
            ${t.error ? `<p style="color:#dc2626">${e(t.error)}</p>` : ''}
            <ul>${(t.findings || []).map(f => `<li>${e(findingText(f))}${f.recommendation ? ` <em>- ${e(f.recommendation)}</em>` : ''}</li>`).join('')}</ul>
          </section>`).join('');
        return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ADB Auditor Report - ${e(report.packageName)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;max-width:860px;margin:32px auto;padding:0 16px;color:#111827">
<h1>ADB Auditor Report</h1>
<p><strong>${e(report.packageName)}</strong><br>${e(report.timestamp)}${meta.device ? '<br>Device: ' + e(meta.device) : ''}</p>
<p>Risk score: <strong>${score}/100 (${riskLabel(score)})</strong> &mdash; pass ${report.summary.pass}, fail ${report.summary.fail}, review ${report.summary.review}, error ${report.summary.error}</p>
${tests}
<hr><p style="color:#6b7280;font-size:12px">Generated by ADB Auditor &mdash; created by Sandeep Wawdane, enhanced by 0x0806.</p>
</body></html>`;
    }

    /* ---------- Browser-only helpers ---------- */

    /** Trigger a download; the object URL is revoked late so the browser has time to start it. */
    function downloadBlob(blob, fileName) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = safeFileName(fileName);
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 30000);
    }

    function debounce(fn, ms) {
        let t = null;
        return function(...args) {
            clearTimeout(t);
            t = setTimeout(() => fn.apply(this, args), ms);
        };
    }

    global.ABUtils = {
        shQuote, suWrap, isValidPackageName, escapeRegExp, normalizePath, joinPath,
        escapeHtml, escapeAttr: escapeHtml, formatSize, formatDuration, timestampForFile, safeFileName,
        base64ToBytes, bytesToBase64, parseLsLine, crc32, buildZip,
        parsePackageFlags, parseResolverFilters,
        SEVERITY_ORDER, normalizeSeverity, maxSeverity, computeRiskScore, riskLabel,
        reportToMarkdown, reportToCSV, reportToHtml, downloadBlob, debounce
    };
})(typeof window !== 'undefined' ? window : globalThis);
