# Changelog

## 2.1.1 - bug-fix release by 0x0806

Found with mutation fuzzing of every parser, a concurrency stress test, adversarial end-to-end scenarios and an independent code review. Each fix has a regression test.

### Fixed
- **SQLite reader hung (29 s) on a corrupted record header** claiming an enormous length; now rejected instantly.
- SQLite reader threw raw `TypeError`/`RangeError` (BigInt mixing, reads past the end of a page) on damaged files; now a clear "Corrupt database" error. Cyclic b-tree pages and looping overflow chains are detected.
- SQLite rowids: negative rowids were decoded wrongly (`-1` showed as `255`) and rowids above 2^53 lost precision. 64-bit varints are now exact.
- APK analyzer: corrupted ZIP, binary-manifest and DEX data produced raw `RangeError`s; they are now clean errors. A damaged APK Signing Block no longer aborts the whole analysis and keeps whatever was parsed before the damage.
- **Unplugged USB devices stayed in the device list forever**; the device manager never removed them on disconnect.
- Devices without a serial number were keyed inconsistently (`undefined` vs a fallback id), so they duplicated and their disconnect events never matched. Two identical serial-less devices no longer make each other vanish. `getDeviceInfo()` and device properties use the same id.
- Saving the device list threw when browser storage was unavailable.
- **A failed connection left the USB interface claimed**, so the next attempt could fail with "device in use"; a double-click on Connect started two connections. Both fixed.
- Directory listings on Android 5-6 (no link-count column, no size for directories) were dropped or misparsed.
- Toast de-duplication skipped items while removing from a live collection.
- Service worker tried to cache partial (206) responses and logged errors.

### Tests
- New: mutation-fuzz suite (APK/ZIP, binary XML, DEX, SQLite, inner-file corruption), device-manager tests, deterministic concurrency stress test (no leaked socket queues), 64-bit rowid fixtures, older-Android `ls` formats.
- ESLint (errors fail the build: undefined variables, duplicate keys, unreachable code...) added to `npm run lint` and CI; it found no undefined identifiers in the shipped code.
- End-to-end run grew to 85 checks and now also exercises APK install/download (single and split), upload/download, file preview with secret warning, the Root toggle on a non-rooted device, live screenshots, every security sub-tab, streaming shell commands with Ctrl+C and root shell quoting.
- End-to-end test now also covers hostile content on every new screen (APK package/component names, DB table names and cells, settings values, activity log), file rename/delete/mkdir command quoting, shell `cd`/completion, and recovery after a failed connect.

## 2.1.0 - more enhancements by 0x0806

Items continue the numbering of 2.0.0. Everything listed is implemented and covered by `npm test`
(131 unit tests) and/or `npm run test:e2e` (headless Chromium, fake WebUSB device). Features marked
*(heuristic)* pattern-match strings and can produce false positives/negatives. Protocol and device
control code is verified against mock devices, not physical hardware.

### Offline APK static analyzer (`js/apk-analyzer.js`)
77. ZIP reader (central directory, correct local-header data offsets, deflate).
78. Binary `AndroidManifest.xml` decoder (UTF-8 and UTF-16 string pools; attributes identified by platform resource IDs so obfuscated builds still decode).
79. Manifest security findings, including implicit-export rules (intent-filter / provider defaults), debuggable, backup, cleartext, old SDK levels, unprotected providers/services.
80. Signing analysis: v1 (JAR) certificates and the v2/v3 APK Signing Block, with certificate subject, issuer, validity, algorithm, key size and SHA-256 fingerprint.
81. Debug-certificate, weak-signature-algorithm and short-RSA-key detection.
82. DEX string-table scanner: URLs, IP addresses and hard-coded secrets (AWS, Google, Slack, GitHub, Stripe, JWT, private keys, Firebase URLs), always masked.
83. Risky API hints from DEX strings *(heuristic)*.
84. Tracker / analytics SDK detection *(heuristic)*.
85. Framework (Flutter, React Native, Unity, Xamarin, Cordova...), native ABI/library and embedded-code detection.
86. APK SHA-256 / SHA-1 hashes.
87. Analyzer UI: pull from the device or drop a local file; JSON and Markdown export.
88. "Analyze APK" from the file browser menu.

### SQLite viewer (`js/sqlite-reader.js`)
89. Read-only SQLite reader (table b-trees, overflow pages, every serial type) verified row-for-row against Python's `sqlite3`.
90. WAL overlay so rows that only exist in the `-wal` file are not missed.
91. UTF-16 databases.
92. Viewer UI: table list, pagination, schema, CSV export (formula-injection safe).
93. "Open in DB viewer" from the file browser; the `-wal` file is pulled automatically.
94. SharedPreferences preview shows parsed `key = value` pairs.
95. File previews warn about masked secrets found in the content.

### New audit checks
96. Device exposure: encryption state, screen lock, developer options, USB debugging, unknown sources, Play Protect / ADB install verification.
97. Device administrator inventory.
98. User-installed CA certificate detection (root).
99. Xposed-family framework detection.
100. Triage: filter apps by granted permission; permissions in the CSV export.

### Device toolkit (`js/toolkit.js`, Tools section)
Every value is validated and single-quoted; state-changing actions ask for confirmation. Tests assert the exact command strings, using a real shell to parse them.
101. Reboot (system / recovery / bootloader).
102. Wi-Fi, Bluetooth, mobile data and airplane-mode switches.
103. Remote keys (Home, Back, Recents, volume, D-pad...).
104. Tap and swipe injection.
105. Text input.
106. Brightness.
107. Open URL on the device.
108. Intent launcher (activity / service / broadcast) with typed extras and command preview.
109. Deep-link tester (BROWSABLE VIEW intent, optional package restriction).
110. Content-provider query.
111. Grant / revoke runtime permissions.
112. Enable / disable apps.
113. AppOps viewer.
114. Force-stop and kill-by-PID.
115. Installed-app baseline and drift report (added, removed, updated, installer changed).
116. Settings viewer / editor (system, secure, global).
117. System property browser with filter and JSON export.
118. Dumpsys explorer with output search.
119. Log-buffer snapshots (main, system, crash, events, radio).
120. Process (`top`) snapshot and storage summary.
121. Network info: addresses, routes, DNS, HTTP proxy, private DNS.
122. HTTP proxy set / clear (clear is verified by reading the value back).
123. Screen recording to MP4.
124. Evidence pack: device info, properties, packages, network info, log snapshot, scan history/last report, activity log and screenshot in one ZIP.

### UX
125. Pin apps to the top of the list.
126. Download a folder as a ZIP.
127. Recursive file search.
128. MD5 / SHA-1 / SHA-256 checksums for device files.
129. File info (`stat`).
130. Text editor with save-back to the device (with confirmation).
131. Light, dark and system themes.
132. Settings panel: forget the stored ADB key, clear saved data.
133. Activity log (connects, scans, file operations, shell commands) with export - a local evidence trail, never uploaded.
134. Tools section (Alt+7) built on a small section/command registry; every tool is also in the command palette.
135. Fixed 13 CSS design tokens that were referenced but never defined (`--danger`, `--success`, `--warning`, `--primary`, `--surface-2`, `--lum-40`...), which left several colours and the progress bars unstyled.

### Engineering
- Test suite grew from 61 to 131 unit tests plus an expanded end-to-end run; test fixtures are generated (a binary-manifest/DEX/ZIP builder validated with `aapt`, Python-generated SQLite databases, OpenSSL certificates). Real-APK smoke tests are opt-in via `ADBAUD_APK_DIR`.
- Fixed CI on Node 22 (explicit test glob).
- Service worker cache bumped and new modules precached.

## 2.0.0 - enhancements by 0x0806

Original project by **Sandeep Wawdane**. Every item below was implemented and is covered by
`npm test` (61 unit tests against a mock ADB device) and/or `npm run test:e2e` (headless Chromium).
Protocol code was verified against the mock, not against physical hardware.

### Security hardening
1. Shell injection fixed in file browser (`ls`, download, upload): every argument is POSIX single-quoted. A file named `$(reboot)` is now just a name.
2. Root upload/download no longer builds `su -c "echo ..."` strings; files go through a temp copy (`cp` + sync) which also handles binary data.
3. Package names are validated and quoted in the ADB core (`pm path`) and in every auditor command.
4. Auditor `sanitizePath` (silent character stripping) replaced by real quoting.
5. XSS fixed: device properties are HTML-escaped.
6. XSS fixed: file names, path bar segments and hostile package names.
7. XSS fixed: component names and all report fields.
8. Content-Security-Policy and `no-referrer` policy added.
9. nginx image ships security headers (`nosniff`, `X-Frame-Options`, `Permissions-Policy: usb=(self)`, COOP).
10. HTML report export escapes everything; CSV export neutralises spreadsheet formula injection.
11. Secrets found by scans are reported masked (`abc***(20 chars)`), never verbatim.
12. The log test no longer wipes the device's logcat buffer (`logcat -c`).
13. APK install uses a random temp name (not the user's file name) and checks the ZIP header.
14. Download names are sanitised; object URLs live long enough for the download to start.

### ADB protocol core
15. Reads and writes are serialised, so concurrent commands (e.g. logcat + file browsing) can no longer corrupt the USB stream.
16. Shell timeouts actually work (the parameter was previously ignored).
17. A timeout can no longer desynchronise the packet stream.
18. UTF-8 output split across packets is decoded correctly.
19. Linear-time buffering for USB reads and sync transfers (was quadratic).
20. USB data views honour `byteOffset`.
21. AUTH tokens are signed the way `adb` does it, so a stored key is accepted and the device stops re-prompting on every connect.
22. Correct Android public-key blob (`n0inv`, `rr`).
23. Fixed a latent hang after a stored key was accepted.
24. Sync push chunk size respects the negotiated payload size (devices with 4 KB limits failed before).
25. Oversized socket writes are split.
26. Downloads show real progress (`STAT` size).
27. Packets for closed sockets are dropped instead of leaking memory.
28. Device properties fetched in one round trip, plus patch level, bootloader, verified boot, SELinux, battery temperature.
29. New `streamShell()` and `shellWithStatus()` APIs.
30. Screenshot rejects non-PNG output with a clear message.
31. Split-APK aware `getApkPaths()`.

### Auditor accuracy
32. Backup check fixed (it flagged nearly every app).
33. Debuggable check fixed; bogus "debug certificate" heuristic removed.
34. Deep-link analysis rewritten (the old parser never matched real `dumpsys` output).
35. Exported components parsed from resolver tables, with permission information.
36. Cleartext-traffic logic follows `targetSdk` defaults instead of flagging everything.
37. Noisy always-on findings removed.
38. Signing-scheme detection for current Android versions.
39. One `dumpsys package` per audit (cached) instead of ~10.
40. Unreadable private storage is reported honestly instead of as a pass.

### New security checks and tools
41. Device posture audit (patch age, bootloader, verified boot, SELinux, ADB-over-network, debuggable build).
42. Installation source check.
43. World-readable files inside private app storage.
44. Secret scanner with Luhn validation, JWT, AWS, Google API key and private-key detection.
45. Accessibility-service and notification-listener inventory.
46. Intent-filter analysis wired into the full scan.
47. Improved WebView heuristics.
48. 0-100 risk score per scan.
49. Triage tab: rank every installed app by risk, sortable, CSV export.
50. Network and process viewer.
51. Scan history with "new failures / fixed since last scan".
52. Report export: JSON, Markdown, HTML, CSV and copy-summary.

### UX and features
53. Command palette (Ctrl/Cmd+K).
54. Keyboard shortcuts (Alt+1-6, Alt+R, Alt+D, `?`) - README previously documented shortcuts that did not exist.
55. Accessible modal dialogs replace `confirm()`/`prompt()`.
56. Per-app actions: scan, info, launch, force-stop, clear data, uninstall, copy name.
57. Multi-APK drop installs split APKs with `pm install-multiple`, with upload progress.
58. Split APKs download as a ZIP.
59. File browser: rename, delete, create folder.
60. File browser: filter, sort, bookmarks, text/hex preview.
61. File browser: symlink handling and protection against out-of-order directory loads.
62. Shell: Tab completion, persisted history, streaming commands with Ctrl+C, transcript export, safe `cd`.
63. Logcat: true streaming, minimum level, text or `/regex/` filter, pause, wrap, 5000-line cap.
64. Screenshot: live mode and copy-to-clipboard.
65. Overview: RAM, uptime, security patch, build details, device-info JSON export.
66. Keep-alive detects a sleeping or stale device.
67. Offline-capable PWA (manifest + service worker).
68. Accessibility: skip link, ARIA roles/labels, focus handling, `prefers-reduced-motion`.
69. Banner when WebUSB or a secure context is unavailable.
70. Toast de-duplication and a global unhandled-rejection handler.

### Engineering
71. 61 unit tests plus a scriptable mock ADB device (`node --test`).
72. End-to-end Chromium test with a fake WebUSB device (`npm run test:e2e`).
73. GitHub Actions CI.
74. Dockerfile hardening, `nginx.conf`, healthcheck, `.dockerignore`.
75. README, API and security documentation updated; this changelog and `NOTICE.md`.
76. `package.json` scripts (`test`, `lint`, `test:e2e`, `serve`).
