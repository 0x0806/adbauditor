# Changelog

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
