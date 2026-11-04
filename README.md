# ADB Auditor

<p align="center">
  <img src="img/logo.svg" alt="ADB Auditor Logo" width="120">
</p>

<p align="center">
  <strong>Android Security Auditing Platform</strong><br>
  Created by <a href="https://github.com/thecybersandeep/adbauditor">Sandeep Wawdane</a> &middot; Enhanced &amp; maintained by <a href="https://github.com/0x0806/adbauditor">0x0806</a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Web-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Protocol-WebUSB%20%2B%20ADB-green?style=flat-square" alt="Protocol">
  <img src="https://img.shields.io/badge/Privacy-100%25%20Client--Side-purple?style=flat-square" alt="Privacy">
  <img src="https://img.shields.io/badge/License-CC%20BY--NC--ND%204.0-lightgrey?style=flat-square" alt="License">
</p>

---

## Overview

ADB Auditor is a browser-based Android security auditing tool designed for penetration testers, security researchers, and cybersecurity professionals. It connects to Android devices via WebUSB and provides comprehensive security analysis capabilities without requiring any server-side processing.

**🔒 100% Client-Side** - All data processing happens in your browser. No data is ever uploaded to any server.

## Credits

- **Original author: Sandeep Wawdane** ([@thecybersandeep](https://github.com/thecybersandeep)) - created ADB Auditor, its WebUSB/ADB architecture and UI. Original repository: https://github.com/thecybersandeep/adbauditor
- **v2.0 enhancements: 0x0806** ([@0x0806](https://github.com/0x0806)) - hardened protocol core, rewritten auditor, new tools, tests, accessibility and docs. See [CHANGELOG.md](CHANGELOG.md) (135 itemised changes across 2.0 and 2.1) and [NOTICE.md](NOTICE.md).

## What's new in 2.1

An offline **APK static analyzer** (manifest, signing certificates, DEX indicators), a **SQLite viewer** with WAL support, a **Tools** section (intent launcher, deep-link tester, provider queries, permissions, settings, proxy, screen recording, evidence pack, baseline drift), device-exposure checks, folder ZIP / search / checksum / editor in the file browser, themes, and an activity log. Details in the [changelog](CHANGELOG.md).

## What's new in 2.0

Safer (injection/XSS fixes, CSP), more reliable (serialised USB transport, real timeouts, working key auth), more accurate (backup, debuggable, deep-link and network checks fixed), and more capable (command palette, app triage, device posture audit, streaming logcat, file operations, report export in JSON/Markdown/HTML/CSV, offline mode). Details in the [changelog](CHANGELOG.md).

## Features

| Feature | Description |
|---------|-------------|
| 📱 **App Analysis** | List installed applications, extract APK files, analyze permissions and signatures |
| 📂 **File Browser** | Navigate device filesystem with root support, upload/download files |
| 🗄️ **Storage Audit** | Analyze SharedPreferences, SQLite databases, identify sensitive data exposure |
| 💻 **Shell Access** | Direct ADB shell with command history and autocomplete |
| 📸 **Screenshot** | Capture device screen for documentation and evidence |
| 🔐 **Security Scan** | Automated security checks for common vulnerabilities |
| 📊 **Device Info** | Comprehensive device information and system properties |
| 🧭 **App Triage** | Rank every installed app by risk (debuggable, backup, SDK levels, permissions) |
| 🛡️ **Device Posture** | Patch age, bootloader, verified boot, SELinux, ADB-over-network, accessibility services |
| 📝 **Reports** | Risk score, history/diff, export as JSON, Markdown, HTML or CSV |
| 🔬 **APK Analyzer** | Offline manifest, signing and DEX analysis of any APK |
| 🗃️ **SQLite Viewer** | Browse app databases (including WAL) in the browser |
| 🧰 **Tools** | Intents, providers, permissions, settings, proxy, screen recording, evidence pack |
| ⌨️ **Command Palette** | `Ctrl/Cmd+K` to jump anywhere; full keyboard navigation |
| 📴 **Offline** | Installable PWA; works without a network after the first load |

## Screenshots

### 🔐 Android Security Auditing Dashboard
Modern, client-side Android security auditing interface with WebUSB + ADB support. Connect devices securely and perform deep analysis without uploading data.
  
![ADB Auditor Dashboard](https://github.com/user-attachments/assets/eab09ce1-ce31-44cd-b02d-131fa14d5faa)

---

### 🧩 Local Storage & App Data Analysis (Root)
Analyze application storage with root access, including SharedPreferences, databases, and internal files for advanced security assessments.
  
![ADB File Browser](https://github.com/user-attachments/assets/75fa83b4-e195-488b-9fdc-5fa248cb2e30)
---

### 📁 Root File Browser via ADB
Full-featured file browser powered by ADB with optional root mode, enabling navigation, upload, download, and inspection of device file systems.
  
![Root Storage Analysis](https://github.com/user-attachments/assets/fbd571d0-3790-4f85-b3bd-807c878087f9)


## Requirements

### Browser Support
- Google Chrome 89+
- Microsoft Edge 89+
- Opera 75+

> ⚠️ **Note:** Firefox and Safari do not support WebUSB API

### Device Requirements
- Android device with USB Debugging enabled
- USB data cable (not charge-only)
- For full analysis: Rooted device (optional but recommended)


## Installation

### Option 1: Run Locally (No Hosting Required)

```bash
# Clone the repository
git clone https://github.com/0x0806/adbauditor.git

# Navigate to directory
cd adbauditor

# Open directly in browser (recommended)
google-chrome index.html
```

### Option 2: Self-Host

```
# Clone the repository
git clone https://github.com/0x0806/adbauditor.git

# Navigate to directory
cd adbauditor

# Serve with any static server
python -m http.server 8080
# or
npx serve .
# or
php -S localhost:8080
```

### Option 3: Docker

```
# Using Docker Compose
docker-compose up -d

# Or using Docker directly
docker build -t adbauditor .
docker run -p 8080:80 adbauditor
```

Access at `http://localhost:8080`

## Usage

### Quick Start

1. **Enable USB Debugging** on your Android device:
   - Go to `Settings` → `About Phone`
   - Tap `Build Number` 7 times to enable Developer Options
   - Go to `Settings` → `Developer Options`
   - Enable `USB Debugging`

2. **Connect your device** via USB cable

3. **Open ADB Auditor** in Chrome/Edge

4. **Click "Connect"** and select your device from the browser popup

5. **Accept the USB debugging prompt** on your device


## Documentation

### File Structure

```
adbauditor/
├── js/
│   ├── utils.js            # Shared pure helpers (quoting, parsing, ZIP, reports)
│   ├── adb-core.js         # ADB protocol implementation
│   ├── security-auditor.js # Security scanning module
│   ├── apk-analyzer.js     # Offline APK static analysis
│   ├── sqlite-reader.js    # Read-only SQLite reader
│   ├── toolkit.js          # Validated device-control commands
│   ├── tools-ui.js         # Tools section UI, settings, theme
│   ├── app.js              # Main application logic
│   └── register-sw.js      # Service worker registration
├── tests/                  # node:test unit tests, mock ADB device, Chromium e2e
├── docs/                   # API.md, SECURITY.md
├── img/logo.svg
├── index.html, 404.html, sw.js, manifest.webmanifest
├── CHANGELOG.md, NOTICE.md, LICENSE
└── Dockerfile, nginx.conf, docker-compose.yml, .github/workflows/ci.yml
```

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Alt + 1-7` | Switch section |
| `Alt + R` | Refresh current view |
| `Alt + D` | Disconnect device |
| `Ctrl/Cmd + K` | Command palette |
| `?` | Shortcut help |
| `Tab` / `↑` `↓` | Shell: autocomplete / history |
| `Ctrl + C` / `Ctrl + L` | Shell: stop streaming command / clear |

### Development & Testing

```bash
npm run lint       # syntax check
npm test           # 114 unit tests (mock ADB device, auditor, APK analyzer, SQLite, toolkit)
npm run test:e2e   # headless Chromium with a fake WebUSB device
```

Protocol and device-control code is tested against a scriptable mock device, not physical hardware. Set `ADBAUD_APK_DIR` to a folder of your own APKs to smoke-test the analyzer on real files.

## Privacy & Security

- **Zero Data Upload**: All processing is done locally in your browser
- **No Tracking**: No analytics, telemetry, or tracking of any kind
- **No Account Required**: Use immediately without registration
- **Open Source**: Full source code available for audit

## Troubleshooting

### Device Not Detected

1. Try a different USB cable (ensure it's a data cable)
2. Try a different USB port
3. Revoke USB debugging authorizations and re-authorize
4. Restart ADB on device: `adb kill-server && adb start-server`

### Connection Lost

1. Check USB cable connection
2. Disable battery optimization for USB debugging
3. Keep device screen on during transfer

### Permission Denied

1. Enable Root toggle for protected directories
2. Grant root access on device when prompted
3. Some system files may still be inaccessible



## License

This project is licensed under CC BY-NC-ND 4.0, Copyright (c) 2026 Sandeep (original author). See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md). Note that the NoDerivatives term means modified versions should be distributed only with the original author's permission.



## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before testing any device. The authors are not responsible for any misuse of this tool.



---

<p align="center">
  Made with ❤️ for the Security Community<br>
  Created by Sandeep Wawdane · Enhanced by 0x0806
</p>

<p align="center">
  <a href="https://github.com/0x0806/adbauditor/stargazers">⭐ Star this repo</a> if you find it useful!
</p>
