# Security Considerations

## Overview

ADB Auditor is designed with privacy and security as core principles. This document outlines the security architecture and considerations for using this tool.

## Privacy Architecture

### 100% Client-Side Processing

- All data processing occurs entirely in your browser
- No data is transmitted to any external server
- No analytics or telemetry of any kind
- No user accounts or authentication required

### Data Flow

```
[Android Device] <--USB/WiFi--> [Your Browser] <--WebUSB API--> [ADB Auditor]
                                      ↓
                              [Local Processing Only]
                                      ↓
                              [Results Displayed]
```

### What Data Stays Local

- Device information
- Application lists
- File contents
- Shell command outputs
- Screenshots
- Extracted APK files
- Security scan results

## Security Best Practices

### Before Using

1. **Verify Source**: Only use ADB Auditor from official sources
   - Original: https://github.com/thecybersandeep/adbauditor (Sandeep Wawdane)
   - Enhanced 2.0: https://github.com/0x0806/adbauditor (0x0806)

2. **Check HTTPS**: Ensure you're using HTTPS connection

3. **Update Browser**: Keep your browser updated for latest security patches

### During Use

1. **Authorization**: Only connect to devices you own or have authorization to test

2. **Public Networks**: Avoid using ADB over WiFi on untrusted networks

3. **Screen Lock**: Keep device unlocked only when actively testing

4. **Root Access**: Use root mode only when necessary

### After Use

1. **Revoke Access**: Consider revoking USB debugging authorization after testing

2. **Disable Debugging**: Turn off USB debugging when not in use

3. **Clear Browser Data**: Clear site data if using shared computer

## WebUSB Security

### Browser Protections

- User gesture required for device selection
- Device chooser shows only ADB-compatible devices
- HTTPS required for WebUSB access
- Cross-origin restrictions enforced

### ADB Protocol Security

- RSA key-based authentication
- Keys stored in browser's IndexedDB
- Device must approve each new connection


## Hardening in 2.0 (0x0806)

- Everything originating from the device (file names, properties, package names, logs) is treated as hostile: HTML-escaped on render and never concatenated into HTML.
- Every value placed in a shell command is single-quoted; package names are validated first.
- A Content-Security-Policy restricts scripts to this origin (`script-src 'self'`).
- Scan reports contain masked samples of secrets, never raw values; CSV exports defuse formula injection.
- The only external request is the Google Fonts stylesheet; the CSP allows nothing else.
- Local storage holds only UI preferences, shell history (last 50 commands) and scan summaries; clear site data to remove them. The ADB RSA key is kept in IndexedDB.

## Legal Disclaimer

ADB Auditor is provided for **authorized security testing only**. Users are responsible for:

- Obtaining proper authorization before testing
- Complying with all applicable laws
- Respecting privacy of device owners
- Using the tool ethically and responsibly

**Unauthorized access to devices is illegal.** The authors assume no liability for misuse of this tool.

## Audit Log

There is no server-side audit log. Scan summaries and shell history are stored only in your own browser (see above).

## Third-Party Dependencies

ADB Auditor uses minimal external dependencies:

| Dependency | Purpose | Security Consideration |
|------------|---------|----------------------|
| Google Fonts | Typography | Loaded from Google CDN |

No JavaScript libraries are loaded from external CDNs. All code is self-contained.
