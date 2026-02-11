# StopRansomware: Interlock (CISA AA25-203A)

## Executive Summary
Interlock is a ransomware variant first observed in late September 2024, targeting organizations in North America and Europe across healthcare, technology, government, and manufacturing sectors. The group employs a double-extortion model with sophisticated initial access techniques including drive-by compromise and ClickFix social engineering.

## Indicators of Compromise

### File Hashes (SHA-256)
- Encryption binary: e86bb8361c436be94b0901e5b39db9b6666134f23cce1e5581421c2981405cb1
- Encryption binary: c733d85f445004c9d6918f7c09a1e0d38a8f3b37ad825cd544b865dba36a1ba6
- Credential stealer (cht.exe): C20BABA26EBB596DE14B403B9F78DDC3C13CE9870EEA332476AC2C1DD582AA07
- Keylogger DLL (klg.dll): A4F0B68052E8DA9A80B70407A92400C6A5DEF19717E0240AC608612476E1137E
- SystemBC cleanup DLL: 1845a910dcde8c6e45ad2e0c48439e5ab8bbbeb731f2af11a1b7bbab3bfe0127

### Malicious File Names
- Fake browser updates: FortiClient.exe, GlobalProtect.exe, Webex.exe, AnyConnectVPN.exe
- Encryption binary: conhost.exe (mimics Windows Console Host)
- Ransom note: !__README__!.txt
- Keylogger output: conhost.txt
- Cleanup DLL: tmp41.wasd
- Keylogger DLL: klg.dll

### Registry Keys
- Persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Chrome Updater

## Attack Chain

1. **Initial Access (T1189, T1204.004)**: Interlock gains entry through drive-by downloads from compromised legitimate websites, fake software updates mimicking Chrome, Edge, or security applications, and ClickFix social engineering where victims see fake CAPTCHA prompts instructing them to open a Run window (Windows+R), paste clipboard contents, and execute a Base64-encoded PowerShell command.

2. **Execution (T1059.001)**: The fake Google Chrome browser executable functions as a remote access trojan that executes a PowerShell script dropping a file into the Windows Startup folder. PowerShell is used extensively for reconnaissance and persistence establishment.

3. **Persistence (T1547.001)**: Registry Run key created at HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Chrome Updater pointing to a malicious log file (autorun.log). This executes on user login.

4. **Reconnaissance (T1033, T1082, T1007, T1016)**: PowerShell commands enumerate system details:
   - WindowsIdentity.GetCurrent() for current user identification
   - systeminfo for OS configuration
   - tasklist /svc for running services
   - Get-Service for service status
   - Get-PSDrive for mounted drives and network shares
   - arp -a for ARP cache inspection

5. **Defense Evasion (T1036.005, T1218.011, T1070.004)**: Masquerading payloads as legitimate software (FortiClient, GlobalProtect, Webex). Cleanup DLL executed via rundll32.exe to delete encryption binary after use. File deletion to remove forensic artifacts.

6. **Credential Access (T1555.003, T1056.001, T1558.003)**: Credential stealer binary (cht.exe) harvests browser passwords and stored credentials. Keylogger DLL (klg.dll) captures keystrokes to conhost.txt. Kerberoasting attacks against Active Directory domain controllers.

7. **Lateral Movement (T1078.002, T1021.001, T1219)**: RDP using stolen domain credentials. Legitimate remote tools: AnyDesk, PuTTY, ScreenConnect for additional access.

8. **Exfiltration (T1567.002, T1048)**: Azure Storage Explorer used to identify and access cloud storage. AzCopy uploads data to Azure blob storage. WinSCP for alternative file transfer.

9. **Impact (T1486)**: 64-bit executable conhost.exe encrypts files using combined AES-RSA algorithm across Windows, Linux, and FreeBSD. File extension: .interlock or .1nt3rlock. Ransom note !__README__!.txt provides victim code and Tor .onion URL for negotiation.

## Recommendations
- Block execution of unknown executables from user-writable directories
- Monitor for PowerShell Base64-encoded command execution
- Detect Registry Run key modifications
- Monitor for credential access tools and Kerberoasting
- Alert on Azure Storage Explorer and AzCopy usage in non-standard contexts
- Deploy application whitelisting
- Implement network segmentation

Source: CISA Advisory AA25-203A (https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a)
