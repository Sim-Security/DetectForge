# DetectForge Scale Test Report

**Generated:** 2026-02-11T20:25:01.125Z
**Total Rules:** 76

## Summary Metrics

| Metric | Value |
|--------|-------|
| Total rules analyzed | 76 |
| Valid rules | 76 (100.0%) |
| Average quality score | 8.9/10 |
| Average TP rate | 87.6% |
| Average FP rate | 0.3% |
| Average field validity | 93.7% |
| Effectiveness pass rate | 59/76 |

## Quality Score Distribution

| Range | Count |
|-------|-------|
| 1-3 | 0 |
| 4-6 | 0 |
| 7-10 | 76 |

## Logsource Distribution

| Logsource | Count |
|-----------|-------|
| process_creation | 23 |
| network_connection | 22 |
| security | 20 |
| registry_set | 5 |
| image_load | 2 |
| ps_script | 2 |
| file_event | 2 |

## Most Common Invalid Fields

| Field | Occurrences |
|-------|-------------|
| EventID | 20 |

## Per-Rule Analysis

| Rule Title | Quality | TP Rate | FP Rate | Field Valid | Issues |
|------------|---------|---------|---------|-------------|--------|
| Suspicious Network Connection to Cloud APIs via No | 9.1 | - | - | 100.0% | none |
| Suspicious Process Injection into System Processes | 9.0 | - | - | 100.0% | none |
| DLL Side-Loading of AppVIsvSubsystems64 via Legiti | 8.8 | - | - | 100.0% | none |
| HTML Smuggling Payload Assembly via PowerShell Scr | 9.0 | - | - | 100.0% | none |
| Suspicious Network Connection to URL Shorteners vi | 8.8 | - | - | 100.0% | none |
| Masquerading WinRAR as VMware Utility | 9.3 | - | - | 100.0% | none |
| Persistence via China Chopper Webshell Registry Mo | 9.0 | - | - | 100.0% | none |
| Exchange Application Impersonation Role Assignment | 8.5 | - | - | 80.0% | invalid-fields |
| Lateral Movement via Impacket Tools (WMI/SMB) Netw | 9.3 | - | - | 100.0% | none |
| Exfiltration to OneDrive via Non-Standard Process | 9.3 | - | - | 100.0% | none |
| Remote Access Tool Network Connection via AnyDesk  | 9.1 | - | - | 100.0% | none |
| Inhibit System Recovery via Vssadmin Shadow Copy D | 9.1 | - | - | 100.0% | none |
| Masquerading SoftPerfect Network Scanner as System | 8.8 | - | - | 100.0% | none |
| Disable or Modify Security Tools via Backstab or P | 8.9 | - | - | 80.0% | invalid-fields |
| LSASS Memory Credential Dumping via Mimikatz | 9.0 | - | - | 100.0% | none |
| Exfiltration to Cloud Storage via RClone to Known  | 8.5 | - | - | 100.0% | none |
| Webshell Persistence via CGI and Python Script Mod | 8.8 | - | - | 100.0% | none |
| Suspicious Exchange Mailbox Permission Manipulatio | 8.0 | - | - | 75.0% | invalid-fields |
| Potential CVE-2023-23397 Exploitation via Outbound | 8.7 | - | - | 75.0% | invalid-fields |
| Internal Spearphishing and Account Discovery via E | 9.0 | - | - | 85.7% | invalid-fields |
| Suspicious Network Pivot via Web Server Process | 9.0 | - | - | 100.0% | none |
| Suspicious Data Staging in Web Directories via Fil | 9.0 | - | - | 100.0% | none |
| Security Tool Exclusion Modification via Scripting | 8.8 | - | - | 100.0% | none |
| Suspicious Network Connection from TeamCity Server | 9.0 | - | - | 100.0% | none |
| Suspicious Network Connection Following Symlink Ev | 8.8 | - | - | 100.0% | none |
| Modification of MaxMpxCt Registry Value for SMB Pe | 8.8 | - | - | 100.0% | none |
| Suspicious Network Connection Initiated by OneNote | 9.0 | - | - | 100.0% | none |
| Suspicious Proxy Tunneling and Geolocation Reconna | 9.1 | - | - | 100.0% | none |
| Suspicious NTDS Database Compression via 7-Zip fro | 9.0 | - | - | 100.0% | none |
| Suspicious NTDS.DIT Extraction and LSASS Dumping v | 9.1 | - | - | 100.0% | none |
| Credential Exfiltration via Compromised Web Portal | 8.0 | - | - | 75.0% | invalid-fields |
| IcedID Execution of DLL Disguised as Image via Pow | 8.3 | - | - | 100.0% | none |
| Creation of Suspicious Scheduled Task for IcedID P | 8.3 | - | - | 80.0% | invalid-fields |
| Suspicious Service Installation for Vulnerable Dri | 9.0 | - | - | 66.7% | invalid-fields |
| Internal Network Service Discovery via Renamed Sca | 9.0 | - | - | 100.0% | none |
| EDR and Antivirus Service Termination via Backstab | 8.3 | - | - | 75.0% | invalid-fields |
| Suspicious Outbound Network Connection from VPN Ap | 9.0 | - | - | 100.0% | none |
| BlackCat Ransomware Execution via Environmental Ke | 9.0 | - | - | 100.0% | none |
| System UUID Discovery via WMIC | 8.8 | - | - | 100.0% | none |
| Inhibit System Recovery via Vssadmin or Bcdedit | 9.1 | - | - | 100.0% | none |
| Suspicious Script Execution for Credential Dumping | 8.0 | - | - | 66.7% | invalid-fields |
| Suspicious Process Spawned by Svchost.exe via Coba | 9.1 | - | - | 100.0% | none |
| Credential Dumping via Registry Hive Export and LS | 9.1 | - | - | 100.0% | none |
| Inhibit System Recovery via Vssadmin Shadow Copy D | 8.8 | - | - | 100.0% | none |
| Suspicious Rundll32 Execution Pattern via Cobalt S | 8.8 | - | - | 100.0% | none |
| Suspicious Exchange Web Services Mailbox Access vi | 9.3 | - | - | 100.0% | none |
| Suspicious Task Manager Launch via Command Shell | 8.8 | - | - | 100.0% | none |
| Nokoyawa Ransomware File Activity and Ransom Note  | 8.8 | - | - | 100.0% | none |
| Data Exfiltration via FileZilla SFTP Connection | 8.8 | - | - | 100.0% | none |
| Suspicious Internal Network Scanning via Reconnais | 9.1 | - | - | 100.0% | none |
| Creation of New User Account for OAuth Consent Per | 8.7 | - | - | 80.0% | invalid-fields |
| Suspicious Scheduled Task Creation Mimicking Secur | 8.7 | - | - | 80.0% | invalid-fields |
| Suspicious Security Log Cleared by User Account | 8.7 | - | - | 66.7% | invalid-fields |
| Remote Access Software Network Connection via RMM  | 9.3 | - | - | 100.0% | none |
| Lateral Movement via Remote Services from VPN Appl | 8.3 | - | - | 75.0% | invalid-fields |
| Exfiltration to Cloud Storage via RClone or WinSCP | 9.3 | - | - | 100.0% | none |
| UAC Bypass via COM Elevation Moniker | 9.0 | - | - | 100.0% | none |
| Potential Password Spraying via Multiple Failed Lo | 9.0 | - | - | 85.7% | invalid-fields |
| Suspicious Outbound Connection from Web Server Pro | 9.0 | - | - | 100.0% | none |
| Potential Defense Evasion via Log Clearing or Serv | 8.6 | - | - | 80.0% | invalid-fields |
| Suspicious Network Connection by Python Dropper vi | 8.8 | - | - | 100.0% | none |
| Discord Execution Flow Hijacking via Malicious Ima | 9.1 | - | - | 100.0% | none |
| Suspicious Network Connection from Python IDE Proc | 9.3 | - | - | 100.0% | none |
| Reflective Code Loading via NSCreateObjectFileImag | 9.0 | - | - | 100.0% | none |
| Suspicious Microsoft Graph or Azure CLI Token Acqu | 9.1 | - | - | 100.0% | none |
| Potential Password Spraying Attack via Windows Sec | 8.3 | - | - | 75.0% | invalid-fields |
| Suspicious Network Connection to Known Residential | 9.1 | - | - | 100.0% | none |
| Potential MFA Fatigue Attack via Repeated Logon Fa | 8.3 | - | - | 66.7% | invalid-fields |
| Unauthorized Device Registration via Windows Secur | 8.3 | - | - | 75.0% | invalid-fields |
| Potential Kerberoasting Activity via Weak Encrypti | 9.0 | - | - | 80.0% | invalid-fields |
| Masquerading as Legitimate Software via Interlock  | 9.3 | - | - | 100.0% | none |
| Indicator Removal via Cleanup DLL File Deletion | 9.1 | - | - | 100.0% | none |
| Exfiltration to Azure Blob Storage via AzCopy or W | 9.1 | - | - | 100.0% | none |
| Persistence via Chrome Updater Registry Run Key | 8.8 | - | - | 100.0% | none |
| Execution of Suspicious PowerShell via Windows Run | 8.8 | - | - | 100.0% | none |
| System Information Discovery via Native Tools and  | 9.1 | - | - | 100.0% | none |
