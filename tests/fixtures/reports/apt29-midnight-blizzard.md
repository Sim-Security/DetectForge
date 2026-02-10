# Midnight Blizzard: Guidance for Responders on Nation-State Attack

**Source:** Microsoft Threat Intelligence
**Date:** January 25, 2024
**Threat Actor:** Midnight Blizzard (APT29 / Cozy Bear / NOBELIUM)

---

## Overview

Microsoft identified a nation-state attack on our corporate systems on January 12, 2024, and immediately activated our response process to investigate, disrupt malicious activity, mitigate the attack, and deny the threat actor further access. Beginning in late November 2023, the threat actor used a password spray attack to compromise a legacy non-production test tenant account and gain a foothold, and then used the account's permissions to access a very small percentage of Microsoft corporate email accounts.

## Technical Details

### Initial Access

The threat actor conducted password spray attacks against Microsoft's infrastructure. The password spray activity used a low volume of attempts to evade detection, launching attacks from a distributed residential proxy infrastructure. The actor targeted a legacy test OAuth application that had elevated access to the Microsoft corporate environment.

The compromised test account had access to an OAuth application with elevated permissions to the Microsoft corporate environment. The threat actor created additional malicious OAuth applications. They created a new user account to grant consent in the Microsoft corporate environment to the actor-controlled malicious OAuth applications.

### Persistence and Lateral Movement

The threat actor used the initial access to identify and compromise a legacy test OAuth application that had elevated access. The actor then leveraged this OAuth app's permissions to:

1. Create additional malicious OAuth applications
2. Create new user accounts to grant consent to the malicious OAuth applications
3. Use these OAuth applications to authenticate to Microsoft Exchange Online
4. Target Microsoft corporate email mailboxes of senior leadership and cybersecurity team members

### Email Access

The threat actor used the OAuth applications to authenticate to Microsoft Exchange Online and target email mailboxes including members of our senior leadership team and employees in our cybersecurity, legal, and other functions. Some emails and attached documents were exfiltrated.

### Command and Control Infrastructure

Midnight Blizzard was observed using the following infrastructure:
- IP addresses from residential proxy networks (rotating IPs)
- Authentication from IP addresses: 195.178.120[.]25, 193.176.86[.]157, 185.248.85[.]18
- User-Agent strings mimicking legitimate browsers
- OAuth token-based access to Exchange Online

### Indicators of Compromise

**IP Addresses (C2/Authentication):**
- 195.178.120[.]25
- 193.176.86[.]157
- 185.248.85[.]18
- 91.193.18[.]11
- 185.174.137[.]26

**Domains:**
- No specific malicious domains disclosed in this advisory

**File Hashes:**
- No specific file hashes disclosed (email-based attack, no malware deployment)

**OAuth Application IDs:**
- Malicious OAuth applications were created but specific App IDs were not publicly shared

**Email Subjects Used in Exfiltration:**
- Targeted senior leadership and cybersecurity team mailboxes

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access, Persistence |
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Defense Evasion, Lateral Movement |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Persistence |
| T1098.002 | Account Manipulation: Additional Email Delegate Permissions | Persistence |
| T1136.003 | Create Account: Cloud Account | Persistence |
| T1114.002 | Email Collection: Remote Email Collection | Collection |
| T1199 | Trusted Relationship | Initial Access |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |

## Detection Recommendations

1. **Monitor OAuth application registrations** — Alert on new OAuth application creation, especially from non-admin accounts
2. **Monitor consent grants** — Alert when users grant consent to OAuth applications, especially for Mail.Read or Mail.ReadWrite permissions
3. **Monitor Azure AD sign-in logs** — Look for password spray indicators: many failed logins from distributed IPs targeting multiple accounts
4. **Monitor Exchange Online access** — Alert on email access from newly created OAuth applications
5. **Monitor for residential proxy usage** — Flag logins from known residential proxy IP ranges

## Remediation

- Revoke sessions and credentials for compromised accounts
- Remove malicious OAuth applications
- Review and reduce OAuth application permissions
- Enable conditional access policies requiring compliant devices
- Implement phishing-resistant MFA
