# Scattered Spider: Social Engineering and Identity Attacks

**Source:** CrowdStrike / Microsoft
**Date:** 2023-2024
**Threat Actor:** Scattered Spider / UNC3944 / Octo Tempest

---

## Overview

Scattered Spider is a financially motivated threat group known for sophisticated social engineering attacks targeting IT help desks and identity providers. The group specializes in SIM swapping, MFA fatigue attacks, and IT help desk social engineering to gain initial access to organizations, then leverages identity providers (Okta, Azure AD) to move laterally and deploy ransomware or steal data. The group has targeted telecommunications, technology, and hospitality sectors.

## Technical Details

### Initial Access — Social Engineering

**IT Help Desk Attacks:**
The threat actors call IT help desks impersonating employees, using publicly available information to pass identity verification. They request password resets or MFA device enrollment for targeted accounts.

**SIM Swapping:**
Port victim's phone number to attacker-controlled SIM card to intercept SMS-based MFA codes. Used T-Mobile, Verizon, and AT&T stores or social engineering carrier support.

**MFA Fatigue / Push Bombing:**
Repeatedly trigger MFA push notifications until the victim accepts out of frustration:
- Sent 50+ push notifications over several hours
- Combined with phishing messages claiming "Approve to stop the notifications"

**Phishing:**
Targeted phishing campaigns using adversary-in-the-middle (AiTM) toolkits:
- EvilProxy or Evilginx2 to capture session tokens
- Phishing domains mimicking Okta login pages: `[company]-okta[.]com`, `[company]-sso[.]com`

### Execution and Persistence

After gaining access to a user account:

1. **Okta/Azure AD manipulation:**
   - Added attacker-controlled MFA device to compromised account
   - Created new user accounts in Okta: `svc-backup01@company.com`
   - Assigned admin roles to compromised accounts
   - Modified conditional access policies to allow attacker IPs

2. **Cloud infrastructure access:**
   - AWS Console login with federated credentials
   - `aws sts assume-role --role-arn arn:aws:iam::123456789:role/admin-role`
   - Created new IAM users and access keys
   - S3 bucket enumeration: `aws s3 ls`

3. **Azure AD persistence:**
   - Created new service principals
   - Added credentials to existing applications
   - `az ad sp create-for-rbac --name "backup-service" --role Contributor`

### Discovery

Extensive cloud and identity reconnaissance:
```
# Okta enumeration
GET /api/v1/users?limit=200
GET /api/v1/groups
GET /api/v1/apps

# Azure AD enumeration
az ad user list --query "[].{Name:displayName,UPN:userPrincipalName}"
az role assignment list
az vm list

# AWS enumeration
aws iam list-users
aws ec2 describe-instances
aws s3api list-buckets
```

### Lateral Movement

- Cross-cloud movement using federated identity
- Access to SaaS applications (Salesforce, ServiceNow, SharePoint) via SSO
- Used Remote Monitoring and Management (RMM) tools: AnyDesk, TeamViewer, Splashtop

### Exfiltration

- Downloaded SharePoint/OneDrive files via Microsoft Graph API
- Exfiltrated data from AWS S3 buckets
- Used cloud storage services for staging (Google Drive, Dropbox)
- `aws s3 cp s3://company-data-bucket/ /tmp/exfil/ --recursive`

### Impact

In some cases, deployed BlackCat/ALPHV ransomware:
- Encrypted VMware ESXi environments
- Ransomed organizations for $1M-$20M+

### Indicators of Compromise

**IP Addresses:**
- 104.194.222[.]71 (VPN infrastructure)
- 198.44.136[.]180 (C2)
- 159.223.238[.]225 (Phishing infrastructure)
- 137.184.61[.]231 (AiTM proxy)

**Domains:**
- [company]-okta[.]com (phishing — varies per target)
- [company]-sso[.]com (phishing — varies per target)
- login-microsoftonline[.]com (credential phishing)
- loginokta[.]com (credential phishing)

**Tools:**
- EvilProxy / Evilginx2 (AiTM phishing)
- AnyDesk
- TeamViewer
- Splashtop
- ALPHV/BlackCat ransomware (in some cases)

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1566.004 | Phishing: Spearphishing Voice | Initial Access |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access, Persistence |
| T1621 | Multi-Factor Authentication Request Generation | Credential Access |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | Credential Access, Defense Evasion |
| T1136.003 | Create Account: Cloud Account | Persistence |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Persistence |
| T1538 | Cloud Service Dashboard | Discovery |
| T1580 | Cloud Infrastructure Discovery | Discovery |
| T1530 | Data from Cloud Storage | Collection |
| T1219 | Remote Access Software | Command and Control |
| T1537 | Transfer Data to Cloud Account | Exfiltration |
| T1486 | Data Encrypted for Impact | Impact |
