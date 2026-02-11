# SVR Cyber Actors Adapt Tactics for Initial Cloud Access (CISA AA24-057A)

## Executive Summary
APT29, also known as Midnight Blizzard, the Dukes, and Cozy Bear, is a cyber espionage group assessed to be part of Russia's Foreign Intelligence Service (SVR). As organizations modernize to cloud infrastructure, APT29 has adapted their TTPs to target cloud environments. This advisory details their cloud-focused initial access techniques including service account compromise, token theft, MFA bypass, and residential proxy use.

## Indicators of Compromise

### Behavioral Indicators
- Authentication attempts from residential IP address ranges against service accounts
- Successful authentication to dormant or unused service accounts
- Anomalous device enrollment events on cloud tenants
- Unusual OAuth token usage patterns or token replay from different source IPs
- Multiple rapid MFA push notifications to a single user (MFA bombing)
- System account access from non-expected geographic locations

### Targeted Services
- Microsoft 365 / Azure AD
- Cloud-based email platforms
- Identity providers supporting OAuth/OIDC
- VPN gateways without MFA enforcement

## Attack Chain

1. **Initial Access - Brute Force (T1110)**: SVR actors conduct systematic password spraying and brute force campaigns against cloud service accounts, targeting accounts that:
   - Lack multi-factor authentication
   - Are dormant or not actively monitored
   - Have system/service account permissions
   - Were created for automated processes

2. **Initial Access - Valid Cloud Accounts (T1078.004)**: Actors use previously compromised cloud credentials obtained through prior operations, infostealer malware, or credential dumps. Focus on service accounts with elevated permissions that often lack MFA requirements.

3. **Credential Access - Token Theft (T1528)**: Stolen OAuth tokens and application access tokens allow actors to bypass password authentication entirely. Tokens are harvested from compromised endpoints, browser sessions, or intercepted authentication flows.

4. **Credential Access - MFA Bombing (T1621)**: SVR actors repeatedly push MFA notifications to targets, exploiting notification fatigue. Users eventually approve a fraudulent request, granting the attacker authenticated access.

5. **Command and Control - Residential Proxies (T1090.002)**: To evade detection based on IP reputation or geolocation anomalies, actors route traffic through residential proxy networks. This makes malicious authentication appear to originate from consumer ISP ranges rather than known VPN or hosting infrastructure.

6. **Persistence - Device Registration (T1098.005)**: After gaining access, actors register their own devices on the compromised cloud tenant. Registered devices receive persistent tokens and bypass conditional access policies that restrict unmanaged devices.

7. **Collection and Exfiltration**: With persistent cloud access, SVR actors access email content, SharePoint/OneDrive files, and Teams communications. Data is exfiltrated through legitimate cloud APIs to avoid network-level detection.

## Key TTPs Summary

| Tactic | Technique ID | Technique Name | Description |
|--------|-------------|----------------|-------------|
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | Using compromised cloud credentials |
| Credential Access | T1110 | Brute Force | Password spraying against service accounts |
| Credential Access | T1528 | Steal Application Access Token | OAuth/OIDC token theft and replay |
| Credential Access | T1621 | MFA Request Generation | MFA push notification bombing |
| Persistence | T1098.005 | Account Manipulation: Device Registration | Registering unauthorized devices |
| Command and Control | T1090.002 | Proxy: External Proxy | Residential proxy infrastructure |

## Recommendations
- Enforce MFA on all accounts including service accounts
- Disable and remove dormant accounts
- Use number-matching or FIDO2 for MFA (resistant to MFA bombing)
- Limit token validity periods
- Restrict device enrollment policies to managed devices only
- Monitor for authentication from residential IP ranges to service accounts
- Enable conditional access policies requiring compliant devices
- Review and audit OAuth application permissions

Source: CISA Advisory AA24-057A (https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a)
