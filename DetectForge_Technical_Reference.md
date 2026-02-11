# DetectForge Technical Reference Document

## Comprehensive Specifications for Detection Rule Generation

---

# Table of Contents

1. [Sigma Rule Specification](#1-sigma-rule-specification)
2. [SigmaHQ Repository Structure](#2-sigmahq-repository-structure)
3. [YARA Rule Specification](#3-yara-rule-specification)
4. [Suricata Rule Format](#4-suricata-rule-format)
5. [MITRE ATT&CK Programmatic Access](#5-mitre-attck-programmatic-access)
6. [Sigma CLI / pySigma Toolchain](#6-sigma-cli--pysigma-toolchain)
7. [Public APT Report Sources](#7-public-apt-report-sources)
8. [Existing Detection-as-Code Tools](#8-existing-detection-as-code-tools)

---

# 1. Sigma Rule Specification

## 1.1 Overview

Sigma is a generic and open signature format for SIEM systems. It allows security analysts to describe log detection patterns in a structured YAML format that can be converted to queries for any SIEM backend (Splunk, Elastic, Microsoft Sentinel, etc.).

- **Specification Repository**: https://github.com/SigmaHQ/sigma-specification
- **Main Rule Repository**: https://github.com/SigmaHQ/sigma
- **Website**: https://sigmahq.io/
- **Current Specification Version**: Sigma v2 (SigmaHQ adopted pySigma-based tooling)

## 1.2 Complete YAML Schema

```yaml
# === REQUIRED FIELDS ===
title: <string>           # Short, descriptive title (max ~256 chars)
logsource:                # Log source definition
    category: <string>    # Generic log source category
    product: <string>     # Product name
    service: <string>     # Service/log channel
detection:                # Detection logic (at least one named condition)
    selection:            # Named detection item(s)
        fieldname: value
    condition: selection  # Boolean logic combining named items

# === RECOMMENDED FIELDS ===
id: <uuid>                # Unique UUID v4 identifier
status: <string>          # Rule maturity: test | stable | experimental | deprecated | unsupported
level: <string>           # Severity: informational | low | medium | high | critical
description: <string>     # Detailed description of what the rule detects
author: <string>          # Rule author(s)
date: <YYYY-MM-DD>        # Creation date (ISO 8601, no slashes)
modified: <YYYY-MM-DD>    # Last modification date

# === OPTIONAL FIELDS ===
references:               # List of reference URLs
    - <url>
tags:                     # MITRE ATT&CK tags and other classifiers
    - attack.t1059.001    # Technique ID (lowercase)
    - attack.execution    # Tactic name (lowercase)
    - cve.2021-44228      # CVE references
falsepositives:           # Known false positive scenarios
    - <string>
fields:                   # Interesting fields to display in results
    - <fieldname>
related:                  # Related rules
    - id: <uuid>
      type: derived | obsoletes | merged | renamed | similar
```

## 1.3 Logsource Specification

The `logsource` field defines where to look for events. It uses three optional sub-fields (at least one must be present):

### Categories (Generic, Product-Independent)

| Category | Description | Example Products |
|---|---|---|
| `process_creation` | Process start events | Sysmon EID 1, Windows 4688 |
| `process_access` | Process memory access | Sysmon EID 10 |
| `image_load` | DLL/module loading | Sysmon EID 7 |
| `file_event` | File creation/modification | Sysmon EID 11 |
| `file_change` | File modification | Sysmon EID 2 |
| `file_rename` | File rename events | Sysmon EID |
| `file_delete` | File deletion | Sysmon EID 23, 26 |
| `file_access` | File access events | Various EDR |
| `registry_set` | Registry value set | Sysmon EID 13 |
| `registry_add` | Registry key creation | Sysmon EID 12 |
| `registry_delete` | Registry key/value deletion | Sysmon EID 12 |
| `registry_event` | Any registry event | Sysmon EID 12, 13, 14 |
| `network_connection` | Outbound network conn | Sysmon EID 3 |
| `firewall` | Firewall events | Various |
| `dns_query` | DNS resolution events | Sysmon EID 22 |
| `dns` | DNS server logs | Various DNS servers |
| `proxy` | Web proxy logs | Squid, Zscaler, etc. |
| `webserver` | Web server access logs | Apache, Nginx, IIS |
| `ps_module` | PowerShell module logging | Windows PS EID 4103 |
| `ps_script` | PowerShell script block | Windows PS EID 4104 |
| `ps_classic_start` | PowerShell classic start | Windows PS EID 400 |
| `pipe_created` | Named pipe creation | Sysmon EID 17 |
| `driver_load` | Driver loading events | Sysmon EID 6 |
| `wmi_event` | WMI event subscription | Sysmon EID 19, 20, 21 |
| `create_remote_thread` | Remote thread creation | Sysmon EID 8 |
| `create_stream_hash` | ADS creation | Sysmon EID 15 |
| `clipboard_capture` | Clipboard monitoring | Sysmon EID 24 |
| `sysmon_error` | Sysmon operational errors | Sysmon EID 255 |
| `sysmon_status` | Sysmon status events | Sysmon EID 16 |
| `antivirus` | AV detection events | Various AV products |

### Products

| Product | Description |
|---|---|
| `windows` | Microsoft Windows |
| `linux` | Linux systems |
| `macos` | Apple macOS |
| `azure` | Microsoft Azure |
| `aws` | Amazon Web Services |
| `gcp` | Google Cloud Platform |
| `m365` | Microsoft 365 |
| `okta` | Okta identity |
| `github` | GitHub audit logs |
| `zeek` | Zeek network monitor |

### Services (Windows-specific examples)

| Service | Maps To |
|---|---|
| `security` | Windows Security Event Log |
| `system` | Windows System Event Log |
| `application` | Windows Application Event Log |
| `sysmon` | Microsoft-Windows-Sysmon/Operational |
| `powershell` | Microsoft-Windows-PowerShell/Operational |
| `powershell-classic` | Windows PowerShell |
| `taskscheduler` | Microsoft-Windows-TaskScheduler/Operational |
| `wmi` | Microsoft-Windows-WMI-Activity/Operational |
| `dns-server` | Microsoft-Windows-DNS-Server/Audit |
| `driver-framework` | Microsoft-Windows-DriverFrameworks-UserMode/Operational |
| `firewall-as` | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall |
| `bits-client` | Microsoft-Windows-Bits-Client/Operational |
| `windefend` | Microsoft-Windows-Windows Defender/Operational |
| `applocker` | Microsoft-Windows-AppLocker/* |
| `msexchange-management` | MSExchange Management |
| `microsoft-servicebus-client` | Microsoft-ServiceBus-Client |
| `ldap_debug` | Microsoft-Windows-LDAP-Client/Debug |
| `codeintegrity-operational` | Microsoft-Windows-CodeIntegrity/Operational |
| `smbclient-security` | Microsoft-Windows-SmbClient/Security |
| `openssh` | OpenSSH/Operational |
| `printservice-admin` | Microsoft-Windows-PrintService/Admin |
| `printservice-operational` | Microsoft-Windows-PrintService/Operational |
| `terminalservices-localsessionmanager` | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational |

## 1.4 Detection Logic Syntax

### Field Matching

```yaml
detection:
    # Simple string match (case-insensitive by default)
    selection:
        CommandLine: 'whoami'

    # List of values (OR logic within the list)
    selection:
        CommandLine:
            - 'whoami'
            - 'ipconfig'
            - 'net user'

    # Wildcards (* and ?)
    selection:
        CommandLine|contains: 'mimikatz'
        ParentImage|endswith: '\cmd.exe'
        Image|startswith: 'C:\Users\Public'

    # Multiple fields in one selection (AND logic between fields)
    selection:
        ParentImage|endswith: '\winword.exe'
        Image|endswith: '\cmd.exe'

    condition: selection
```

### Value Modifiers (Applied with | Pipe Syntax)

| Modifier | Description | Example |
|---|---|---|
| `contains` | Substring match | `field|contains: 'malware'` |
| `startswith` | Prefix match | `field|startswith: 'C:\Temp'` |
| `endswith` | Suffix match | `field|endswith: '.exe'` |
| `base64` | Match base64 encoded value | `field|base64: 'command'` |
| `base64offset` | Match base64 with offset variants | `field|base64offset: 'cmd'` |
| `utf16le` | UTF-16 LE encoding | `field|utf16le|base64: 'text'` |
| `utf16be` | UTF-16 BE encoding | `field|utf16be|base64: 'text'` |
| `wide` | Alias for utf16le | `field|wide|base64: 'text'` |
| `re` | Regular expression match | `field|re: '.*\\\\(cmd|powershell)\\.exe'` |
| `cidr` | CIDR network matching | `DestinationIp|cidr: '10.0.0.0/8'` |
| `all` | All values must match (AND) | `field|all|contains: [val1, val2]` |
| `windash` | Match - and / variants | `CommandLine|windash|contains: '-enc'` |
| `exists` | Field existence check | `field|exists: true` or `false` |
| `expand` | Expand placeholders | `field|expand: '%variable%'` |
| `gt` | Greater than (numeric) | `field|gt: 100` |
| `gte` | Greater than or equal | `field|gte: 100` |
| `lt` | Less than | `field|lt: 10` |
| `lte` | Less than or equal | `field|lte: 10` |

Modifiers can be chained: `CommandLine|contains|all`, `field|utf16le|base64offset`

### Condition Syntax

The `condition` field uses boolean algebra to combine named detection items:

```yaml
detection:
    selection1:
        Image|endswith: '\cmd.exe'
    selection2:
        CommandLine|contains: '/c'
    filter_legit:
        ParentImage|endswith: '\svchost.exe'
    filter_user:
        User|contains: 'SYSTEM'

    # Boolean operators: and, or, not
    # Parentheses for grouping
    # Quantifiers: 1 of, all of, <N> of

    condition: selection1 and selection2 and not filter_legit and not filter_user
```

**Condition Operators:**

| Operator | Description | Example |
|---|---|---|
| `and` | Logical AND | `sel1 and sel2` |
| `or` | Logical OR | `sel1 or sel2` |
| `not` | Logical NOT | `not filter1` |
| `( )` | Grouping | `sel1 and (sel2 or sel3)` |
| `1 of selection*` | Any one of matching items | `1 of selection*` |
| `all of selection*` | All matching items | `all of selection*` |
| `1 of them` | Any one of all named items | `1 of them` |
| `all of them` | All named items must match | `all of them` |
| `<N> of selection*` | N of matching items | `2 of selection*` |
| `1 of filter*` | Any one of filter items | `selection and not 1 of filter*` |

### Timeframe Aggregation (Sigma v2 / Near-Time)

```yaml
detection:
    selection:
        EventID: 4625
    condition: selection | count() > 10
    # Also supports: count(fieldname), min, max, avg, sum
    # Timeframe defined at rule level:
timeframe: 5m   # Supports s (seconds), m (minutes), h (hours), d (days)
```

## 1.5 Complete Example Rule

```yaml
title: Suspicious Encoded PowerShell Command Line
id: f26c6093-6f14-4b12-800f-0571728ff8c1
status: test
description: Detects suspicious encoded PowerShell command lines commonly used by malware and attack tools
references:
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe
author: Florian Roth (Nextron Systems)
date: 2022/09/15
modified: 2023/01/05
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    selection_cli:
        CommandLine|contains|windash:
            - '-e '
            - '-en '
            - '-enc '
            - '-enco'
            - '-encodedcommand'
    selection_encoded:
        CommandLine|base64offset|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
    condition: all of selection_*
falsepositives:
    - Legitimate encoded PowerShell scripts from IT administration tools
    - Some EDR/monitoring agents
level: high
fields:
    - CommandLine
    - ParentImage
    - User
```

## 1.6 Field Name Conventions

Sigma uses standardized field names across products. Key field name mappings:

| Sigma Field | Sysmon | Windows Security | Description |
|---|---|---|---|
| `Image` | Image | NewProcessName | Full exe path |
| `OriginalFileName` | OriginalFileName | - | PE original name |
| `CommandLine` | CommandLine | CommandLine (4688) | Process CLI |
| `ParentImage` | ParentImage | ParentProcessName | Parent exe path |
| `ParentCommandLine` | ParentCommandLine | - | Parent CLI |
| `User` | User | SubjectUserName | User context |
| `IntegrityLevel` | IntegrityLevel | - | Process integrity |
| `Hashes` | Hashes | - | File hashes |
| `md5` | - | - | Extracted MD5 |
| `sha256` | - | - | Extracted SHA256 |
| `TargetFilename` | TargetFilename | - | Target file |
| `SourceIp` | SourceIp | - | Source IP |
| `DestinationIp` | DestinationIp | - | Dest IP |
| `DestinationPort` | DestinationPort | - | Dest port |
| `DestinationHostname` | DestinationHostname | - | Dest hostname |
| `EventID` | - | EventID | Windows EID |
| `TargetObject` | TargetObject | - | Registry target |
| `Details` | Details | - | Registry value |

---

# 2. SigmaHQ Repository Structure

## 2.1 Repository URL and Stats

- **Repository**: https://github.com/SigmaHQ/sigma
- **Rules Count**: 3,000+ detection rules (as of early 2025, growing continuously)
- **Contributors**: 500+ community contributors
- **License**: Detection Rule License (DRL) 1.1

## 2.2 Directory Structure

```
sigma/
├── rules/                          # Main rules directory
│   ├── windows/                    # Windows detection rules
│   │   ├── process_creation/       # Process creation events (largest category)
│   │   ├── image_load/             # DLL loading events
│   │   ├── file/                   # File system events
│   │   │   ├── file_event/
│   │   │   ├── file_change/
│   │   │   ├── file_delete/
│   │   │   ├── file_rename/
│   │   │   └── file_access/
│   │   ├── registry/               # Registry events
│   │   │   ├── registry_set/
│   │   │   ├── registry_add/
│   │   │   ├── registry_delete/
│   │   │   └── registry_event/
│   │   ├── network_connection/     # Outbound connections
│   │   ├── dns_query/              # DNS resolution
│   │   ├── pipe_created/           # Named pipes
│   │   ├── ps_module/              # PowerShell module logs
│   │   ├── ps_script/              # PowerShell script blocks
│   │   ├── ps_classic/             # PowerShell classic logs
│   │   ├── driver_load/            # Driver loading
│   │   ├── create_remote_thread/   # Remote thread injection
│   │   ├── wmi_event/              # WMI persistence
│   │   ├── clipboard_capture/      # Clipboard monitoring
│   │   ├── create_stream_hash/     # ADS (Alternate Data Streams)
│   │   ├── builtin/                # Windows built-in event logs
│   │   │   ├── security/           # Security event log rules
│   │   │   ├── system/             # System event log rules
│   │   │   ├── application/        # Application event log rules
│   │   │   ├── windefend/          # Windows Defender rules
│   │   │   ├── applocker/          # AppLocker rules
│   │   │   ├── bits-client/        # BITS rules
│   │   │   ├── firewall-as/        # Firewall rules
│   │   │   ├── msexchange/         # Exchange rules
│   │   │   ├── ntlm/              # NTLM authentication rules
│   │   │   ├── openssh/           # OpenSSH rules
│   │   │   ├── ldap/              # LDAP rules
│   │   │   ├── dns-server/        # DNS Server rules
│   │   │   ├── smbclient/         # SMB client rules
│   │   │   ├── codeintegrity/     # Code integrity rules
│   │   │   ├── terminalservices/  # RDP rules
│   │   │   └── taskscheduler/     # Task Scheduler rules
│   │   └── sysmon/                 # Sysmon-specific rules
│   ├── linux/                      # Linux detection rules
│   │   ├── process_creation/
│   │   ├── file_event/
│   │   ├── network_connection/
│   │   ├── auditd/                # Linux Audit daemon
│   │   └── builtin/
│   │       ├── syslog/
│   │       ├── auth/
│   │       ├── sudo/
│   │       └── cron/
│   ├── macos/                      # macOS detection rules
│   │   ├── process_creation/
│   │   └── file_event/
│   ├── cloud/                      # Cloud platform rules
│   │   ├── aws/                    # AWS CloudTrail, GuardDuty
│   │   ├── azure/                  # Azure activity/audit logs
│   │   ├── gcp/                    # Google Cloud audit logs
│   │   ├── m365/                   # Microsoft 365 audit
│   │   ├── okta/                   # Okta identity events
│   │   └── github/                 # GitHub audit log events
│   ├── network/                    # Network-based detection
│   │   ├── dns/                    # DNS traffic analysis
│   │   ├── firewall/               # Firewall log analysis
│   │   ├── proxy/                  # Web proxy logs
│   │   └── zeek/                   # Zeek/Bro IDS rules
│   ├── web/                        # Web application rules
│   │   └── webserver/              # Web server log analysis
│   ├── application/                # Application-specific rules
│   │   ├── antivirus/              # AV detection events
│   │   ├── django/
│   │   ├── python/
│   │   ├── ruby/
│   │   ├── rpc_firewall/
│   │   └── spring/
│   └── category/                   # Cross-platform categories
│       └── ...
├── rules-emerging-threats/         # Rules for specific emerging threats
├── rules-threat-hunting/           # Broader hunting queries
├── rules-compliance/               # Compliance-focused rules
├── deprecated/                     # Deprecated rules (kept for reference)
├── tests/                          # Rule validation tests
└── unsupported/                    # Rules not currently maintained
```

## 2.3 Rule Quality Levels (Status Field)

| Status | Meaning | Requirements |
|---|---|---|
| `stable` | Production-ready | Thoroughly tested, low FP rate, community validated |
| `test` | Testing phase | Functional but needs broader testing |
| `experimental` | Experimental | New rule, may have high FP rate |
| `deprecated` | Deprecated | Replaced by newer rule (linked via `related`) |
| `unsupported` | Unsupported | Not maintained, may be broken |

## 2.4 SigmaHQ Quality Standards

**Required for PR acceptance:**
- Valid UUID in `id` field
- Proper `date` and `modified` fields (YYYY/MM/DD format)
- `status` field present
- `level` field with appropriate severity
- `description` explaining what the rule detects
- At least one `tag` with ATT&CK reference where applicable
- `falsepositives` field (even if just listing "Unknown")
- `author` field
- Detection logic that is syntactically valid
- No duplicate rule IDs

**Naming convention:** Files are named descriptively with the pattern:
`<verb>_<noun>_<detail>.yml` (e.g., `proc_creation_win_susp_encoded_powershell.yml`)

## 2.5 Severity Level Guidelines

| Level | Meaning | Expected FP Rate |
|---|---|---|
| `informational` | Baseline activity, useful for enrichment | Very high |
| `low` | Interesting but common activity | High |
| `medium` | Suspicious activity worth investigating | Moderate |
| `high` | Likely malicious, requires investigation | Low |
| `critical` | Almost certainly malicious, immediate response | Very low |

---

# 3. YARA Rule Specification

## 3.1 Overview

YARA is a pattern-matching tool designed for malware researchers to identify and classify malware samples. It matches binary or text patterns in files, memory, or network streams.

- **Official Documentation**: https://yara.readthedocs.io/en/stable/
- **GitHub Repository**: https://github.com/VirusTotal/yara
- **Current Version**: YARA 4.x series
- **Python Binding**: `yara-python` (pip install yara-python)

## 3.2 Complete Rule Syntax

```
rule RuleName : tag1 tag2
{
    meta:
        <key> = <value>

    strings:
        $<identifier> = <pattern>

    condition:
        <boolean expression>
}
```

### 3.2.1 Rule Header

```
rule <identifier> : <optional_tags>
{
    ...
}

// Rule names: alphanumeric + underscore, cannot start with digit
// Tags: space-separated, alphanumeric + underscore
// Rules can be private (not reported in output):
private rule HelperRule { ... }

// Rules can be global (must match for any other rule to match):
global rule GlobalFilter { ... }

// Imports for modules:
import "pe"
import "elf"
import "math"
import "hash"
import "cuckoo"
import "magic"
import "dotnet"
```

### 3.2.2 Meta Section

```
meta:
    // String values
    description = "Detects APT29 backdoor variant"
    author = "Florian Roth"
    reference = "https://example.com/report"
    date = "2024-01-15"
    modified = "2024-06-20"
    hash = "a1b2c3d4e5f6..."

    // Integer values
    score = 75

    // Boolean values
    in_the_wild = true

    // Common metadata conventions:
    tlp = "WHITE"
    sharing = "TLP:CLEAR"
    id = "12345678-1234-1234-1234-123456789012"

    // MITRE ATT&CK mapping (convention, not enforced)
    mitre_attack_tactic = "TA0002"
    mitre_attack_technique = "T1059.001"
```

### 3.2.3 Strings Section

**Text Strings:**
```
strings:
    $text1 = "malware string"              // Case-sensitive
    $text2 = "MaLwArE" nocase              // Case-insensitive
    $text3 = "wide string" wide            // UTF-16 LE encoding
    $text4 = "both" ascii wide             // Match both encodings
    $text5 = "full word" fullword          // Match whole word only
    $text6 = "private" private             // Don't include in output
    $text7 = "xor me" xor                  // XOR with single-byte keys (0x00-0xFF)
    $text8 = "xor range" xor(0x01-0x0F)   // XOR with key range
    $text9 = "base64" base64               // Match base64-encoded form
    $text10 = "b64alpha" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    // Modifiers can be combined:
    $combo = "combined" ascii wide nocase fullword
```

**Hexadecimal Strings (Byte Patterns):**
```
strings:
    $hex1 = { 4D 5A 90 00 }                    // Exact bytes
    $hex2 = { 4D 5A ?? 00 }                    // Wildcard byte
    $hex3 = { 4D 5A [2-4] 00 }                 // Jump: 2 to 4 bytes
    $hex4 = { 4D 5A [2-] 00 }                  // Jump: 2 or more bytes
    $hex5 = { 4D 5A [-] 00 }                   // Jump: any number of bytes
    $hex6 = { 4D 5A ( 90 00 | 89 00 ) }        // Alternation (OR)
    $hex7 = { 4D 5? }                           // Nibble wildcard
    $hex8 = { ~00 }                             // NOT byte (any byte except 0x00)
    // Combinations:
    $hex9 = { 4D 5A ( 90 | 89 ) [0-10] ( E8 | FF 15 ) }
```

**Regular Expressions:**
```
strings:
    $re1 = /https?:\/\/[a-z0-9\-\.]+\.(com|net|org)/
    $re2 = /[A-Z]{3,6}\d{2,4}/ nocase
    $re3 = /cmd\.exe.*\/c/ wide ascii

    // Supported regex syntax: PCRE-like
    // Metacharacters: . \w \W \s \S \d \D \b \B
    // Quantifiers: * + ? {n} {n,m} {n,}
    // Anchors: ^ $ (per-line by default)
    // Character classes: [abc] [a-z] [^abc]
    // Alternation: |
    // Grouping: ( )
    // Non-greedy: *? +? ??
```

### 3.2.4 Condition Section

```
condition:
    // Boolean operators
    $string1 and $string2
    $string1 or $string2
    not $string1

    // Counting strings
    #string1 > 5                    // Occurrence count
    #string1 in (0..1024) > 2      // Count in range

    // String sets
    any of ($text*)                 // Any string matching $text*
    all of ($hex*)                  // All strings matching $hex*
    2 of ($a, $b, $c)             // At least 2 of the named strings
    3 of them                      // At least 3 of all strings
    any of them                    // Any defined string
    all of them                    // All defined strings
    75% of them                    // Percentage-based

    // String offset and position
    $string1 at 0                  // String at exact offset
    $string1 in (0..1024)          // String within range
    @string1[1]                    // Offset of 1st occurrence
    @string1[2]                    // Offset of 2nd occurrence
    !string1[1]                    // Length of 1st match

    // File size
    filesize < 500KB
    filesize > 1MB

    // Entry point (PE/ELF)
    $string1 at entrypoint
    $string1 in (entrypoint..entrypoint+100)

    // Integer functions
    uint16(0) == 0x5A4D            // MZ header check
    uint32(0) == 0x464C457F        // ELF header check
    uint8(0) == 0x4D               // Single byte check
    uint16be(0) == 0x4D5A          // Big endian
    int32(0) == -1                 // Signed integer

    // for-of / for-in iterators
    for any of ($a*) : ( $ at entrypoint )
    for all of them : ( # > 3 )
    for any i in (1..#str) : ( @str[i] < 100 )

    // Combining with PE module
    pe.number_of_sections > 5
    pe.imports("kernel32.dll", "VirtualAlloc")
    pe.exports("DllMain")
    pe.timestamp > 1600000000
```

### 3.2.5 Commonly Used Modules

```
import "pe"       // PE file analysis
    pe.machine == pe.MACHINE_AMD64
    pe.characteristics & pe.DLL
    pe.number_of_sections
    pe.sections[0].name == ".text"
    pe.imports("kernel32.dll", "VirtualAlloc")
    pe.imports("ntdll.dll")          // Any import from ntdll
    pe.exports("ServiceMain")
    pe.number_of_resources
    pe.is_signed
    pe.number_of_signatures

import "elf"      // ELF file analysis
    elf.type == elf.ET_EXEC
    elf.machine == elf.EM_X86_64

import "math"     // Mathematical functions
    math.entropy(0, filesize) > 7.0
    math.mean(0, filesize) > 128
    math.serial_correlation(0, filesize) < 0.1

import "hash"     // Hash functions
    hash.md5(0, filesize) == "abc123..."
    hash.sha256(0, filesize) == "def456..."
    hash.sha1(0, filesize) == "789abc..."
    hash.crc32(0, filesize) == 0x12345678

import "dotnet"   // .NET analysis
    dotnet.version == "v4.0.30319"
    dotnet.assembly.name == "Malware"
    for any s in dotnet.streams : ( s.name == "#~" )
```

## 3.3 Complete Example Rule

```
import "pe"
import "math"

rule APT29_WellMess_Backdoor : APT Russia
{
    meta:
        description = "Detects WellMess backdoor used by APT29/Cozy Bear"
        author = "DetectForge Research"
        date = "2024-07-15"
        modified = "2024-09-01"
        reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
        hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        tlp = "WHITE"
        score = 80
        mitre_attack_tactic = "TA0011"
        mitre_attack_technique = "T1071.001"

    strings:
        $go_buildid = "Go build ID:" ascii
        $s1 = "WellMess" ascii wide nocase
        $s2 = "/bot/api" ascii
        $s3 = "Cookie: SessionId=" ascii
        $s4 = { 48 8B 44 24 ?? 48 89 44 24 ?? C3 }

        $ua1 = "Mozilla/5.0 (Windows NT 6.1" ascii
        $ua2 = "Mozilla/5.0 (Macintosh; Intel" ascii

        $enc1 = /[A-Za-z0-9+\/]{40,}={0,2}/ ascii  // Base64 pattern
        $enc2 = { 30 82 [2] 30 82 }                 // ASN.1 cert

        $func1 = "main.main" ascii
        $func2 = "main.bot" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $go_buildid and
        (
            ( 2 of ($s*) ) or
            ( 1 of ($s*) and 1 of ($ua*) and 1 of ($enc*) ) or
            ( all of ($func*) and 1 of ($s*) )
        ) and
        math.entropy(0, filesize) > 5.5
}
```

## 3.4 YARA Best Practices / Quality Guidelines

**Good YARA Rules:**
- Combine multiple string matches with logical conditions
- Use `filesize` constraints to limit scope
- Check file headers (`uint16(0) == 0x5A4D` for PE)
- Use entropy checks to filter packed/encrypted files
- Include unique strings from the malware, not common library strings
- Use `fullword` to prevent partial matches
- Test against a goodware corpus to verify low false positive rate
- Include detailed metadata for attribution and context

**Bad YARA Rules (Anti-Patterns):**
- Single string matches without additional conditions
- Matching on extremely common strings ("http://", "Windows", "cmd.exe")
- No filesize constraint (will scan huge files unnecessarily)
- Overly broad regex patterns
- Matching only on metadata or version info
- No performance consideration (slow patterns with `[-]` jumps)
- XOR modifier without byte range constraint

---

# 4. Suricata Rule Format

## 4.1 Overview

Suricata is an open-source IDS/IPS/NSM engine. Its rule format is compatible with (and extends) the Snort rule format.

- **Documentation**: https://docs.suricata.io/en/latest/rules/
- **GitHub**: https://github.com/OISF/suricata
- **Rule Sources**: ET Open (Emerging Threats), ET Pro, Suricata default rules
- **Emerging Threats Open Rules**: https://rules.emergingthreats.net/open/suricata/rules/

## 4.2 Rule Structure

```
ACTION PROTOCOL SOURCE_IP SOURCE_PORT DIRECTION DEST_IP DEST_PORT (OPTIONS)
```

### 4.2.1 Action

| Action | Description |
|---|---|
| `alert` | Generate an alert |
| `pass` | Stop further inspection of packet |
| `drop` | Drop packet and generate alert (IPS mode) |
| `reject` | Send RST/ICMP unreachable and drop |
| `rejectsrc` | Send reject to source |
| `rejectdst` | Send reject to destination |
| `rejectboth` | Send reject to both |

### 4.2.2 Protocol

| Protocol | Description |
|---|---|
| `tcp` | TCP traffic |
| `udp` | UDP traffic |
| `icmp` | ICMP traffic |
| `ip` | Any IP traffic |
| `http` | HTTP (application layer) |
| `tls` | TLS/SSL |
| `dns` | DNS |
| `ftp` | FTP |
| `ssh` | SSH |
| `smtp` | SMTP |
| `smb` | SMB |
| `dcerpc` | DCE/RPC |
| `dhcp` | DHCP |
| `ntp` | NTP |
| `ikev2` | IKEv2 |
| `krb5` | Kerberos 5 |
| `nfs` | NFS |
| `tftp` | TFTP |
| `pkthdr` | Packet header only |

### 4.2.3 IP and Port

```
# IP specification
any                         # Any IP
$HOME_NET                   # Variable (defined in suricata.yaml)
$EXTERNAL_NET               # Variable
192.168.1.0/24             # CIDR notation
[192.168.1.0/24,10.0.0.0/8]  # IP group
!192.168.1.0/24            # Negation

# Port specification
any                         # Any port
80                          # Single port
[80,443]                    # Port group
[1024:]                     # Range: 1024 and above
[:1024]                     # Range: 1024 and below
[1024:65535]               # Range: 1024 to 65535
!80                         # Negation
[80,!99]                    # Group with negation
```

### 4.2.4 Direction

| Direction | Description |
|---|---|
| `->` | Source to destination (unidirectional) |
| `<>` | Bidirectional |

### 4.2.5 Rule Options (Complete Reference)

**Meta Keywords:**
```
msg:"Description of what the rule detects";
sid:1000001;                    # Unique signature ID
rev:3;                          # Rule revision number
gid:1;                          # Generator ID (default: 1)
classtype:trojan-activity;      # Classification
priority:1;                     # Priority (1=high, 4=low)
metadata: affected_product Windows, attack_target Client_Endpoint, \
    created_at 2024_01_15, deployment Perimeter, \
    former_category MALWARE, confidence High, \
    signature_severity Major, updated_at 2024_06_01, \
    mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, \
    mitre_technique_id T1566, mitre_technique_name Phishing;
reference:url,example.com/analysis;
reference:cve,2021-44228;
reference:md5,abc123def456;
target: dest_ip;                # Target of the attack
```

**Content Matching:**
```
content:"malicious string";     # Content match (case-sensitive)
content:"|4D 5A|";              # Hex content match
content:!"legitimate";          # Negated content
nocase;                         # Case-insensitive (modifier)
depth:100;                      # Search first N bytes
offset:4;                       # Start search at byte N
distance:0;                     # Relative to previous match
within:50;                      # Within N bytes of previous match
startswith;                     # Content must be at start
endswith;                       # Content must be at end
rawbytes;                       # Match raw packet bytes
fast_pattern;                   # Use as fast pattern match
```

**PCRE (Regular Expression):**
```
pcre:"/malware[0-9]{2,4}/i";   # Perl-compatible regex
    # Flags: i=case-insensitive, s=dotall, m=multiline
    #        U=ungreedy, R=relative to last match
    #        B=rawbytes
```

**HTTP Keywords:**
```
http.uri;                       # Normalized URI
http.uri.raw;                   # Raw (un-normalized) URI
http.method;                    # HTTP method (GET, POST, etc.)
http.host;                      # Host header value
http.host.raw;                  # Raw host header
http.header;                    # Full HTTP headers
http.header.raw;                # Raw headers
http.cookie;                    # Cookie header
http.user_agent;                # User-Agent header
http.request_body;              # HTTP request body
http.response_body;             # HTTP response body
http.stat_code;                 # Response status code
http.stat_msg;                  # Response status message
http.content_type;              # Content-Type header
http.request_line;              # Full request line
http.response_line;             # Full response line
http.header_names;              # List of header names
http.accept;                    # Accept header
http.accept_lang;               # Accept-Language header
http.accept_enc;                # Accept-Encoding header
http.referer;                   # Referer header
http.connection;                # Connection header
http.protocol;                  # HTTP version
http.start;                     # Start of HTTP (request or response)
```

**TLS Keywords:**
```
tls.cert_subject;               # Certificate subject
tls.cert_issuer;                # Certificate issuer
tls.cert_serial;                # Certificate serial
tls.cert_fingerprint;           # Certificate SHA1 fingerprint
tls.sni;                        # Server Name Indication
tls.version;                    # TLS version
tls.ja3.hash;                   # JA3 hash
tls.ja3.string;                 # JA3 string
tls.ja3s.hash;                  # JA3S hash (server)
tls.ja3s.string;                # JA3S string
tls.cert_chain_len;             # Certificate chain length
tls.certs;                      # Access certificate fields
tls.random;                     # TLS random bytes
```

**DNS Keywords:**
```
dns.query;                      # DNS query name
dns.opcode;                     # DNS opcode
dns.rrtype;                     # DNS record type
```

**File Keywords:**
```
filename;                       # File name
fileext;                        # File extension
filemagic;                      # File magic (libmagic)
filemd5;                        # MD5 file hash list
filesha1;                       # SHA1 file hash list
filesha256;                     # SHA256 file hash list
filesize;                       # File size
filestore;                      # Store extracted file
```

**Flow Keywords:**
```
flow:to_server,established;     # Flow direction and state
flow:to_client,established;
flow:from_server;
flow:from_client;
flow:established;               # Established connection
flow:not_established;
flow:stateless;                 # Stateless inspection
flowbits:set,malware.active;    # Set a flow flag
flowbits:isset,malware.active;  # Check if flag is set
flowbits:unset,malware.active;  # Unset a flag
flowbits:toggle,malware.active; # Toggle a flag
flowbits:noalert;               # Don't alert (just set bits)
flowint:counter,+,1;            # Flow integer operations
```

**Threshold/Rate Keywords:**
```
threshold:type both, track by_src, count 5, seconds 60;
    # Types: threshold, limit, both
    # Track: by_src, by_dst, by_both, by_rule
detection_filter:track by_src, count 10, seconds 60;
```

**Byte Operations:**
```
byte_test:4,>,1000,0;          # Test N bytes at offset
    # byte_test:<bytes>,<op>,<value>,<offset>[,flags]
byte_jump:4,0,relative;        # Jump N bytes
byte_extract:4,0,var_name;     # Extract bytes to variable
byte_math:bytes 4, offset 0, oper +, rvalue 10, result var;
```

**Other Important Keywords:**
```
itype:8;                        # ICMP type
icode:0;                        # ICMP code
ttl:64;                         # TTL value
tos:0;                          # TOS value
id:1234;                        # IP ID
fragbits:M;                     # Fragmentation bits
dsize:>100;                     # Payload size
flags:S;                        # TCP flags (S=SYN, A=ACK, etc.)
window:1024;                    # TCP window size
seq:0;                          # TCP sequence number
ack:0;                          # TCP ACK number
stream_size:server,>,1000;      # Stream size
app-layer-protocol:http;        # Application protocol
app-layer-event:http.host_header_ambiguous;  # App layer event
lua:detect.lua;                 # Lua scripting
dataset:set,malicious_ips,type ip,state /var/lib/suricata/malicious_ips;
```

## 4.3 Complete Example Rules

```
# HTTP C2 Beacon Detection
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Cobalt Strike Beacon C2 Activity";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; content:"/activity"; depth:9;
    http.uri; content:".js"; distance:0;
    http.header; content:"Cookie:";
    pcre:"/Cookie:\s[A-Za-z0-9+\/]{60,}={0,2}/";
    http.user_agent; content:"Mozilla/5.0"; depth:11;
    threshold:type limit, track by_src, count 1, seconds 600;
    classtype:trojan-activity;
    sid:2030001; rev:1;
    metadata: mitre_tactic_id TA0011, mitre_technique_id T1071.001,
              created_at 2024_07_15, updated_at 2024_07_15;
    reference:url,www.cobaltstrike.com;
)

# DNS Tunneling Detection
alert dns $HOME_NET any -> any any (
    msg:"ET MALWARE Possible DNS Tunneling - Excessive Subdomain Length";
    flow:to_server;
    dns.query;
    pcre:"/^[a-z0-9]{30,}\.[a-z0-9-]+\.[a-z]{2,6}$/i";
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:trojan-activity;
    sid:2030002; rev:1;
)

# TLS Certificate Anomaly
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Suspicious Self-Signed Certificate";
    flow:to_client,established;
    tls.cert_subject; content:"CN=localhost";
    tls.cert_issuer; content:"CN=localhost";
    classtype:trojan-activity;
    sid:2030003; rev:1;
)

# JA3 Hash for Known Malware
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Known Malicious JA3 Hash - Emotet";
    flow:to_server,established;
    tls.ja3.hash; content:"51c64c77e60f3980eea90869b68c58a8";
    classtype:trojan-activity;
    sid:2030004; rev:1;
    reference:url,sslbl.abuse.ch;
)
```

## 4.4 Suricata Classification Types

| Classtype | Priority | Description |
|---|---|---|
| `trojan-activity` | 1 | Trojan horse activity |
| `exploit-kit` | 1 | Exploit kit activity |
| `targeted-activity` | 1 | Targeted malicious activity |
| `command-and-control` | 1 | Command and control |
| `successful-admin` | 1 | Successful admin access |
| `successful-user` | 1 | Successful user access |
| `attempted-admin` | 2 | Attempted admin access |
| `attempted-user` | 2 | Attempted user access |
| `web-application-attack` | 2 | Web application attack |
| `policy-violation` | 2 | Policy violation |
| `bad-unknown` | 2 | Potentially bad traffic |
| `misc-attack` | 2 | Misc attack |
| `attempted-recon` | 3 | Attempted recon |
| `misc-activity` | 3 | Misc activity |
| `not-suspicious` | 4 | Not suspicious |

---

# 5. MITRE ATT&CK Programmatic Access

## 5.1 Overview

- **Website**: https://attack.mitre.org/
- **GitHub (Data)**: https://github.com/mitre/cti (STIX 2.1 JSON bundles)
- **GitHub (ATT&CK Python)**: https://github.com/mitre-attack/mitreattack-python
- **TAXII Server**: https://cti-taxii.mitre.org/
- **ATT&CK Navigator**: https://mitre-attack.github.io/attack-navigator/
- **ATT&CK STIX Data**: https://github.com/mitre-attack/attack-stix-data

## 5.2 STIX 2.1 Data Format

ATT&CK data is expressed in STIX 2.1 (Structured Threat Information Expression). Each ATT&CK concept maps to a STIX object:

| ATT&CK Concept | STIX Object Type | Example |
|---|---|---|
| Technique | `attack-pattern` | T1059.001 PowerShell |
| Tactic | `x-mitre-tactic` | TA0002 Execution |
| Group (APT) | `intrusion-set` | APT29, Lazarus Group |
| Software/Malware | `malware` or `tool` | Cobalt Strike, Mimikatz |
| Mitigation | `course-of-action` | M1042 Disable or Remove Feature |
| Data Source | `x-mitre-data-source` | DS0009 Process |
| Data Component | `x-mitre-data-component` | Process Creation |
| Campaign | `campaign` | C0021 |
| Matrix | `x-mitre-matrix` | Enterprise, Mobile, ICS |

### STIX 2.1 Technique Object Example:

```json
{
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
    "created": "2017-05-31T21:30:44.329Z",
    "modified": "2024-04-16T12:45:00.000Z",
    "name": "PowerShell",
    "description": "Adversaries may abuse PowerShell commands and scripts...",
    "kill_chain_phases": [
        {
            "kill_chain_name": "mitre-attack",
            "phase_name": "execution"
        }
    ],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/techniques/T1059/001",
            "external_id": "T1059.001"
        }
    ],
    "x_mitre_platforms": ["Windows"],
    "x_mitre_data_sources": [
        "Process: Process Creation",
        "Command: Command Execution",
        "Script: Script Execution",
        "Module: Module Load"
    ],
    "x_mitre_detection": "Monitor for loading of PowerShell...",
    "x_mitre_is_subtechnique": true,
    "x_mitre_version": "1.5",
    "x_mitre_attack_spec_version": "3.2.0"
}
```

## 5.3 TAXII 2.0 Server Access

```
TAXII Server Root: https://cti-taxii.mitre.org/taxii2/
Discovery URL:     https://cti-taxii.mitre.org/taxii2/

API Roots:
- https://cti-taxii.mitre.org/stix/

Collections:
- Enterprise ATT&CK: 95ecc380-afe9-11e4-9b6c-751b66dd541e
- Mobile ATT&CK:     2f669986-b40b-4423-b720-4396ca6a462b
- ICS ATT&CK:        02c3ef24-9cd4-48f3-a99f-b74ce24f1d34
```

### Python TAXII Client Example:

```python
from taxii2client.v20 import Collection, Server
from stix2 import TAXIICollectionSource, Filter

# Connect to MITRE's TAXII server
server = Server("https://cti-taxii.mitre.org/taxii2/")

# Get Enterprise ATT&CK collection
api_root = server.api_roots[0]
collection = Collection(
    "https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/"
)

# Create a data source
tc_source = TAXIICollectionSource(collection)

# Query techniques
techniques = tc_source.query([
    Filter("type", "=", "attack-pattern"),
    Filter("external_references.external_id", "=", "T1059.001")
])
```

## 5.4 mitreattack-python Library

```python
# pip install mitreattack-python
from mitreattack.stix20 import MitreAttackData

# Load from local STIX data (download from GitHub first)
mitre_attack = MitreAttackData("enterprise-attack.json")

# Get all techniques
techniques = mitre_attack.get_techniques()

# Get technique by ID
technique = mitre_attack.get_object_by_attack_id("T1059.001", "attack-pattern")

# Get techniques used by a group
apt29_techniques = mitre_attack.get_techniques_used_by_group("intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542")

# Get all groups
groups = mitre_attack.get_groups()

# Get software
software = mitre_attack.get_software()

# Get mitigations for a technique
mitigations = mitre_attack.get_mitigations_mitigating_technique(technique_stix_id)

# Get data sources for a technique
data_sources = mitre_attack.get_data_sources()

# Get tactics
tactics = mitre_attack.get_tactics()

# Map techniques to tactics
for technique in techniques:
    for phase in technique.get("kill_chain_phases", []):
        tactic = phase["phase_name"]
```

## 5.5 Direct GitHub Data Access

```bash
# Clone the STIX data repository
git clone https://github.com/mitre-attack/attack-stix-data.git

# Directory structure:
# attack-stix-data/
# ├── enterprise-attack/           # Enterprise matrix
# │   └── enterprise-attack.json   # Full STIX 2.1 bundle
# ├── mobile-attack/               # Mobile matrix
# │   └── mobile-attack.json
# └── ics-attack/                  # ICS matrix
#     └── ics-attack.json
```

### Loading Data Directly (stix2 Library):

```python
# pip install stix2
from stix2 import MemoryStore, Filter
import json

# Load from file
with open("enterprise-attack.json", "r") as f:
    attack_data = json.load(f)

ms = MemoryStore(stix_data=attack_data["objects"])

# Query all techniques
techniques = ms.query([
    Filter("type", "=", "attack-pattern")
])

# Query specific technique
t1059_001 = ms.query([
    Filter("type", "=", "attack-pattern"),
    Filter("external_references.external_id", "=", "T1059.001")
])

# Query all groups (APT actors)
groups = ms.query([
    Filter("type", "=", "intrusion-set")
])

# Query relationships (e.g., techniques used by a group)
relationships = ms.query([
    Filter("type", "=", "relationship"),
    Filter("relationship_type", "=", "uses"),
    Filter("source_ref", "=", "intrusion-set--<GROUP_STIX_ID>")
])

# Get all software/malware
malware = ms.query([Filter("type", "=", "malware")])
tools = ms.query([Filter("type", "=", "tool")])
```

## 5.6 ATT&CK REST API (via MITRE's Website)

ATT&CK does not provide a dedicated REST API, but data can be fetched from GitHub raw URLs:

```
Enterprise STIX Bundle:
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

Mobile STIX Bundle:
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json

ICS STIX Bundle:
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json
```

## 5.7 ATT&CK Tactic IDs and Names

| Tactic ID | Name | Description |
|---|---|---|
| TA0043 | Reconnaissance | Gathering information for planning |
| TA0042 | Resource Development | Establishing resources for operations |
| TA0001 | Initial Access | Gaining initial foothold |
| TA0002 | Execution | Running malicious code |
| TA0003 | Persistence | Maintaining presence |
| TA0004 | Privilege Escalation | Gaining higher-level permissions |
| TA0005 | Defense Evasion | Avoiding detection |
| TA0006 | Credential Access | Stealing credentials |
| TA0007 | Discovery | Exploring the environment |
| TA0008 | Lateral Movement | Moving through the network |
| TA0009 | Collection | Gathering target data |
| TA0011 | Command and Control | Communicating with compromised systems |
| TA0010 | Exfiltration | Stealing data |
| TA0040 | Impact | Manipulating, destroying systems/data |

---

# 6. Sigma CLI / pySigma Toolchain

## 6.1 Historical Context: sigmac vs pySigma

### Legacy: sigmac (Deprecated)
- Original Python tool for Sigma rule conversion
- Located in the old `SigmaHQ/sigma` repository under `tools/`
- Monolithic codebase, hard to maintain
- **Status: Deprecated. Do not use for new projects.**

### Current: pySigma (Active)
- Complete rewrite of the Sigma tooling ecosystem
- Modular architecture with separate backend packages
- Active development by SigmaHQ team
- **Repository**: https://github.com/SigmaHQ/pySigma
- **PyPI**: `pip install pySigma`

## 6.2 pySigma Architecture

```
pySigma (Core Library)
├── sigma.rule          # Rule parsing and representation
├── sigma.collection    # Rule collection management
├── sigma.conversion    # Conversion pipeline
├── sigma.processing    # Processing pipeline (field mapping, transformations)
├── sigma.validators    # Rule validation
├── sigma.modifiers     # Value modifiers
├── sigma.conditions    # Condition parsing
├── sigma.types         # Type system
└── sigma.exceptions    # Exception hierarchy

Backend Packages (Separate PyPI packages):
├── pySigma-backend-splunk        # Splunk SPL output
├── pySigma-backend-elasticsearch # Elasticsearch/OpenSearch
├── pySigma-backend-insightIDR    # Rapid7 InsightIDR
├── pySigma-backend-qradar        # IBM QRadar
├── pySigma-backend-microsoft365defender  # Microsoft Defender/Sentinel (KQL)
├── pySigma-backend-carbonblack   # VMware Carbon Black
├── pySigma-backend-crowdstrike   # CrowdStrike Falcon LogScale
├── pySigma-backend-loki          # Grafana Loki
├── pySigma-backend-cortexxdr     # Palo Alto Cortex XDR
├── pySigma-backend-sentinelone   # SentinelOne
├── pySigma-backend-sqlite        # SQLite (for testing)
└── pySigma-backend-kusto         # Azure Data Explorer / Kusto

Pipeline Packages (Field Mapping / Normalization):
├── pySigma-pipeline-windows      # Windows field mappings
├── pySigma-pipeline-sysmon       # Sysmon-specific mappings
├── pySigma-pipeline-crowdstrike  # CrowdStrike field mappings
└── pySigma-pipeline-sentinelone  # SentinelOne field mappings
```

## 6.3 pySigma Usage Examples

### Rule Parsing and Validation

```python
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.validators.core import (
    AllOfThemConditionValidator,
    ATTACKTagValidator,
    DuplicateDetectionValidator,
    IdentifierExistenceValidator,
    IdentifierUniquenessValidator,
    InvalidModifierValidator,
    StatusExistenceValidator,
    DanglingDetectionValidator,
)

# Parse a single rule from YAML string
rule_yaml = """
title: Test Rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"""

rule = SigmaRule.from_yaml(rule_yaml)

# Access rule properties
print(rule.title)            # "Test Rule"
print(rule.status)           # SigmaStatus.TEST
print(rule.level)            # SigmaLevel.MEDIUM
print(rule.logsource)        # SigmaLogSource object
print(rule.detection)        # SigmaDetection object
print(rule.tags)             # List of SigmaRuleTag
print(rule.id)               # UUID or None

# Parse from file
rule = SigmaRule.from_yaml(open("rule.yml").read())

# Parse a collection (directory of rules)
collection = SigmaCollection.load_ruleset(["rules/"])

# Validate a rule
validators = [
    IdentifierExistenceValidator(),
    StatusExistenceValidator(),
    ATTACKTagValidator(),
    DuplicateDetectionValidator(),
    InvalidModifierValidator(),
    DanglingDetectionValidator(),
]

for validator in validators:
    issues = validator.validate(rule)
    for issue in issues:
        print(f"[{issue.severity}] {issue.message}")
```

### Rule Conversion

```python
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_pipeline

# Create backend with processing pipeline
splunk_backend = SplunkBackend(processing_pipeline=sysmon_pipeline())
elastic_backend = LuceneBackend(processing_pipeline=windows_pipeline())

# Convert rule
rule = SigmaRule.from_yaml(rule_yaml)

splunk_query = splunk_backend.convert_rule(rule)
elastic_query = elastic_backend.convert_rule(rule)

print(splunk_query)    # Returns list of query strings
print(elastic_query)   # Returns list of query strings

# Convert entire collection
collection = SigmaCollection.load_ruleset(["rules/"])
all_queries = splunk_backend.convert(collection)
```

## 6.4 sigma-cli (Command-Line Interface)

```bash
# Installation
pip install sigma-cli

# List available backends
sigma list backends

# List available pipelines
sigma list pipelines

# Convert a rule to Splunk
sigma convert -t splunk -p sysmon rule.yml

# Convert to Elasticsearch with pipeline
sigma convert -t elasticsearch -p ecs_windows rule.yml

# Convert entire directory
sigma convert -t splunk -p sysmon rules/windows/process_creation/

# Validate rules
sigma check rule.yml

# Convert with multiple pipelines (chained)
sigma convert -t splunk -p sysmon -p windows rule.yml

# Output formats
sigma convert -t splunk -p sysmon -f savedsearches rule.yml   # Splunk saved search
sigma convert -t splunk -p sysmon -f data_model rule.yml       # Splunk data model

# Plugin management
sigma plugin install splunk
sigma plugin install elasticsearch
sigma plugin list
```

## 6.5 Custom Validation with pySigma

```python
from sigma.validators.base import SigmaRuleValidator, SigmaValidationIssue, SigmaValidationIssueSeverity
from sigma.rule import SigmaRule

class CustomValidator(SigmaRuleValidator):
    """Custom validator for DetectForge quality standards."""

    def validate(self, rule: SigmaRule) -> list:
        issues = []

        # Check for required fields
        if not rule.id:
            issues.append(SigmaValidationIssue(
                rules=[rule],
                severity=SigmaValidationIssueSeverity.HIGH,
                message="Rule must have a UUID identifier"
            ))

        if not rule.description:
            issues.append(SigmaValidationIssue(
                rules=[rule],
                severity=SigmaValidationIssueSeverity.MEDIUM,
                message="Rule should have a description"
            ))

        if not rule.tags:
            issues.append(SigmaValidationIssue(
                rules=[rule],
                severity=SigmaValidationIssueSeverity.MEDIUM,
                message="Rule should have ATT&CK tags"
            ))

        if not rule.falsepositives:
            issues.append(SigmaValidationIssue(
                rules=[rule],
                severity=SigmaValidationIssueSeverity.LOW,
                message="Rule should document known false positives"
            ))

        return issues
```

---

# 7. Public APT Report Sources

## 7.1 Primary Threat Intelligence Sources

### Government / National CERT Sources

| Source | URL | Format | Access Method |
|---|---|---|---|
| **CISA Advisories** | https://www.cisa.gov/news-events/cybersecurity-advisories | HTML, PDF, STIX | RSS, API (catalog.json) |
| **CISA Known Exploited Vulns** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | JSON, CSV | Direct download: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| **NCSC (UK)** | https://www.ncsc.gov.uk/section/keep-up-to-date/reports-advisories | HTML, PDF | RSS feed |
| **ANSSI (France)** | https://www.cert.ssi.gouv.fr/ | HTML, PDF | RSS feed |
| **BSI (Germany)** | https://www.bsi.bund.de/EN/ | HTML, PDF | RSS feed |
| **CERT-EU** | https://cert.europa.eu/ | HTML, PDF | RSS feed |
| **US-CERT/ICS-CERT** | https://us-cert.cisa.gov/ | HTML, STIX | RSS, AIS (Automated Indicator Sharing) |

### Vendor Threat Intelligence

| Vendor | Blog/Reports URL | RSS/API | Notable Reports |
|---|---|---|---|
| **Mandiant (Google)** | https://www.mandiant.com/resources/blog | RSS available | APT reports, M-Trends annual |
| **CrowdStrike** | https://www.crowdstrike.com/blog/ | RSS available | Adversary profiles, Overwatch |
| **Unit 42 (Palo Alto)** | https://unit42.paloaltonetworks.com/ | RSS available | Campaign analyses |
| **Microsoft Threat Intelligence** | https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/ | RSS available | Nation-state actor reports |
| **Cisco Talos** | https://blog.talosintelligence.com/ | RSS available | Vulnerability research |
| **Recorded Future** | https://www.recordedfuture.com/blog | RSS available | Threat landscape reports |
| **Secureworks** | https://www.secureworks.com/research | RSS available | Threat group profiles |
| **Trend Micro** | https://www.trendmicro.com/en_us/research.html | RSS available | Campaign analyses |
| **ESET** | https://www.welivesecurity.com/ | RSS available | APT group tracking |
| **Kaspersky GReAT** | https://securelist.com/ | RSS available | APT campaign reports |
| **Proofpoint** | https://www.proofpoint.com/us/blog | RSS available | Email threat campaigns |
| **SentinelOne (SentinelLabs)** | https://www.sentinelone.com/labs/ | RSS available | Malware analysis |
| **Symantec (Broadcom)** | https://symantec-enterprise-blogs.security.com/ | RSS available | Threat group reports |
| **Check Point Research** | https://research.checkpoint.com/ | RSS available | Campaign analyses |
| **Volexity** | https://www.volexity.com/blog/ | RSS available | APT campaigns |
| **Elastic Security Labs** | https://www.elastic.co/security-labs | RSS available | Detection-focused research |
| **Google TAG** | https://blog.google/threat-analysis-group/ | RSS available | Zero-day / APT tracking |

### Open Threat Intelligence Platforms

| Platform | URL | API | Data Format |
|---|---|---|---|
| **MISP** | https://www.misp-project.org/ | REST API | MISP JSON, STIX |
| **OpenCTI** | https://www.opencti.io/ | GraphQL API | STIX 2.1 |
| **AlienVault OTX** | https://otx.alienvault.com/ | REST API (free key) | OTX Pulse JSON |
| **Abuse.ch** | https://abuse.ch/ | API, CSV feeds | Multiple formats |
| **MalwareBazaar** | https://bazaar.abuse.ch/ | REST API | JSON, CSV |
| **URLhaus** | https://urlhaus.abuse.ch/ | REST API, CSV | JSON, CSV |
| **ThreatFox** | https://threatfox.abuse.ch/ | REST API | JSON (IOCs) |
| **VirusTotal** | https://www.virustotal.com/ | REST API (keyed) | JSON |
| **Malshare** | https://malshare.com/ | REST API (free key) | Samples + metadata |
| **PhishTank** | https://phishtank.org/ | REST API | XML, JSON, CSV |
| **GreyNoise** | https://www.greynoise.io/ | REST API (free tier) | JSON |
| **Shodan** | https://www.shodan.io/ | REST API (keyed) | JSON |

### Structured Threat Intel Feeds

| Feed | URL | Format | Update Frequency |
|---|---|---|---|
| **abuse.ch SSL Blacklist** | https://sslbl.abuse.ch/ | CSV, JSON | Real-time |
| **abuse.ch Feodo Tracker** | https://feodotracker.abuse.ch/ | CSV, JSON | Real-time |
| **ET Open IOCs** | https://rules.emergingthreats.net/open/ | Suricata rules, IPs | Daily |
| **CISA AIS** | https://www.cisa.gov/ais | STIX/TAXII | Real-time |
| **Botvrij** | https://www.botvrij.eu/ | MISP feeds | Regular |

## 7.2 APT Report Aggregators

| Aggregator | URL | Description |
|---|---|---|
| **APT Notes** | https://github.com/aptnotes/data | Curated collection of APT reports (PDFs) |
| **Threat Reports** | https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections | Large collection of reports |
| **Malpedia** | https://malpedia.caad.fkie.fraunhofer.de/ | Malware encyclopedia with YARA rules |
| **MITRE ATT&CK Groups** | https://attack.mitre.org/groups/ | APT group profiles with technique mappings |
| **ThaiCERT Threat Group Cards** | https://apt.thaicert.or.th/ | Visual APT group summaries |
| **Ransomware Tracker** | Various | Multiple community trackers |
| **vx-underground** | https://vx-underground.org/ | Malware samples and papers |

## 7.3 Key RSS Feeds for Automated Ingestion

```
# CISA
https://www.cisa.gov/cybersecurity-advisories/all.xml

# Mandiant
https://www.mandiant.com/resources/blog/rss.xml

# Unit 42
https://unit42.paloaltonetworks.com/feed/

# Microsoft Security Blog
https://www.microsoft.com/en-us/security/blog/feed/

# Cisco Talos
https://blog.talosintelligence.com/rss/

# Securelist (Kaspersky)
https://securelist.com/feed/

# ESET WeLiveSecurity
https://www.welivesecurity.com/en/rss/feed/

# The DFIR Report
https://thedfirreport.com/feed/

# Elastic Security Labs
https://www.elastic.co/security-labs/rss/feed.xml

# SentinelOne Labs
https://www.sentinelone.com/labs/feed/
```

## 7.4 API Examples for Automated Ingestion

### AlienVault OTX
```python
from OTXv2 import OTXv2

otx = OTXv2("YOUR_API_KEY")

# Get subscribed pulses (threat intel packages)
pulses = otx.getall()

# Search for IOCs related to a malware family
results = otx.search_pulses("APT29")

# Get indicators for a specific pulse
indicators = otx.get_pulse_indicators("pulse_id")

# Get indicators by type
file_indicators = otx.get_all_indicators(indicator_types=["FileHash-SHA256"])
```

### Abuse.ch ThreatFox
```python
import requests

# Query IOCs
response = requests.post(
    "https://threatfox-api.abuse.ch/api/v1/",
    json={"query": "search_ioc", "search_term": "cobalt strike"}
)

# Get recent IOCs
response = requests.post(
    "https://threatfox-api.abuse.ch/api/v1/",
    json={"query": "get_iocs", "days": 7}
)

# Query by malware family
response = requests.post(
    "https://threatfox-api.abuse.ch/api/v1/",
    json={"query": "malwareinfo", "malware": "win.cobalt_strike"}
)
```

### CISA Known Exploited Vulnerabilities
```python
import requests

kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
response = requests.get(kev_url)
kev_data = response.json()

for vuln in kev_data["vulnerabilities"]:
    print(f"{vuln['cveID']}: {vuln['vulnerabilityName']}")
    print(f"  Vendor: {vuln['vendorProject']}")
    print(f"  Product: {vuln['product']}")
    print(f"  Date Added: {vuln['dateAdded']}")
    print(f"  Due Date: {vuln['dueDate']}")
    print(f"  Action: {vuln['requiredAction']}")
```

---

# 8. Existing Detection-as-Code Tools

## 8.1 Current Landscape

### SOC Prime (Uncoder.io / Uncoder AI)
- **URL**: https://uncoder.io/ and https://tdm.socprime.com/
- **What it does**: Translates Sigma rules to SIEM-specific queries; provides a marketplace of community-contributed detection rules; Uncoder AI can generate detection rules from natural language
- **Strengths**: Large rule marketplace (250,000+ rules claimed), supports 30+ SIEM platforms, community-driven content
- **Limitations**:
  - Commercial platform (freemium model, advanced features paywalled)
  - Rules are behind a login/marketplace model
  - AI rule generation is a black box with no validation pipeline
  - No offline/self-hosted option for the AI features
  - Limited to Sigma-to-SIEM conversion; does not generate YARA or Suricata
  - No integration with threat intelligence feeds for automated rule generation

### Sigma (SigmaHQ Ecosystem)
- **URL**: https://github.com/SigmaHQ/sigma
- **What it does**: Open-source Sigma rule repository + pySigma conversion toolchain
- **Strengths**: Industry standard, 3000+ rules, strong community, open specification
- **Limitations**:
  - Rules only, no AI-assisted generation
  - Sigma format only (no YARA, Suricata, Snort)
  - No automated threat intel ingestion
  - Manual rule writing process
  - No automated quality scoring beyond basic validation

### Elastic Detection Rules
- **URL**: https://github.com/elastic/detection-rules
- **What it does**: Detection rules for Elastic Security, written in TOML with KQL/EQL
- **Strengths**: High quality, well-tested, includes unit tests, ATT&CK mapped
- **Limitations**:
  - Elastic-specific (KQL/EQL only)
  - Not portable to other SIEMs without conversion
  - No multi-format generation

### Splunk Security Content (ESCU)
- **URL**: https://github.com/splunk/security_content
- **What it does**: Splunk's security content repository (Analytic Stories)
- **Strengths**: Comprehensive, includes baselines, well-documented, MITRE mapped
- **Limitations**:
  - Splunk SPL only
  - Tied to Splunk data models
  - Not portable

### Chronicle / Google Security Operations Detection Rules
- **URL**: https://github.com/chronicle/detection-rules
- **What it does**: YARA-L rules for Chronicle SIEM
- **Strengths**: Google backing, unique YARA-L format for log analysis
- **Limitations**:
  - Chronicle-specific YARA-L format
  - Not portable

### Panther Detection-as-Code
- **URL**: https://github.com/panther-labs/panther-analysis
- **What it does**: Python-based detection rules for Panther SIEM
- **Strengths**: Python-native, unit testable, CI/CD friendly
- **Limitations**:
  - Panther-specific
  - Python only
  - Not portable

### Matano Detection Rules
- **URL**: https://github.com/matanolabs/matano
- **What it does**: Open-source cloud-native SIEM with Python detections
- **Strengths**: Serverless, S3-based, cost-effective
- **Limitations**:
  - AWS-specific
  - Small community

### YARA-Forge
- **URL**: https://github.com/YARAHQ/yara-forge
- **What it does**: Automatically collects, curates, and packages YARA rules from various public sources
- **Strengths**: Automated aggregation, quality scoring, deduplication
- **Limitations**:
  - YARA only
  - Aggregation only, not generation
  - No threat intel integration for new rule creation

### Detection Lab / Detection Engineering Tools
- **URL**: Various
- **Includes**: Atomic Red Team (attack simulation), MITRE Caldera, Vectr (tracking)
- **Relevance**: Testing frameworks, not rule generation

### LLM-Based/AI Security Tools (Emerging)
- **Google SecLM / Sec-PaLM**: Google's security-specific LLM (integrated into Chronicle)
- **Microsoft Security Copilot**: AI assistant for security operations (Microsoft ecosystem)
- **Various startups**: Multiple companies exploring AI for detection engineering

## 8.2 Gap Analysis: Where DetectForge Fits

| Capability | SOC Prime | SigmaHQ | Elastic | DetectForge (Target) |
|---|---|---|---|---|
| AI-powered rule generation | Partial | No | No | **Yes** |
| Multi-format output (Sigma+YARA+Suricata) | No (Sigma only) | No (Sigma only) | No | **Yes** |
| Threat intel feed ingestion | No | No | No | **Yes** |
| Automated quality validation | Basic | Basic | Good | **Comprehensive** |
| MITRE ATT&CK auto-mapping | Manual | Manual | Manual | **Automated** |
| Open source / self-hosted | No | Yes (rules) | Partial | **Yes** |
| APT report to rules pipeline | No | No | No | **Yes** |
| Cross-SIEM conversion | Yes | Yes | No | **Yes (via pySigma)** |
| Offline operation | No | Yes | Yes | **Yes** |
| Rule deduplication vs existing | No | Manual | No | **Automated** |
| IOC extraction from reports | No | No | No | **Yes** |

### Key Differentiators for DetectForge:

1. **Unified Multi-Format Generation**: Single tool that generates Sigma + YARA + Suricata rules from the same threat intelligence input
2. **Automated Threat Intel Pipeline**: Ingest APT reports (PDF, HTML, structured feeds) and automatically generate detection rules
3. **AI-Powered with Validation**: Use LLM for initial rule generation but validate against specification schemas and quality standards
4. **MITRE ATT&CK Native**: Automatically map generated rules to ATT&CK techniques based on behavior analysis
5. **Quality Scoring**: Automated scoring against SigmaHQ standards, YARA best practices, and Suricata performance guidelines
6. **Deduplication Engine**: Check generated rules against existing SigmaHQ/ET Open/community rules to avoid redundancy
7. **Self-Hosted / Offline**: No cloud dependency; can run air-gapped for classified environments

---

# Appendix A: Key Python Packages for DetectForge

```
# Core Sigma tooling
pySigma>=0.11.0                    # Sigma rule parsing, validation, conversion
sigma-cli>=1.0.0                   # CLI interface for pySigma

# Sigma backends (install as needed)
pySigma-backend-splunk
pySigma-backend-elasticsearch
pySigma-backend-microsoft365defender
pySigma-backend-qradar
pySigma-backend-insightIDR

# Sigma pipelines
pySigma-pipeline-windows
pySigma-pipeline-sysmon

# YARA
yara-python>=4.3.0                 # YARA rule compilation and matching
plyara>=2.1.0                      # YARA rule parser (Python)

# MITRE ATT&CK
mitreattack-python>=0.1.0          # ATT&CK data access library
stix2>=3.0.0                       # STIX 2.1 library
taxii2-client>=2.3.0               # TAXII 2.0 client

# Threat Intelligence
pymisp>=2.4.170                    # MISP integration
OTXv2>=1.5.12                      # AlienVault OTX
cabby                              # TAXII 1.x client (legacy feeds)

# IOC Extraction
iocextract>=1.16.1                 # Extract IOCs from text
cyobstract                         # Observable extraction
defang                             # Defang/refang IOCs

# Document Processing (for APT report ingestion)
PyPDF2>=3.0.0                      # PDF parsing
pdfplumber>=0.9.0                  # Advanced PDF text extraction
beautifulsoup4>=4.12.0             # HTML parsing
feedparser>=6.0.0                  # RSS feed parsing
newspaper3k                        # Article extraction

# LLM Integration
openai>=1.0.0                      # OpenAI API (or compatible)
anthropic>=0.18.0                  # Anthropic Claude API
langchain>=0.1.0                   # LLM orchestration framework
tiktoken>=0.5.0                    # Token counting

# Validation & Testing
jsonschema>=4.20.0                 # JSON Schema validation
yamale>=4.0.0                      # YAML schema validation
pyyaml>=6.0.1                      # YAML parsing
pytest>=7.4.0                      # Testing framework

# Data & Utilities
requests>=2.31.0                   # HTTP client
aiohttp>=3.9.0                     # Async HTTP client
pydantic>=2.5.0                    # Data validation models
click>=8.1.0                       # CLI framework
rich>=13.7.0                       # Rich terminal output
```

# Appendix B: Suricata Rule SID Ranges

| SID Range | Owner |
|---|---|
| 0 - 99 | Reserved |
| 100 - 999,999 | Snort community rules |
| 1,000,000 - 1,999,999 | Reserved |
| 2,000,000 - 2,099,999 | Emerging Threats (ET) rules |
| 2,100,000 - 2,103,999 | ET open rules |
| 2,200,000 - 2,299,999 | ET Pro rules |
| 2,800,000 - 2,899,999 | ET open test rules |
| 3,000,000+ | Custom / user-defined |

**For DetectForge-generated rules, use SID range 9,000,000 - 9,999,999 (custom range).**

# Appendix C: Reference URLs Summary

| Resource | URL |
|---|---|
| Sigma Specification | https://github.com/SigmaHQ/sigma-specification |
| Sigma Rules | https://github.com/SigmaHQ/sigma |
| pySigma | https://github.com/SigmaHQ/pySigma |
| sigma-cli | https://github.com/SigmaHQ/sigma-cli |
| YARA Documentation | https://yara.readthedocs.io/en/stable/ |
| YARA GitHub | https://github.com/VirusTotal/yara |
| plyara (YARA Parser) | https://github.com/plyara/plyara |
| Suricata Documentation | https://docs.suricata.io/en/latest/rules/ |
| Suricata GitHub | https://github.com/OISF/suricata |
| ET Open Rules | https://rules.emergingthreats.net/open/ |
| MITRE ATT&CK | https://attack.mitre.org/ |
| ATT&CK STIX Data | https://github.com/mitre-attack/attack-stix-data |
| mitreattack-python | https://github.com/mitre-attack/mitreattack-python |
| MITRE CTI (STIX) | https://github.com/mitre/cti |
| CISA Advisories | https://www.cisa.gov/news-events/cybersecurity-advisories |
| CISA KEV Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| AlienVault OTX | https://otx.alienvault.com/ |
| Abuse.ch ThreatFox | https://threatfox.abuse.ch/ |
| MalwareBazaar | https://bazaar.abuse.ch/ |
| MISP Project | https://www.misp-project.org/ |
| OpenCTI | https://www.opencti.io/ |
| SOC Prime / Uncoder | https://uncoder.io/ |
| Elastic Detection Rules | https://github.com/elastic/detection-rules |
| Splunk Security Content | https://github.com/splunk/security_content |
| YARA-Forge | https://github.com/YARAHQ/yara-forge |
| Malpedia | https://malpedia.caad.fkie.fraunhofer.de/ |

---

*Document generated for the DetectForge project. Last updated: 2026-02-10.*
