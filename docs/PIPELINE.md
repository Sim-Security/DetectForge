# DetectForge Pipeline

> How a threat intelligence report becomes detection rules.

---

## Overview

```
┌─────────────────┐
│  Threat Report   │  Input: Markdown, text, PDF, HTML
│  (CISA advisory, │
│   vendor blog,   │
│   incident report)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  1. Normalize    │  No AI — pure parsing
│     Report       │  Split into sections, extract metadata
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  2. Extract IOCs │  No AI — regex pattern matching
│     (regex)      │  IPs, domains, hashes, CVEs, URLs
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  3. Extract TTPs │  AI Call #1 — LLM identifies attack techniques
│     (AI)         │  Returns structured TTP objects with artifacts
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  4. Map to       │  AI Call #2 — LLM maps TTPs to MITRE ATT&CK
│     ATT&CK (AI)  │  Returns technique IDs, tactics, confidence
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  5. Select       │  No AI — lookup table
│     Template     │  ATT&CK technique → logsource category → fields
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  6. Generate     │  AI Call #3 (per technique) — core generation
│     Sigma Rules  │  LLM produces detection YAML using template fields
│     (AI)         │  + IOCs embedded as detection values
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  7. Validate     │  No AI — schema + syntax checking
│     Rules        │  Structure, logsource, condition references
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  8. Score        │  No AI — heuristic content analysis
│     Quality      │  5 dimensions: syntax, logic, docs, ATT&CK, FP
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Output          │  Sigma YAML files, JSON results,
│                  │  quality report, benchmark markdown
└─────────────────┘
```

**AI calls per report:** 2 + N (where N = number of ATT&CK techniques identified, typically 5-7)

**Typical cost:** $0.02-0.03 per report using the fast model tier

---

## Step 1: Normalize Report

**Code:** `src/ingestion/normalizer.ts`

**What it does:** Takes raw input in any supported format and produces a structured `ThreatReport` object.

**Input:** Raw text, markdown, PDF buffer, or HTML string.

**Process:**
1. Detects input format (markdown, PDF, HTML, plain text)
2. Converts to clean text (strips HTML tags, extracts PDF text)
3. Splits into sections by markdown headers (`## Attack Chain`, `## IOCs`, etc.)
4. Classifies each section's type (ioc_section, ttp_section, recommendations, executive_summary)
5. Extracts metadata (title from first H1, date patterns, source URL)

**Output:**
```typescript
{
  id: "report-abc123",
  title: "StopRansomware: Black Basta",
  rawText: "# StopRansomware: Black Basta...",  // full text
  sections: [
    { title: "Executive Summary", type: "executive_summary", content: "..." },
    { title: "Attack Chain", type: "ttp_section", content: "..." },
    { title: "Indicators of Compromise", type: "ioc_section", content: "..." },
    // ...
  ],
  metadata: { source: "CISA", date: "2024-05-10" }
}
```

**No AI involved.** Pure text parsing and regex-based section classification.

---

## Step 2: Extract IOCs

**Code:** `src/extraction/ioc-extractor.ts`

**What it does:** Scans the full report text with regex patterns to find indicators of compromise.

**Input:** The raw text string from the normalized report.

**IOC types detected:**

| Type | Pattern | Example |
|------|---------|---------|
| IPv4 | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | `170.130.165.73` |
| IPv6 | Full IPv6 regex | `2001:db8::1` |
| Domain | Domain name patterns, including defanged | `moereng[.]com`, `hxxps://evil.com` |
| URL | HTTP/HTTPS URLs, defanged variants | `hxxps://evil[.]com/payload` |
| MD5 | 32 hex chars | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 | 40 hex chars | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 | 64 hex chars | `e3b0c44298fc1c149afbf4c8996fb924...` |
| CVE | `CVE-\d{4}-\d{4,}` | `CVE-2024-1709` |
| Email | Standard email pattern | `attacker@evil.com` |
| Registry Key | Windows registry path patterns | `HKLM\SOFTWARE\Microsoft\...` |

**Output:**
```typescript
[
  { type: "ipv4", value: "170.130.165.73", context: "C2 server used for..." },
  { type: "cve", value: "CVE-2024-1709", context: "ConnectWise ScreenConnect..." },
  { type: "domain", value: "moereng.com", context: "..." },
  // ...
]
```

**No AI involved.** Regex-only extraction. Runs in under 1 second regardless of report size. IOCs extracted here get embedded into generated detection rules (e.g., as IP addresses in network rules, hashes in file rules).

---

## Step 3: Extract TTPs (AI)

**Code:** `src/extraction/ttp-extractor.ts`

**What it does:** Sends the report text to the LLM and asks it to identify the tactics, techniques, and procedures described.

**Input:** The full report text + extraction options (model tier, temperature).

**The AI prompt includes:**
- The full report text
- Instructions to extract structured TTP objects
- Expected output format: technique name, description, artifacts (processes, files, network indicators, registry keys), confidence level
- JSON schema for the response

**Example AI response (parsed):**
```typescript
[
  {
    name: "EDR Disablement via Backstab Tool",
    description: "Threat actors use the Backstab tool to terminate
      endpoint security processes, allowing them to operate undetected.
      They also use PowerShell commands to disable Windows Defender
      real-time monitoring.",
    artifacts: [
      { type: "process", value: "backstab.exe" },
      { type: "process", value: "backstab64.exe" },
      { type: "process", value: "powershell.exe" },
      { type: "command", value: "Set-MpPreference -DisableRealtimeMonitoring" }
    ],
    confidence: "high"
  },
  {
    name: "Shadow Copy Deletion for Recovery Prevention",
    description: "Before deploying ransomware, actors delete Volume
      Shadow Copies using vssadmin to prevent file recovery.",
    artifacts: [
      { type: "process", value: "vssadmin.exe" },
      { type: "command", value: "vssadmin delete shadows /all /quiet" }
    ],
    confidence: "high"
  },
  // ... typically 5-7 TTPs per report
]
```

**1 API call.** ~10-15 seconds. The LLM reads the entire report and identifies discrete attack behaviors with their observable artifacts.

---

## Step 4: Map to ATT&CK (AI)

**Code:** `src/extraction/attack-mapper.ts`

**What it does:** Takes each extracted TTP and asks the LLM to map it to the most specific MITRE ATT&CK technique.

**Input:** The array of extracted TTPs from Step 3.

**The AI prompt includes:**
- Each TTP's name, description, and artifacts
- Instructions to find the most specific technique ID (prefer sub-techniques like T1562.001 over parent T1562)
- The local ATT&CK knowledge base (`src/knowledge/mitre-attack/`) provides valid technique IDs, names, and tactics for validation

**Example AI response (parsed):**
```typescript
[
  {
    techniqueId: "T1562.001",
    techniqueName: "Impair Defenses: Disable or Modify Tools",
    tactic: "Defense Evasion",
    confidence: "high"
  },
  {
    techniqueId: "T1490",
    techniqueName: "Inhibit System Recovery",
    tactic: "Impact",
    confidence: "high"
  },
  // ... one mapping per TTP
]
```

**1 API call.** ~4-7 seconds. The mapping is validated against the local ATT&CK dataset to ensure technique IDs actually exist.

---

## Step 5: Select Template

**Code:** `src/generation/sigma/templates.ts`

**What it does:** Maps each ATT&CK technique to the best Sigma logsource category and loads the corresponding template.

**Input:** ATT&CK technique ID + tactic from Step 4.

**Lookup chain:**
1. Check specific sub-technique ID (e.g., `T1562.001` → `security`, `process_creation`)
2. Check parent technique (e.g., `T1562` → `security`, `registry_event`)
3. Fall back to tactic (e.g., `defense-evasion` → `process_creation`, `ps_script`)
4. Fall back to artifact types from the TTP (process → `process_creation`, file → `file_event`)

**Available templates (10 logsource categories):**

| Category | Product | Available Fields |
|----------|---------|------------------|
| `process_creation` | windows | Image, CommandLine, ParentImage, User, Hashes, ... |
| `network_connection` | windows | Image, DestinationIp, DestinationHostname, DestinationPort, ... |
| `file_event` | windows | Image, TargetFilename, CreationUtcTime, User |
| `registry_event` | windows | EventType, Image, TargetObject, Details, User |
| `security` | windows | EventID, SubjectUserName, TargetUserName, LogonType, IpAddress, Status, ... |
| `image_load` | windows | Image, ImageLoaded, Signed, SignatureStatus, ... |
| `dns_query` | windows | Image, QueryName, QueryStatus, QueryResults |
| `pipe_created` | windows | PipeName, Image, User |
| `wmi_event` | windows | EventType, Operation, Query, Consumer, Filter |
| `ps_script` | windows | ScriptBlockText, ScriptBlockId, Path |

**Each template provides:**
- The `logsource` block for the Sigma rule header
- The list of `availableFields` — real Sysmon/Windows field names the AI can use
- Common false positive patterns for that log type
- An example detection structure

**No AI involved.** Deterministic lookup. The template's `availableFields` list is critical — it gets sent to the AI in Step 6 so the generated rules use real, valid field names instead of hallucinated ones.

---

## Step 6: Generate Sigma Rules (AI)

**Code:** `src/generation/sigma/sigma-generation.ts`

**What it does:** For each TTP + ATT&CK mapping + template, constructs a detailed prompt and asks the LLM to generate a complete Sigma detection rule.

**Input per rule:**
- The TTP (name, description, artifacts)
- The ATT&CK mapping (technique ID, name, tactic)
- The template (logsource, available fields, common FPs)
- Extracted IOCs from Step 2 (IPs, domains, hashes to embed)

**The AI prompt includes:**
1. **System prompt** — You are a detection engineer. Generate a Sigma rule. Here are the available fields for this logsource: `[Image, CommandLine, ParentImage, User, ...]`
2. **User prompt** — containing:
   - TTP description and artifacts
   - ATT&CK technique details
   - IOCs to embed as detection values
   - Instructions: use multiple selection blocks, include filters for false positives, use specific field values from the artifacts
3. **JSON schema** — enforces the exact output structure:
   ```
   { title, description, tags, logsource, detection, falsepositives, level }
   ```

**Example generated rule (what the AI returns, converted to YAML):**
```yaml
title: Inhibit System Recovery via Vssadmin Shadow Copy Deletion
id: 9d088a1b-e491-4be0-a8b5-bcb7b8b161b1
status: experimental
description: >
  Detects the deletion of Volume Shadow Copies using vssadmin.exe.
  This technique is frequently used by ransomware families, such as
  Black Basta, to prevent victims from recovering encrypted files.
author: DetectForge
date: 2026/02/10
tags:
  - attack.impact
  - attack.t1490
logsource:
  product: windows
  category: process_creation
detection:
  selection_vssadmin:
    Image:
      - "*\\vssadmin.exe"
    CommandLine:
      - "*delete*"
      - "*shadows*"
  selection_flags:
    CommandLine:
      - "*/all*"
      - "*/quiet*"
  filter_legitimate_admin:
    User:
      - NT AUTHORITY\SYSTEM
    ParentImage:
      - "*\\services.exe"
      - "*\\msiexec.exe"
  condition: (selection_vssadmin and selection_flags) and not filter_legitimate_admin
falsepositives:
  - Legitimate backup software performing maintenance tasks
  - System administrators manually managing disk space
  - Windows Update or installer processes managing restore points
level: high
```

**Key things to notice in the output:**
- **Real field names** from the template: `Image`, `CommandLine`, `ParentImage`, `User` — these are actual Sysmon/Windows event log fields
- **Multiple detection blocks**: `selection_vssadmin` + `selection_flags` + `filter_legitimate_admin`
- **Wildcard patterns**: `*\\vssadmin.exe`, `*delete*` — standard Sigma value matching
- **Filter block**: Excludes legitimate SYSTEM account activity — shows FP awareness
- **Boolean condition**: `(A and B) and not C` — structured logic
- **IOC integration**: Artifacts from Step 3 (`vssadmin.exe`, `delete shadows /all /quiet`) became detection values
- **ATT&CK tags**: `attack.impact`, `attack.t1490` link back to the mapping

**1 API call per technique.** ~3-5 seconds each. This is the most expensive step, accounting for ~60% of total cost. For a report with 6 ATT&CK techniques, this step makes 6 separate API calls.

---

## Step 7: Validate Rules

**Code:** `src/generation/sigma/validator.ts`

**What it does:** Checks each generated rule for structural correctness.

**Validation checks performed:**

| Check | What It Verifies |
|-------|-----------------|
| Required fields | title, description, logsource, detection, condition all present |
| UUID format | `id` field is valid UUID v4 |
| Status enum | Must be: experimental, test, stable, deprecated, unsupported |
| Level enum | Must be: informational, low, medium, high, critical |
| Logsource catalog | product + category + service combination is recognized |
| Condition references | Every block name in `condition` has a matching detection key |
| ATT&CK tags | Tags starting with `attack.t` have valid technique ID format |
| Detection structure | Each detection block is a valid key-value mapping |
| YAML syntax | The raw YAML string parses without errors |

**Output:**
```typescript
{
  valid: true,        // overall pass/fail
  syntaxValid: true,  // YAML parses correctly
  schemaValid: true,  // all required fields present and typed correctly
  errors: [],         // blocking issues
  warnings: []        // non-blocking concerns
}
```

**No AI involved.** Deterministic validation. ~94% of generated rules pass on the first attempt. Failed rules get errors like "condition references 'filter_main' but no detection key 'filter_main' exists."

---

## Step 8: Score Quality

**Code:** `src/testing/quality-scorer.ts`

**What it does:** Analyzes the actual content of each rule and scores it 1-10 across five dimensions.

**Dimensions and weights:**

| Dimension | Weight | What It Measures |
|-----------|--------|-----------------|
| Syntax Validity | 25% | Validation errors and warnings (10 minus penalties) |
| Detection Logic | 30% | Field relevance vs template, value patterns, condition complexity, filter blocks |
| Documentation | 15% | Description quality, ATT&CK tags, references, inline FP documentation |
| ATT&CK Mapping | 15% | Valid technique ID format, tactic present, sub-technique specificity |
| FP Handling | 15% | falsepositives array, filter/exclusion blocks, description specificity, severity level |

**Detection Logic scoring (the most complex dimension):**

For Sigma rules, the scorer checks:
1. **Selection/filter block count** — more detection blocks = more specific rule (0-2 pts)
2. **Explicit filter blocks** — `filter_*` or `exclusion_*` keys show FP awareness (0-2 pts)
3. **Field relevance** — are the field names in the detection blocks actually valid for this logsource? Cross-references against the template's `availableFields` list (0-2 pts)
4. **Value pattern diversity** — how many values, do they use wildcards, are they specific? (0-2 pts)
5. **Condition complexity** — boolean operators, negation, grouping, multiple block references (0-2 pts)

**Example score breakdown for a high-quality rule (8.1/10):**
```
Syntax:     10/10  (no errors or warnings)
Detection:   9/10  (3 blocks + filter + relevant fields + wildcards + complex condition)
Docs:        7/10  (100+ char description + 2 ATT&CK tags + 3 FP strings)
ATT&CK:      8/10  (valid T1490 + tactic "impact")
FP Handling:  8/10  (3 FP strings + filter block + appropriate "high" level)

Overall: (10×0.25) + (9×0.30) + (7×0.15) + (8×0.15) + (8×0.15) = 8.7 → 8.1 (after rounding)
```

**Example score breakdown for a weaker rule (6.0/10):**
```
Syntax:      8/10  (1 validation warning)
Detection:   5/10  (1 selection + no filters + generic fields)
Docs:        5/10  (short description + 1 ATT&CK tag)
ATT&CK:      8/10  (valid technique ID + tactic)
FP Handling:  4/10  (1 FP string + no filter blocks)

Overall: (8×0.25) + (5×0.30) + (5×0.15) + (8×0.15) + (4×0.15) = 6.1 → 6.0
```

**No AI involved.** Pure heuristic analysis of rule content.

---

## What Gets Produced

For each input report, DetectForge generates:

| Output | Location | Description |
|--------|----------|-------------|
| Sigma YAML files | `data/benchmark-output/<report>/` | One `.yml` file per ATT&CK technique — ready to deploy to a SIEM |
| Benchmark results JSON | `data/benchmark-output/benchmark-results.json` | Full structured data: IOCs, TTPs, mappings, rules, scores per report |
| Benchmark report | `docs/BENCHMARKS.md` | Formatted markdown with aggregate and per-report results |

**Each Sigma YAML file** is a complete, valid Sigma rule that can be loaded directly into:
- Splunk (via sigma-cli or pySigma backend)
- Elastic Security (via Sigma to ES|QL conversion)
- Microsoft Sentinel (via Sigma to KQL conversion)
- Any SIEM that supports Sigma rule format

---

## Cost and Performance

Benchmarked against 3 real CISA threat intelligence advisories:

| Metric | Value |
|--------|-------|
| Reports processed | 3 |
| Total API calls | 23 |
| Total tokens | 52,534 |
| Total cost | $0.08 |
| Total time | 126 seconds |
| Avg time per report | 42 seconds |
| Avg cost per report | $0.027 |
| Rules generated | 17 |
| Validation pass rate | 94% (16/17) |
| Avg quality score | 7.8/10 |

**Cost breakdown by step:**
- TTP extraction: ~20% of cost (1 call per report)
- ATT&CK mapping: ~15% of cost (1 call per report)
- Rule generation: ~65% of cost (1 call per technique, 5-7 per report)
- All other steps: $0 (no AI calls)

---

## API Configuration

DetectForge uses OpenRouter as the AI provider, supporting three model tiers:

| Tier | Use Case | Model | Cost |
|------|----------|-------|------|
| `fast` | Default for benchmarks | Cost-optimized | ~$0.03/report |
| `standard` | Balanced quality/cost | Mid-tier model | ~$0.06/report |
| `quality` | Maximum rule quality | Top-tier model | ~$0.10/report |

Configuration via `.env`:
```
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL_FAST=...
OPENROUTER_MODEL_STANDARD=...
OPENROUTER_MODEL_QUALITY=...
```

All AI calls use temperature 0.1 for deterministic output and JSON schema enforcement for structured responses.
