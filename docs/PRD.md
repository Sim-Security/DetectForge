# DetectForge Product Requirements Document (PRD)

**Version:** 1.0
**Date:** 2026-02-10
**Author:** DetectForge Team
**Status:** Draft

---

## 1. Executive Summary

DetectForge is an AI-powered detection rule generation platform that transforms threat intelligence reports into validated, production-ready detection rules across multiple formats (Sigma, YARA, Suricata). Built for detection engineers and SOC teams, DetectForge automates the traditionally manual, time-intensive process of operationalizing threat intelligence.

The average detection engineer spends 6-14 hours per threat report manually extracting indicators of compromise (IOCs), mapping tactics, techniques, and procedures (TTPs) to MITRE ATT&CK, and crafting detection rules. This bottleneck results in backlogs of 50-100+ unoperationalized reports at most security operations centers. DetectForge reduces this timeline from hours to minutes while maintaining quality benchmarks against human-written rules from SigmaHQ and the security community.

Unlike existing tools that convert between rule formats or provide AI suggestions without validation, DetectForge offers a complete, end-to-end pipeline: ingest threat reports (PDF, HTML, Markdown, STIX), extract IOCs and TTPs with AI assistance, generate multi-format detection rules, validate syntax and semantics, test against attack and benign datasets, and produce comprehensive documentation. DetectForge is designed as a portfolio-grade, open-source, CLI-first tool with honest quality metrics and transparent benchmarking.

---

## 2. Problem Statement

### The Manual Detection Engineering Bottleneck

Security operations teams receive dozens of high-quality threat intelligence reports weekly from sources like Mandiant, CrowdStrike, Unit 42, CISA, and others. Each report contains actionable intelligence about adversary behavior, but converting that intelligence into operational detections is a manual, labor-intensive process:

1. **Reading & Analysis** (30-60 min): Parse the full report, often 20-50 pages of technical detail
2. **IOC Extraction** (15-30 min): Manually extract IP addresses, domains, file hashes, registry keys, etc., handling defanged formats and context
3. **TTP Identification & ATT&CK Mapping** (30-60 min): Identify behavioral patterns, map to MITRE ATT&CK techniques/subtechniques
4. **Detection Rule Writing** (2-8 hours per technique): Write Sigma rules for SIEM, YARA rules for file analysis, Suricata rules for network detection
5. **Documentation** (1-2 hours): Document each rule, expected false positives, coverage gaps
6. **Validation** (30 min): Test syntax against spec, validate field names, check logic
7. **Testing** (1-2 hours): Test against sample data, tune for false positives

**Total: 6-14 hours of skilled labor per report.**

### The Backlog Crisis

Most SOC teams have a backlog of 50-100 threat intelligence reports they have never operationalized. Threat actors evolve faster than defenders can write detection rules. This creates a strategic vulnerability: teams know about threats but cannot detect them.

### Existing Tool Gaps

Current solutions are insufficient:

- **Uncoder.io / SOC Prime**: Excellent at converting between rule formats, but doesn't generate rules from threat intelligence. AI rule generation is a black box with no validation.
- **ChatGPT/Claude raw prompting**: Generates plausible-looking rules but with no validation, no false positive analysis, no ATT&CK mapping verification, and no benchmarking against known-good rules.
- **Sigma/SigmaHQ**: Gold standard rule repository, but rules are manually written. No AI-assisted generation pipeline.
- **Elastic/Splunk Detection Repos**: Vendor-specific, manually maintained, not portable.

**DetectForge fills this gap with a full AI-powered pipeline that maintains quality through rigorous validation and testing.**

---

## 3. Vision & Goals

### Primary Goal

**Reduce the time from threat intelligence report to operational detection rules from 6-14 hours to under 10 minutes**, while maintaining or exceeding the quality of human-written rules.

### Secondary Goals

1. **Quality Benchmarking**: Measure generated rules against SigmaHQ human-written baselines across metrics: syntax validity, detection logic quality, true positive rates, false positive rates, documentation completeness.

2. **Honest Metrics**: Publish both successes and failures transparently. DetectForge is a portfolio project that demonstrates engineering rigor through honest reporting of limitations and gaps.

3. **Multi-Format Generation**: Support the three primary detection rule formats used in modern security operations:
   - Sigma (SIEM-agnostic log detection)
   - YARA (file-based malware detection)
   - Suricata (network traffic detection)

4. **Automated Testing**: Validate every generated rule against syntax specifications, test against attack simulations, measure false positive rates on benign data, and generate coverage metrics against MITRE ATT&CK.

5. **Portfolio Excellence**: Serve as a portfolio-grade project demonstrating advanced TypeScript/Node.js architecture, AI integration, detection engineering expertise, testing methodology, and technical documentation.

---

## 4. Target Users & Personas

### Primary: Detection Engineers

**Who they are:** Security professionals responsible for writing, tuning, and deploying detection rules across SIEM, EDR, and network monitoring platforms.

**Daily pain:**
- Backlog of 50-100 unprocessed threat intelligence reports
- Manual extraction of IOCs and TTPs from verbose reports
- Writing rules in 3+ different formats for different platforms
- Tuning rules to reduce false positives without missing threats
- Keeping rules updated as ATT&CK taxonomy evolves

**How DetectForge helps:**
- Automate 90% of the manual extraction and rule generation work
- Generate Sigma, YARA, and Suricata rules from a single threat report
- Get rules with pre-documented false positive scenarios and coverage gaps
- Benchmark generated rules against SigmaHQ standards

**Success looks like:**
- Processing 10 threat reports per day instead of 1-2 per week
- Reducing rule backlog from 100+ to <10 within a month
- Spending more time on advanced threat hunting and less on manual rule writing

### Secondary: SOC Analysts

**Who they are:** Tier 1-3 analysts who triage alerts, investigate incidents, and write hunt queries.

**Daily pain:**
- Receiving threat intelligence reports but lacking time/expertise to write rules
- Copy-pasting IOCs into manual queries
- Missing threats because rules don't exist yet

**How DetectForge helps:**
- Generate hunt queries from threat intel in minutes
- Get pre-validated rules that can be deployed immediately
- Understand ATT&CK mapping without manual research

**Success looks like:**
- Operationalizing threat intel the day it's published
- Running hunt queries during investigations without custom rule development
- Better understanding of which techniques are covered vs. gaps

### Secondary: Threat Intelligence Analysts

**Who they are:** Analysts who produce or consume threat intelligence reports.

**Daily pain:**
- Publishing reports but not seeing them operationalized
- No feedback loop on which IOCs/TTPs are most valuable
- Lack of visibility into detection coverage

**How DetectForge helps:**
- Automatically generate detection content from their reports
- See which parts of their report are detectable vs. blind spots
- Provide machine-readable threat intel outputs (STIX, structured JSON)

**Success looks like:**
- Threat reports come with ready-to-deploy detection rules
- Feedback on detection coverage influences future intelligence priorities
- Faster operationalization increases perceived value of intel team

### Tertiary: Security Engineers / Architects

**Who they are:** Engineers responsible for SIEM platform management, detection engineering infrastructure, and security tool integrations.

**Daily pain:**
- Managing disparate rule formats across multiple platforms
- Ensuring rules meet quality standards before production deployment
- Tracking detection coverage across the MITRE ATT&CK matrix

**How DetectForge helps:**
- CLI-first tool that integrates into CI/CD pipelines
- Automated quality gates and validation
- Coverage reporting and gap analysis

**Success looks like:**
- Detection rules as code with version control and automated testing
- Pre-deployment validation catches issues before production
- ATT&CK Navigator layers show real-time coverage

---

## 5. Scope

### In Scope for v1.0 (MVP)

**Core Pipeline:**
- FR-ING: Ingest threat reports (PDF, HTML, Markdown, plain text)
- FR-EXT: Extract IOCs (IPs, domains, hashes, URLs, emails, file paths, registry keys)
- FR-EXT: Extract TTPs using AI with MITRE ATT&CK mapping
- FR-GEN: Generate Sigma rules for host-based detection (process creation, file events, registry events)
- FR-GEN: Generate YARA rules for file-based detection
- FR-GEN: Generate Suricata rules for network detection
- FR-VAL: Validate all rules against syntax specifications
- FR-DOC: Generate documentation for each rule (what it detects, how it works, expected FPs, coverage gaps)
- FR-CLI: Command-line interface with progress indicators and summary reports
- FR-RPT: Output formats: JSON, Markdown, individual rule files

**Quality & Testing:**
- FR-TST: Automated syntax validation (100% pass rate required)
- FR-TST: ATT&CK technique ID validation
- FR-TST: Field name validation for Sigma logsource categories
- FR-DAT: MITRE ATT&CK data pipeline (automated download and parsing of STIX data)
- NFR-QUAL: Quality gates enforced in CLI

**Documentation:**
- README with problem statement, installation, quick start, architecture, benchmarks
- Per-rule documentation with false positive analysis
- Honest metrics: publish accuracy rates, failures, and limitations

### In Scope for v1.1+

**Advanced Testing:**
- FR-TST: True positive testing against synthetic attack logs
- FR-TST: False positive testing against benign baselines
- FR-TST: Automated benchmarking against SigmaHQ corpus
- FR-RPT: SARIF output for CI/CD integration
- FR-RPT: ATT&CK Navigator JSON layers

**Extended Ingestion:**
- FR-ING: STIX JSON bundle parsing
- FR-ING: Direct URL ingestion (download and parse)
- FR-ING: RSS feed monitoring for new reports

**Advanced Generation:**
- FR-GEN: Sigma rule conversion to SPL, KQL, Lucene (via pySigma backends)
- FR-GEN: Cloud detection rules (AWS CloudTrail, Azure, GCP)
- FR-GEN: Linux/macOS detection rules
- FR-GEN: Advanced Sigma features (aggregation, timeframes)

**AI Enhancements:**
- FR-EXT: Confidence scoring for extracted IOCs and TTPs
- FR-GEN: Quality scoring for generated rules
- FR-DOC: Automated tuning recommendations based on environment

**Data Collection:**
- FR-DAT: SigmaHQ reference corpus download and indexing
- FR-DAT: Threat report collection from RSS feeds
- FR-DAT: Attack log generation using Atomic Red Team integration

### Explicitly Out of Scope

**Not in v1.x:**
- Web UI (CLI-first, web UI is future consideration)
- Real-time threat feed integration (batch processing only)
- Automated deployment to production SIEMs (output rules for manual deployment)
- Machine learning model training (use pre-trained LLMs via API)
- Support for proprietary/paid threat intel platforms (public sources only)
- Actual malware samples in repository (hashes and references only)
- Live attack simulation (use pre-recorded datasets)
- Multi-tenancy / SaaS deployment (local/self-hosted only)

---

## 6. Functional Requirements

### FR-ING: Ingestion

**FR-ING-001: PDF Report Parsing** (P0)
- **Description:** Parse PDF threat intelligence reports and extract structured text
- **Acceptance Criteria:**
  - Supports standard threat intel report formats (Mandiant, CrowdStrike, Unit 42, CISA)
  - Handles multi-column layouts
  - Extracts section headings and body text
  - Preserves IOC formatting (including defanged indicators)
  - Handles documents up to 100 pages
  - Gracefully handles encrypted PDFs (error message)
- **Dependencies:** `pdf-parse` npm package

**FR-ING-002: HTML Report Parsing** (P0)
- **Description:** Parse HTML-formatted threat reports (blog posts, advisories)
- **Acceptance Criteria:**
  - Extracts main article content, strips navigation/chrome
  - Handles common CMS platforms (WordPress, Medium, Ghost)
  - Preserves code blocks and tables
  - Extracts metadata (title, author, date if available)
- **Dependencies:** `cheerio` or `jsdom`

**FR-ING-003: Markdown Report Parsing** (P1)
- **Description:** Parse Markdown-formatted threat reports
- **Acceptance Criteria:**
  - Full Markdown spec support (CommonMark)
  - Preserves section structure
  - Handles tables, code blocks, lists
- **Dependencies:** `marked` or `markdown-it`

**FR-ING-004: Plain Text Report Parsing** (P1)
- **Description:** Parse plain text threat reports
- **Acceptance Criteria:**
  - Handles UTF-8 and ASCII encoding
  - Attempts to detect section boundaries
  - Preserves line breaks and structure

**FR-ING-005: Report Normalization** (P0)
- **Description:** Normalize all input formats to a unified ThreatReport data structure
- **Acceptance Criteria:**
  - Produces consistent ThreatReport object with: id, title, source, date, rawText, sections[], metadata
  - Sections categorized as: overview, technical_details, iocs, ttps, recommendations, other
  - Metadata extraction: threatActor, campaign, targetSectors, malwareFamilies (when available)
  - TypeScript types defined and documented

**FR-ING-006: STIX JSON Parsing** (P1, v1.1)
- **Description:** Parse STIX 2.1 JSON bundles
- **Acceptance Criteria:**
  - Extracts indicators, attack-patterns, malware, intrusion-sets
  - Maps to internal ThreatReport structure
  - Preserves relationships between objects

### FR-EXT: Extraction

**FR-EXT-001: IOC Extraction - Network Indicators** (P0)
- **Description:** Extract network-based IOCs from report text
- **Acceptance Criteria:**
  - IPv4 addresses (standard and defanged: `192.168.1[.]1`, `192.168.1.1`)
  - IPv6 addresses
  - Domains (standard and defanged: `evil[.]com`, `evil(.)com`)
  - URLs (standard and defanged)
  - Email addresses
  - Deduplication (normalize to canonical form)
  - Classification by type and confidence
- **Target Metrics:** >95% recall, >90% precision vs. ground truth

**FR-EXT-002: IOC Extraction - File Indicators** (P0)
- **Description:** Extract file-based IOCs from report text
- **Acceptance Criteria:**
  - MD5 hashes (32 hex chars)
  - SHA1 hashes (40 hex chars)
  - SHA256 hashes (64 hex chars)
  - Windows file paths (C:\..., \\..., %APPDATA%\...)
  - Linux/macOS file paths (/var/..., ~/...)
  - Registry keys (HKLM\..., HKCU\...)
  - Deduplication and normalization

**FR-EXT-003: IOC Extraction - Other Indicators** (P1)
- **Description:** Extract miscellaneous IOCs
- **Acceptance Criteria:**
  - CVE IDs (CVE-YYYY-NNNNN)
  - MITRE ATT&CK technique IDs (T####.###)
  - Mutex names
  - Service names
  - Scheduled task names
  - User account names

**FR-EXT-004: IOC Context Extraction** (P1)
- **Description:** Extract context and relationships for IOCs using AI
- **Acceptance Criteria:**
  - Distinguish threat IOCs from example/reference IOCs
  - Extract IOC relationships (IP hosted domain, domain served hash)
  - Extract timestamps (when was IOC observed)
  - Extract usage context (C2 server, initial payload, staging domain)

**FR-EXT-005: TTP Extraction** (P0)
- **Description:** Extract behavioral TTPs from report text using AI
- **Acceptance Criteria:**
  - Plain-English description of adversary behavior
  - Tools/utilities used (Mimikatz, PsExec, PowerShell, etc.)
  - Target systems/platforms (Windows, Linux, macOS, Cloud)
  - Artifacts created (files, registry keys, event log entries)
  - Detection opportunities mentioned in report
  - Confidence scoring (high/medium/low)
  - TypeScript TTP data structure
- **Target Metrics:** >85% recall, >80% precision vs. ground truth

**FR-EXT-006: MITRE ATT&CK Mapping** (P0)
- **Description:** Map extracted TTPs to MITRE ATT&CK technique IDs
- **Acceptance Criteria:**
  - Two-pass approach: AI mapping + validation against ATT&CK data
  - Subtechnique specificity (prefer T1059.001 over T1059)
  - Multiple techniques per TTP when applicable
  - Tactic assignment (Initial Access, Execution, Persistence, etc.)
  - Platform matching (Windows, Linux, macOS, etc.)
  - Confidence scoring (high/medium/low)
  - Validation: technique exists, correct tactic, platform matches
- **Target Metrics:** >85% correct technique ID at subtechnique level

**FR-EXT-007: IOC Enrichment** (P1)
- **Description:** Enrich extracted IOCs with additional context
- **Acceptance Criteria:**
  - Defang indicators for safe handling
  - Type classification (C2 server, phishing domain, payload hash)
  - Deduplication across report
  - Refanging for detection rule generation

### FR-GEN: Rule Generation

**FR-GEN-001: Sigma Rule Generation - Structure** (P0)
- **Description:** Generate syntactically valid Sigma rules from extraction results
- **Acceptance Criteria:**
  - All required fields: title, id (UUID v4), status, description, logsource, detection, level
  - Recommended fields: author (DetectForge), date, modified, references, tags, falsepositives
  - YAML formatting complies with Sigma spec
  - UTF-8 encoding
  - One rule per detected TTP (where Sigma is appropriate)
- **Target Metrics:** 100% syntax validity

**FR-GEN-002: Sigma Rule Generation - Detection Logic** (P0)
- **Description:** Generate effective detection logic for Sigma rules
- **Acceptance Criteria:**
  - Uses appropriate logsource category (process_creation, file_event, registry_event, network_connection, dns_query, etc.)
  - Field names match logsource standard (Image, CommandLine, ParentImage, TargetFilename, etc.)
  - Detection patterns use appropriate modifiers (contains, endswith, startswith, re, base64, etc.)
  - Multiple selection conditions when needed
  - Filter conditions for known false positives
  - Condition logic is well-formed (AND/OR/NOT operators)
  - Not overly broad (e.g., not just matching "powershell.exe" without additional context)

**FR-GEN-003: Sigma Rule Generation - Metadata & Documentation** (P0)
- **Description:** Generate comprehensive metadata and documentation for Sigma rules
- **Acceptance Criteria:**
  - Title follows SigmaHQ naming convention (descriptive, technique-specific)
  - Description explains what behavior is detected (2-5 sentences)
  - References include original threat report URL and ATT&CK technique URL
  - Tags include ATT&CK tactic and technique (attack.execution, attack.t1059.001)
  - Level is justified (informational/low/medium/high/critical based on impact)
  - Falsepositives section includes at least 3 specific scenarios with tuning guidance
  - Status is "experimental" for newly generated rules

**FR-GEN-004: Sigma Rule Generation - Logsource Coverage** (P0)
- **Description:** Support key Sigma logsource categories
- **Acceptance Criteria:**
  - Windows: process_creation, image_load, file_event, registry_event, network_connection, dns_query, ps_script
  - Windows Event IDs: Security (4688), Sysmon (1, 3, 7, 11, 13, 22)
  - Coverage: Process execution, file creation, registry modification, network connections, PowerShell
- **Out of scope for v1.0:** Linux, macOS, Cloud (AWS/Azure/GCP)

**FR-GEN-005: YARA Rule Generation - Structure** (P0)
- **Description:** Generate syntactically valid YARA rules from extraction results
- **Acceptance Criteria:**
  - Valid rule syntax (compiles with `yara -C`)
  - Metadata section with: description, author, date, reference, hash, mitre_attack, tlp
  - Strings section with appropriate patterns (text strings, hex patterns, regex)
  - Condition section with file type checks (magic bytes) and size constraints
  - Rule names follow convention: alphanumeric + underscore, descriptive
  - Tags for classification (apt_name, malware_family, technique)
- **Target Metrics:** 100% compilation success

**FR-GEN-006: YARA Rule Generation - Detection Logic** (P0)
- **Description:** Generate effective YARA detection logic
- **Acceptance Criteria:**
  - File type constraints (uint16(0) == 0x5A4D for PE, etc.)
  - Filesize constraints (filesize < 10MB, etc.)
  - Multiple string matches combined with logical operators
  - Uses unique strings from malware, not generic library strings
  - Appropriate modifiers (ascii, wide, nocase, fullword)
  - Entropy checks for packed/encrypted files (math.entropy)
  - PE module checks (imports, exports, sections) when applicable
  - Not overly broad (single string without filesize constraint)

**FR-GEN-007: YARA Rule Generation - Performance** (P1)
- **Description:** Generate performant YARA rules
- **Acceptance Criteria:**
  - Avoids overly expensive patterns (e.g., `[-]` unbounded jumps)
  - String length > 4 bytes (no very short strings)
  - Regex patterns are efficient (no catastrophic backtracking)
  - File type and size constraints limit scan scope

**FR-GEN-008: Suricata Rule Generation - Structure** (P0)
- **Description:** Generate syntactically valid Suricata rules from extraction results
- **Acceptance Criteria:**
  - Valid rule syntax (passes `suricata -T`)
  - Components: action, protocol, source, destination, direction, options
  - Options include: msg, flow, content/pcre, reference, metadata, classtype, sid, rev
  - SID allocation: 9,000,000 - 9,999,999 range (local/custom rules)
  - Revision tracking (rev:1, rev:2, etc.)
- **Target Metrics:** 100% syntax validity

**FR-GEN-009: Suricata Rule Generation - Detection Logic** (P0)
- **Description:** Generate effective Suricata detection logic
- **Acceptance Criteria:**
  - Appropriate protocol (tcp, udp, http, dns, tls, etc.)
  - Flow direction (to_server, to_client, established)
  - Content matching for network IOCs (domains, IPs, URIs, user agents)
  - HTTP keywords (http.host, http.uri, http.user_agent, http.method)
  - TLS keywords (tls.sni, tls.cert_subject, tls.ja3.hash)
  - DNS keywords (dns.query)
  - PCRE patterns for flexible matching
  - Appropriate classtype (trojan-activity, command-and-control, etc.)
  - Metadata includes MITRE ATT&CK mapping

**FR-GEN-010: Suricata Rule Generation - Network IOC Coverage** (P0)
- **Description:** Generate Suricata rules for network-based IOCs
- **Acceptance Criteria:**
  - DNS queries to malicious domains
  - HTTP/HTTPS connections to malicious IPs/domains
  - Specific URI patterns (C2 check-in paths)
  - TLS certificate patterns (self-signed, suspicious CN)
  - JA3/JA3S fingerprints when available
  - File downloads (specific content types, sizes)

### FR-VAL: Validation

**FR-VAL-001: Sigma Syntax Validation** (P0)
- **Description:** Validate Sigma rules against specification
- **Acceptance Criteria:**
  - YAML parsing (no syntax errors)
  - Required fields present (title, logsource, detection, level)
  - Detection condition is well-formed
  - Field modifiers are valid (contains, endswith, re, base64, etc.)
  - Logsource category/product/service combinations are valid
  - ATT&CK technique IDs are real (validate against ATT&CK data)
  - No duplicate rule IDs
  - Uses pySigma validators or custom TypeScript implementation
- **Target Metrics:** 100% of generated rules pass validation

**FR-VAL-002: YARA Syntax Validation** (P0)
- **Description:** Validate YARA rules against specification
- **Acceptance Criteria:**
  - Compilation succeeds (`yara -C` or `yara-python` compile)
  - No syntax errors
  - String identifiers are unique
  - Condition references defined strings
  - Metadata keys are valid
  - Uses yara-python subprocess or YARA binary
- **Target Metrics:** 100% of generated rules compile

**FR-VAL-003: Suricata Syntax Validation** (P0)
- **Description:** Validate Suricata rules against specification
- **Acceptance Criteria:**
  - Passes `suricata -T` validation
  - Action is valid (alert, drop, pass, reject, etc.)
  - Protocol is valid (tcp, udp, http, tls, dns, etc.)
  - Options are well-formed
  - SID is unique and in correct range
  - PCRE patterns are valid
  - Uses Suricata binary validation
- **Target Metrics:** 100% of generated rules pass validation

**FR-VAL-004: Semantic Validation** (P1)
- **Description:** Validate detection logic correctness beyond syntax
- **Acceptance Criteria:**
  - Field names exist in target logsource (e.g., "CommandLine" exists in process_creation)
  - Values are appropriate for field type (e.g., EventID is numeric)
  - Condition logic is not trivially true or false
  - Not overly broad (e.g., matching on too-common strings)
  - Detection logic matches stated purpose in description

### FR-DOC: Documentation

**FR-DOC-001: Rule-Level Documentation** (P0)
- **Description:** Generate comprehensive documentation for each rule
- **Acceptance Criteria:**
  - "What This Detects" section (plain English, 1-3 paragraphs)
  - "How It Works" section (technical explanation of each detection logic component)
  - "MITRE ATT&CK Mapping" section (technique, tactic, platform)
  - "Expected False Positives" section (3-5 specific scenarios with tuning recommendations)
  - "What This Rule Does NOT Catch" section (evasions, limitations, gaps)
  - "Recommended Log Sources" section (specific event logs, data sources required)
  - "Tuning Recommendations" section (how to tune for specific environments)
  - Markdown format, one file per rule

**FR-DOC-002: False Positive Analysis** (P0)
- **Description:** Document expected false positive scenarios
- **Acceptance Criteria:**
  - Uses AI to generate 3-5 realistic FP scenarios
  - Each scenario is SPECIFIC (not "legitimate admin activity", but "SCCM task sequences executing encoded PowerShell with -ExecutionPolicy Bypass -NonInteractive -EncodedCommand to deploy software packages. The parent process chain would be svchost.exe → CCMExec.exe → powershell.exe.")
  - Includes tuning recommendation for each scenario (exclude specific accounts, parent processes, source hosts)
  - Severity assessment (how common is this FP scenario)

**FR-DOC-003: Coverage Gap Analysis** (P0)
- **Description:** Document what the generated rules do NOT cover
- **Acceptance Criteria:**
  - TTPs from report that couldn't be translated to rules (and why)
  - Alternative implementations of techniques that would evade rules
  - Required log sources that may not be available in all environments
  - Time-based gaps (rules work for active attack, not historical hunting)
  - Platform gaps (rule is Windows-specific, threat also targets Linux)

**FR-DOC-004: Summary Report** (P0)
- **Description:** Generate summary report for each processed threat report
- **Acceptance Criteria:**
  - Executive summary (1 paragraph: report source, threat actor, campaign)
  - IOCs extracted (counts by type: IPs, domains, hashes, etc.)
  - TTPs identified (count, list with ATT&CK IDs)
  - Rules generated (counts by type: Sigma, YARA, Suricata)
  - Validation results (pass/fail per rule)
  - ATT&CK coverage (techniques covered, tactics covered, percentage)
  - Processing metadata (time taken, AI tokens used, timestamp)
  - Markdown format

### FR-TST: Testing (v1.1)

**FR-TST-001: Synthetic Attack Log Generation** (P1, v1.1)
- **Description:** Generate synthetic attack logs that should match generated rules
- **Acceptance Criteria:**
  - For each Sigma rule, generate JSON log entries that match detection logic
  - Logs match logsource category schema (Sysmon Event ID 1, Windows Security 4688, etc.)
  - Include both positive cases (should match) and negative cases (should not match)
  - Store as test fixtures

**FR-TST-002: True Positive Testing** (P1, v1.1)
- **Description:** Test Sigma rules against attack datasets
- **Acceptance Criteria:**
  - Integrate Chainsaw or Hayabusa for rule-to-log matching
  - Test against EVTX-ATTACK-SAMPLES or OTRF Security Datasets
  - Report true positive rate (TP / (TP + FN))
  - Target: >90% TP rate per rule

**FR-TST-003: False Positive Testing** (P1, v1.1)
- **Description:** Test rules against benign datasets
- **Acceptance Criteria:**
  - Test against benign Windows baseline logs (48hr VM recording)
  - Report false positive rate (FP / total benign logs)
  - Target: <5% FP rate (aggregate), <0.1% for critical rules

**FR-TST-004: Benchmarking vs. SigmaHQ** (P1, v1.1)
- **Description:** Compare generated rules to SigmaHQ human-written rules
- **Acceptance Criteria:**
  - For techniques with existing SigmaHQ rules, compare detection logic breadth, field usage, FP handling, documentation quality
  - Score on 1-10 scale across dimensions
  - Publish results as comparative table

### FR-CLI: Command-Line Interface

**FR-CLI-001: Generate Command** (P0)
- **Description:** Primary command to generate rules from threat report
- **Syntax:** `detectforge generate --input <path> --output <dir> [options]`
- **Options:**
  - `--input, -i <path>`: Path to threat report file or URL
  - `--output, -o <dir>`: Output directory for rules (default: ./rules/)
  - `--format <formats>`: Comma-separated: sigma, yara, suricata, all (default: all)
  - `--sigma-only`: Shortcut for --format sigma
  - `--yara-only`: Shortcut for --format yara
  - `--suricata-only`: Shortcut for --format suricata
  - `--verbose, -v`: Verbose output
  - `--quiet, -q`: Minimal output
  - `--test`: Run validation and testing (v1.1)
  - `--benchmark`: Run benchmarking vs. reference rules (v1.1)
- **Output:**
  - Progress indicators for each stage (ingestion, extraction, generation, validation)
  - Color-coded results (green=valid, yellow=warning, red=error)
  - Summary table at end (IOCs extracted, rules generated, validation status)
  - Files written: individual rule files + summary report + documentation

**FR-CLI-002: Extract Command** (P1)
- **Description:** Extract IOCs and TTPs without generating rules
- **Syntax:** `detectforge extract --input <path> --output <file>`
- **Output:** JSON file with extraction results

**FR-CLI-003: Validate Command** (P1)
- **Description:** Validate existing rules
- **Syntax:** `detectforge validate --input <dir> --format <type>`
- **Output:** Validation report (pass/fail per rule, error details)

**FR-CLI-004: Coverage Command** (P1, v1.1)
- **Description:** Analyze ATT&CK coverage
- **Syntax:** `detectforge coverage --input <dir> --output <file> [--navigator-layer]`
- **Output:** Coverage report JSON, optionally ATT&CK Navigator layer JSON

**FR-CLI-005: Benchmark Command** (P1, v1.1)
- **Description:** Benchmark rules against reference corpus
- **Syntax:** `detectforge benchmark --input <dir> --sigmahq-path <dir>`
- **Output:** Benchmark report comparing to SigmaHQ

**FR-CLI-006: Progress Indicators** (P0)
- **Description:** Real-time feedback during processing
- **Acceptance Criteria:**
  - Spinner or progress bar during AI API calls
  - Stage-by-stage updates (Ingesting → Extracting → Generating → Validating)
  - Time elapsed per stage
  - Estimated remaining time (when possible)

**FR-CLI-007: Summary Output** (P0)
- **Description:** Comprehensive summary at end of generation
- **Acceptance Criteria:**
  - ASCII table with key metrics
  - Report title and source
  - IOCs extracted (by type)
  - TTPs identified (count)
  - ATT&CK techniques (count)
  - Rules generated (by format, valid/invalid counts)
  - Test results (if --test flag) (v1.1)
  - FP rate (if --test flag) (v1.1)
  - ATT&CK coverage percentage
  - Processing time
  - API tokens used (approximate cost)

### FR-RPT: Reporting

**FR-RPT-001: JSON Output** (P0)
- **Description:** Machine-readable JSON output
- **Acceptance Criteria:**
  - Single JSON file with all extraction and generation results
  - Schema: report metadata, IOCs[], TTPs[], rules[], validation[], coverage{}
  - JSON Schema defined and documented
  - UTF-8 encoding

**FR-RPT-002: Markdown Output** (P0)
- **Description:** Human-readable Markdown report
- **Acceptance Criteria:**
  - Summary section
  - IOCs table
  - TTPs table with ATT&CK mapping
  - Rules section (links to individual rule files)
  - Coverage summary
  - Gaps and limitations section

**FR-RPT-003: Individual Rule Files** (P0)
- **Description:** Write rules as individual files
- **Acceptance Criteria:**
  - Sigma rules: `<technique_id>_<descriptive_name>.yml` (e.g., `t1059.001_suspicious_encoded_powershell.yml`)
  - YARA rules: `<malware_family>_<descriptive_name>.yar`
  - Suricata rules: `<category>_<descriptive_name>.rules` or combined `custom.rules` file
  - UTF-8 encoding
  - Organized by subdirectories: `output/sigma/`, `output/yara/`, `output/suricata/`

**FR-RPT-004: SARIF Output** (P1, v1.1)
- **Description:** SARIF (Static Analysis Results Interchange Format) output for CI/CD
- **Acceptance Criteria:**
  - SARIF 2.1.0 format
  - Each rule as a SARIF "result"
  - Validation errors as SARIF "notifications"
  - Integrates with GitHub Advanced Security / code scanning

**FR-RPT-005: ATT&CK Navigator Layer** (P1, v1.1)
- **Description:** Generate ATT&CK Navigator JSON layer
- **Acceptance Criteria:**
  - Valid Navigator v4.x layer format
  - Techniques colored by coverage depth (number of rules)
  - Metadata includes rule titles
  - Can be uploaded to https://mitre-attack.github.io/attack-navigator/

### FR-DAT: Data Pipeline

**FR-DAT-001: ATT&CK Data Download** (P0)
- **Description:** Download and parse MITRE ATT&CK STIX data
- **Acceptance Criteria:**
  - Downloads from https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
  - Parses STIX 2.1 JSON bundle
  - Builds lookup maps: technique ID → name, description, tactics, data sources, platforms
  - Exports as TypeScript data structure or JSON cache
  - Includes subtechniques
  - Script: `scripts/download-attack-data.ts`
  - Refresh frequency: weekly (automated) or on-demand (manual)

**FR-DAT-002: ATT&CK Data Access** (P0)
- **Description:** Provide programmatic access to ATT&CK data
- **Acceptance Criteria:**
  - TypeScript module: `src/knowledge/mitre-attack/techniques.ts`
  - Functions: getTechniqueById(id), searchTechniques(query), getTactics(), getDataSources()
  - Validates technique IDs during extraction and generation
  - Provides detection recommendations from ATT&CK

**FR-DAT-003: SigmaHQ Corpus Download** (P1, v1.1)
- **Description:** Download reference Sigma rules for benchmarking
- **Acceptance Criteria:**
  - Clones or downloads from https://github.com/SigmaHQ/sigma
  - Curates representative subset (200-500 rules covering key techniques)
  - Categories: Windows (process_creation, file_event, registry, network), Linux, Cloud
  - Parses rules for comparison (logsource, detection patterns, field usage)
  - Script: `scripts/download-sigmahq-samples.ts`

**FR-DAT-004: Threat Report Collection** (P1, v1.1)
- **Description:** Collect public threat reports for testing
- **Acceptance Criteria:**
  - Collects 10-20 high-quality APT reports from CISA, Mandiant, CrowdStrike, Unit 42, The DFIR Report
  - Saves in multiple formats (original + plain text + markdown)
  - Creates ground truth JSON for each report (known IOCs, TTPs, expected rule counts)
  - Used as test oracle for measuring accuracy
  - Script: `scripts/collect-threat-reports.ts`

---

## 7. Non-Functional Requirements

### NFR-PERF: Performance

**NFR-PERF-001: Processing Time** (P0)
- **Requirement:** Process a typical threat report (20-50 pages, 5-10 TTPs) in under 5 minutes (target: under 3 minutes)
- **Measurement:** End-to-end time from `detectforge generate` command to completion
- **Acceptance:** 90% of reports process within time limit

**NFR-PERF-002: API Token Usage** (P1)
- **Requirement:** Track and report AI API token usage per operation
- **Measurement:** Count tokens for each AI call (extraction, generation, documentation)
- **Acceptance:** Report total tokens used, estimated cost (at OpenRouter rates)
- **Constraint:** Design prompts to minimize token usage while maintaining quality

**NFR-PERF-003: Large Report Handling** (P1)
- **Requirement:** Handle reports up to 100 pages / 100,000 words
- **Acceptance:** No crashes, graceful performance degradation, chunk processing if needed

### NFR-QUAL: Quality Gates

**NFR-QUAL-001: Syntax Validity** (P0)
- **Requirement:** 100% of generated rules pass syntax validation
- **Measurement:** Automated validation with sigma-cli, yara, suricata -T
- **Acceptance:** Zero syntax errors in generated rules

**NFR-QUAL-002: IOC Extraction Accuracy** (P0)
- **Requirement:** >95% recall, >90% precision on IOC extraction vs. ground truth
- **Measurement:** Benchmark against manually created ground truth files
- **Acceptance:** Achieve metrics on 10+ test reports

**NFR-QUAL-003: ATT&CK Mapping Accuracy** (P0)
- **Requirement:** >85% correct technique ID at subtechnique level vs. ground truth
- **Measurement:** Benchmark against manually created ground truth files
- **Acceptance:** Achieve metrics on 10+ test reports

**NFR-QUAL-004: TTP Extraction Recall** (P0)
- **Requirement:** >85% recall on TTP extraction vs. ground truth
- **Measurement:** Benchmark against manually created ground truth files
- **Acceptance:** Achieve metrics on 10+ test reports

**NFR-QUAL-005: True Positive Rate** (P1, v1.1)
- **Requirement:** >90% of generated rules match their corresponding attack logs
- **Measurement:** Test against EVTX-ATTACK-SAMPLES, OTRF Security Datasets
- **Acceptance:** Per-rule TP rate measured and reported

**NFR-QUAL-006: False Positive Rate** (P1, v1.1)
- **Requirement:** <5% aggregate FP rate, <0.1% for critical rules
- **Measurement:** Test against benign baseline (48hr VM recording)
- **Acceptance:** FP rate per rule and aggregate measured and reported

**NFR-QUAL-007: Documentation Completeness** (P0)
- **Requirement:** Every rule has documentation with FP analysis
- **Measurement:** Automated check: each rule file has corresponding documentation file
- **Acceptance:** 100% of rules have documentation

**NFR-QUAL-008: Coverage Transparency** (P0)
- **Requirement:** Every report's gap analysis identifies uncovered TTPs
- **Measurement:** Coverage report includes "gaps" section
- **Acceptance:** Gap analysis present in 100% of reports

**NFR-QUAL-009: Unit Test Coverage** (P0)
- **Requirement:** >80% code coverage
- **Measurement:** Vitest coverage report
- **Acceptance:** 80% line coverage, 70% branch coverage

### NFR-SEC: Security

**NFR-SEC-001: API Key Handling** (P0)
- **Requirement:** ANTHROPIC_API_KEY or OPENROUTER_API_KEY stored in .env only, never in code or commits
- **Acceptance:** .env.example provided, .gitignore includes .env, no API keys in repository history

**NFR-SEC-002: Input Validation** (P0)
- **Requirement:** Validate and sanitize all file inputs to prevent path traversal, command injection
- **Acceptance:** Input validation unit tests pass, no arbitrary file access

**NFR-SEC-003: No Malware in Repository** (P0)
- **Requirement:** No actual malware samples in Git repository
- **Acceptance:** Test data includes hashes and references only, not binaries. Malware samples downloaded on-demand for testing.

**NFR-SEC-004: Secure Dependencies** (P1)
- **Requirement:** Regularly update dependencies, no known high/critical vulnerabilities
- **Acceptance:** `npm audit` shows zero high/critical vulnerabilities, Dependabot enabled

### NFR-COST: Cost Management

**NFR-COST-001: AI Inference Provider** (P0)
- **Requirement:** Use OpenRouter for AI inference (cost-efficient model selection vs. direct Anthropic API)
- **Rationale:** OpenRouter provides access to multiple models with competitive pricing and single API key
- **Acceptance:** OpenRouter SDK integration, model selection configurable

**NFR-COST-002: Model Selection Strategy** (P0)
- **Requirement:** Use cheap models for extraction/classification, quality models for generation
- **Strategy:**
  - IOC extraction: Cheaper models (Haiku, Gemini Flash) - pattern matching task
  - TTP extraction: Mid-tier models (Sonnet 3.5, GPT-4o-mini) - reasoning task
  - Rule generation: Quality models (Opus, GPT-4o) - creative generation task
  - Documentation: Mid-tier models - explanation task
- **Acceptance:** Model selection configurable per operation type

**NFR-COST-003: Token Tracking** (P1)
- **Requirement:** Track API token usage per report and per operation type
- **Acceptance:** Summary report includes estimated cost, logging tracks token usage

**NFR-COST-004: Cost Target** (P1)
- **Target:** Process a typical report for <$0.50 in API costs (with cheap model defaults)
- **Measurement:** Actual cost reported in summary
- **Acceptance:** 90% of reports process within cost target

### NFR-MAINT: Maintainability

**NFR-MAINT-001: TypeScript Throughout** (P0)
- **Requirement:** All application code in TypeScript, Python only for validation tool subprocesses
- **Acceptance:** >95% of codebase is TypeScript (excluding config files)

**NFR-MAINT-002: Minimal Dependencies** (P0)
- **Requirement:** Minimize npm dependencies to reduce attack surface and maintenance burden
- **Acceptance:** Justify each dependency, prefer built-in Node.js APIs when feasible, <50 direct dependencies

**NFR-MAINT-003: Clean Architecture** (P0)
- **Requirement:** Modular architecture with clear separation of concerns
- **Structure:**
  - `src/cli/` - CLI entry points
  - `src/ingestion/` - Parsers and normalizers
  - `src/extraction/` - IOC and TTP extractors
  - `src/generation/` - Rule generators
  - `src/knowledge/` - ATT&CK data access
  - `src/testing/` - Testing framework (v1.1)
  - `src/reporting/` - Output formatters
  - `src/ai/` - AI client abstraction
  - `src/utils/` - Shared utilities
- **Acceptance:** Each module has clear interface, minimal coupling, unit testable

**NFR-MAINT-004: Code Quality** (P1)
- **Requirement:** Consistent code style, documented APIs, type safety
- **Acceptance:** ESLint + Prettier configured, TypeScript strict mode, TSDoc comments for public APIs

---

## 8. Technical Architecture

### 8.1 System Architecture (ASCII Diagram)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DetectForge CLI                                 │
│                    (Commander.js / yargs)                               │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                ┌────────────────┴────────────────┐
                │                                  │
       ┌────────▼─────────┐             ┌────────▼─────────┐
       │   Ingestion      │             │    Reporting     │
       │    Pipeline      │             │     Pipeline     │
       │                  │             │                  │
       │ PDF/HTML/MD/TXT  │             │ JSON/Markdown/   │
       │ → ThreatReport   │             │ SARIF/Navigator  │
       └────────┬─────────┘             └──────────────────┘
                │
       ┌────────▼─────────┐
       │   Extraction     │
       │    Pipeline      │
       │                  │
       │ IOC Extractor    │──┐
       │ TTP Extractor    │  │
       │ ATT&CK Mapper    │  │        ┌──────────────────┐
       └────────┬─────────┘  │        │  AI Inference    │
                │             └───────►│  (OpenRouter)    │
       ┌────────▼─────────┐           │                  │
       │   Generation     │           │ Model Selection: │
       │    Pipeline      │◄──────────┤ - Extraction     │
       │                  │           │ - Generation     │
       │ Sigma Generator  │           │ - Documentation  │
       │ YARA Generator   │           └──────────────────┘
       │ Suricata Gen.    │
       └────────┬─────────┘
                │
       ┌────────▼─────────┐           ┌──────────────────┐
       │   Validation     │           │ Knowledge Base   │
       │    Pipeline      │           │                  │
       │                  │◄──────────┤ MITRE ATT&CK     │
       │ Sigma Validator  │           │ (STIX 2.1 Data)  │
       │ YARA Validator   │           │                  │
       │ Suricata Valid.  │           │ Technique Lookup │
       └────────┬─────────┘           │ Tactic Mapping   │
                │                     │ Data Sources     │
       ┌────────▼─────────┐           └──────────────────┘
       │   Testing (v1.1) │
       │    Pipeline      │           ┌──────────────────┐
       │                  │           │  SigmaHQ Corpus  │
       │ TP Testing       │◄──────────┤  (Reference)     │
       │ FP Testing       │           │                  │
       │ Benchmarking     │           │ Human-written    │
       └────────┬─────────┘           │ Rules for A/B    │
                │                     └──────────────────┘
       ┌────────▼─────────┐
       │  Documentation   │
       │    Pipeline      │
       │                  │
       │ Per-Rule Docs    │
       │ FP Analysis      │
       │ Gap Analysis     │
       └──────────────────┘
```

### 8.2 Component Breakdown

| Component | Responsibilities | Key Technologies |
|-----------|-----------------|------------------|
| **CLI** | Command parsing, user interaction, progress display | Commander.js / yargs, chalk (colors) |
| **Ingestion** | Parse PDF/HTML/Markdown/text, normalize to ThreatReport | pdf-parse, cheerio, marked |
| **Extraction** | Extract IOCs (regex + AI), extract TTPs (AI), map to ATT&CK (AI + validation) | OpenRouter SDK, regex, defang library |
| **Generation** | Generate Sigma/YARA/Suricata rules with detection logic and metadata | OpenRouter SDK, YAML serialization, template engine |
| **Validation** | Syntax and semantic validation against specs | pySigma (subprocess), yara-python (subprocess), suricata (subprocess) |
| **Testing** | True positive testing, false positive testing, benchmarking (v1.1) | Chainsaw (subprocess), YARA binary, Suricata binary |
| **Reporting** | JSON, Markdown, SARIF, Navigator layer output | JSON serialization, markdown-it, SARIF schema |
| **Knowledge** | ATT&CK data access, SigmaHQ corpus, logsource mappings | STIX parser, JSON cache, TypeScript data structures |
| **AI Client** | OpenRouter API abstraction, prompt management, response parsing | openrouter-sdk or fetch, retry logic, token tracking |
| **Utils** | Defang/refang, hash validation, YAML parsing, logging | Built-in Node.js APIs, yaml package |

### 8.3 Data Flow

```
┌───────────────────┐
│ Threat Intel      │
│ Report (PDF/HTML) │
└─────────┬─────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. INGESTION                                                │
│    - Parse document format                                  │
│    - Extract text, preserve structure                       │
│    - Normalize to ThreatReport object                       │
│                                                             │
│    Output: ThreatReport { id, title, source, date,         │
│                           rawText, sections[], metadata }  │
└─────────┬───────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. EXTRACTION                                               │
│    - IOC extraction (regex + AI context)                    │
│      → IPs, domains, hashes, URLs, emails, paths, reg keys │
│    - TTP extraction (AI analysis)                           │
│      → Behavioral descriptions, tools, artifacts            │
│    - ATT&CK mapping (AI + validation)                       │
│      → Technique IDs, tactics, platforms                    │
│                                                             │
│    Output: ExtractionResult { iocs[], ttps[],              │
│                                attackTechniques[] }         │
└─────────┬───────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. GENERATION                                               │
│    - For each TTP with detection opportunity:               │
│      → Generate Sigma rule (host-based detection)           │
│      → Generate YARA rule (file-based detection)            │
│      → Generate Suricata rule (network detection)           │
│    - Each rule includes:                                    │
│      → Detection logic (fields, values, conditions)         │
│      → Metadata (author, date, references, ATT&CK tags)     │
│      → Documentation (description, FPs, gaps)               │
│                                                             │
│    Output: GeneratedRule[] { type, content, metadata,       │
│                               documentation }               │
└─────────┬───────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. VALIDATION                                               │
│    - Syntax validation:                                     │
│      → Sigma: pySigma / sigma-cli                           │
│      → YARA: yara-python / yara binary                      │
│      → Suricata: suricata -T                                │
│    - Semantic validation:                                   │
│      → Field names exist in logsource                       │
│      → ATT&CK IDs are valid                                 │
│      → Logic is not trivially true/false                    │
│                                                             │
│    Output: ValidationResult[] { ruleId, valid, errors[] }   │
└─────────┬───────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. TESTING (v1.1)                                           │
│    - True positive testing:                                 │
│      → Test against attack logs (EVTX-ATTACK-SAMPLES, etc.) │
│      → Measure TP rate per rule                             │
│    - False positive testing:                                │
│      → Test against benign baseline                         │
│      → Measure FP rate per rule                             │
│    - Benchmarking:                                          │
│      → Compare to SigmaHQ reference rules                   │
│      → Score quality across dimensions                      │
│                                                             │
│    Output: TestResult[] { ruleId, tpRate, fpRate, score }   │
└─────────┬───────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. REPORTING                                                │
│    - Write individual rule files (Sigma YAML, YARA, etc.)  │
│    - Generate per-rule documentation (Markdown)             │
│    - Generate summary report (Markdown + JSON)              │
│    - Generate ATT&CK Navigator layer (JSON) (v1.1)          │
│    - Generate SARIF output (JSON) (v1.1)                    │
│                                                             │
│    Output: Files written to output directory                │
└─────────────────────────────────────────────────────────────┘
```

### 8.4 Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Runtime** | Node.js 20+ | Mature, fast, excellent TypeScript support |
| **Language** | TypeScript 5+ | Type safety, maintainability, Adam's preference |
| **Package Manager** | bun | Fast, TypeScript-native, modern |
| **CLI Framework** | Commander.js | Standard, well-documented, flexible |
| **AI Inference** | OpenRouter SDK | Multi-model access, cost-efficient, single API |
| **ATT&CK Data** | STIX 2.1 JSON | Official MITRE format, machine-readable |
| **Sigma Validation** | pySigma (Python subprocess) | Official SigmaHQ tooling, validation + conversion |
| **YARA Validation** | yara-python (Python subprocess) | Standard YARA Python binding |
| **Suricata Validation** | Suricata binary (subprocess) | Official validation mode (suricata -T) |
| **Testing Framework** | Vitest | Fast, TypeScript-native, modern |
| **Linting/Formatting** | ESLint + Prettier | Code quality, consistent style |
| **Output Formats** | YAML, JSON, Markdown | Standard formats for rules and reports |
| **CI/CD** | GitHub Actions | Free for public repos, standard |

### 8.5 AI Inference Layer

**OpenRouter Integration:**

OpenRouter provides a unified API for multiple LLM providers, enabling:
- Cost optimization through model selection
- Fallback to alternative models if primary fails
- Single API key management
- Competitive pricing

**Model Selection Strategy:**

| Operation | Model Tier | Suggested Models | Rationale |
|-----------|-----------|-----------------|-----------|
| IOC Extraction | Cheap | Anthropic Claude Haiku, Google Gemini Flash | Pattern matching, high volume |
| TTP Extraction | Mid-Tier | Anthropic Claude Sonnet 3.5, OpenAI GPT-4o-mini | Reasoning required, moderate volume |
| Rule Generation | Quality | Anthropic Claude Opus, OpenAI GPT-4o | Creative generation, quality critical |
| Documentation | Mid-Tier | Anthropic Claude Sonnet 3.5 | Explanation, lower criticality |
| FP Analysis | Mid-Tier | Anthropic Claude Sonnet 3.5 | Reasoning, scenario generation |

**Prompt Engineering Approach:**

1. **Structured Prompts:** System prompt + user prompt with clear instructions, format specifications, and examples
2. **Few-Shot Examples:** Include 2-3 examples of desired output for complex tasks (TTP extraction, rule generation)
3. **JSON Output:** Request structured JSON responses for parsing (schema specified in prompt)
4. **Validation in Prompt:** Instruct model to self-validate (e.g., "Ensure all ATT&CK IDs are valid")
5. **Iterative Refinement:** If response is invalid, provide feedback and request correction (up to 2 retries)

**Response Parsing:**

- Expect JSON responses with defined schema
- Validate schema before processing (e.g., required fields present, types correct)
- Handle malformed responses gracefully (retry with clarification, fallback to default)
- Extract text from markdown code blocks if model wraps JSON in ```json```

**Cost Tracking:**

- Log token counts for each API call (prompt + completion)
- Aggregate by operation type (extraction, generation, documentation)
- Report total tokens and estimated cost in summary
- Store logs for analysis and optimization

**Upgrade Path:**

1. **Start Cheap:** Default to cheap models, measure quality
2. **Measure Quality:** Track accuracy metrics (IOC recall, ATT&CK mapping accuracy, rule validation pass rate)
3. **Upgrade Selectively:** If quality is insufficient, upgrade specific operation types to mid-tier or quality models
4. **User Configuration:** Allow users to override model selection per operation type

### 8.6 External Dependencies

| Dependency | Purpose | Integration Method | Fallback |
|-----------|---------|-------------------|----------|
| **OpenRouter API** | AI inference | HTTPS API (SDK or fetch) | Fail gracefully with error message |
| **MITRE ATT&CK STIX Data** | ATT&CK technique validation | Download JSON from GitHub, cache locally | Ship bundled snapshot, update periodically |
| **pySigma** | Sigma rule validation | Python subprocess | Custom TypeScript validator (limited) |
| **yara-python** | YARA rule validation | Python subprocess | YARA binary if available |
| **Suricata** | Suricata rule validation | Binary subprocess | Skip Suricata validation with warning |
| **SigmaHQ Repo** (v1.1) | Reference rules for benchmarking | Git clone or download | Skip benchmarking if unavailable |
| **EVTX Attack Samples** (v1.1) | True positive testing | Download from GitHub | Skip TP testing if unavailable |

---

## 9. AI Strategy

### 9.1 OpenRouter as Inference Provider

**Why OpenRouter:**
- **Cost Efficiency:** Access to cheaper models (Haiku, Gemini Flash) alongside quality models (Opus, GPT-4o)
- **Model Flexibility:** Switch between models without changing code
- **Single API Key:** Manage one API key instead of multiple (Anthropic, OpenAI, Google)
- **Fallback Support:** If primary model fails/rate-limited, fallback to alternative
- **Competitive Pricing:** Often cheaper than direct provider APIs due to bulk pricing

**Integration:**
- Use OpenRouter SDK or direct HTTPS API
- Configure model per operation type via environment variables or config file
- Default model selection based on cost/quality tradeoff

### 9.2 Model Tier Strategy

**Tier 1: Cheap Models (< $0.50 per million tokens)**
- **Use Cases:** IOC extraction (regex-heavy, pattern matching), classification tasks
- **Models:** Anthropic Claude Haiku, Google Gemini Flash, Meta Llama 3
- **Volume:** High (many API calls per report)
- **Quality Requirement:** Moderate (validation catches errors)

**Tier 2: Mid-Tier Models ($1-5 per million tokens)**
- **Use Cases:** TTP extraction (reasoning), documentation generation, FP analysis
- **Models:** Anthropic Claude Sonnet 3.5, OpenAI GPT-4o-mini, Google Gemini Pro
- **Volume:** Moderate (several calls per report)
- **Quality Requirement:** High (but validation provides safety net)

**Tier 3: Quality Models ($15-50 per million tokens)**
- **Use Cases:** Detection rule generation (creative, critical quality)
- **Models:** Anthropic Claude Opus, OpenAI GPT-4o
- **Volume:** Low (one call per TTP, typically 5-10 per report)
- **Quality Requirement:** Very high (output goes to production detection systems)

### 9.3 Prompt Engineering Approach

**Principles:**
1. **Be Specific:** Clear instructions, explicit format requirements, no ambiguity
2. **Provide Context:** Include relevant context from report, ATT&CK data, logsource schemas
3. **Use Examples:** Few-shot prompting with 2-3 examples for complex tasks
4. **Request Structure:** Always request JSON output with defined schema
5. **Instruct Validation:** Ask model to self-check (e.g., "Verify all field names are valid")
6. **Handle Errors:** If response is invalid, provide feedback and retry (up to 2 times)

**Example Prompt (TTP Extraction):**

```
System: You are a cybersecurity expert analyzing threat intelligence reports. Extract behavioral tactics, techniques, and procedures (TTPs) from the provided report.

User:
# Task
Extract all TTPs (behavioral patterns) from the following threat intelligence report. For each TTP, provide:
- description: Plain-English description of the adversary behavior
- tools: Tools or utilities used (e.g., "Mimikatz", "PowerShell")
- platforms: Target systems (e.g., "Windows", "Linux")
- artifacts: Files, registry keys, or other artifacts created
- detection_opportunities: How this behavior can be detected

# Input Report
[Report text here]

# Output Format
Respond with valid JSON matching this schema:
{
  "ttps": [
    {
      "description": "string",
      "tools": ["string"],
      "platforms": ["string"],
      "artifacts": ["string"],
      "detection_opportunities": ["string"]
    }
  ]
}

# Examples
[2-3 example TTP extractions from known reports]

# Instructions
- Focus on actionable behavioral patterns, not just tool names
- Be specific about what the adversary DID, not just what they COULD do
- Distinguish between adversary actions and defender recommendations
- If multiple campaigns or variants are described, extract TTPs for each
```

### 9.4 Response Parsing and Validation

**Parsing Strategy:**
1. **Extract JSON:** Look for JSON in response body (may be wrapped in ```json``` markdown)
2. **Validate Schema:** Use JSON Schema or TypeScript type guards to validate structure
3. **Required Fields:** Check all required fields are present and non-empty
4. **Type Validation:** Ensure types match (strings are strings, arrays are arrays)
5. **Value Validation:** Validate values (e.g., ATT&CK IDs match T####.### format)

**Error Handling:**
- **Schema Mismatch:** Retry with feedback: "Your response was missing required field X. Please provide complete output."
- **Invalid Values:** Retry with feedback: "ATT&CK ID 'T999999' is invalid. Please verify against the ATT&CK framework."
- **Malformed JSON:** Retry with feedback: "Response was not valid JSON. Please respond with properly formatted JSON."
- **Max Retries (2):** If still invalid after 2 retries, log error, skip this operation, continue processing

**Validation Before Use:**
- All extracted ATT&CK IDs validated against local ATT&CK data
- All IOCs validated with regex (IP format, domain format, hash length)
- All generated rules validated with syntax validators (pySigma, yara, suricata)

### 9.5 Cost Tracking

**What to Track:**
- Prompt tokens per API call
- Completion tokens per API call
- Model used per API call
- Operation type (extraction, generation, documentation)
- Timestamp

**Aggregation:**
- Total tokens per operation type
- Total tokens per report
- Estimated cost (tokens * model pricing)
- Average tokens per operation type (for optimization)

**Reporting:**
- Include in summary report: "API Tokens Used: ~12,400 (~$0.35 estimated cost)"
- Log to file for analysis: `logs/token-usage-YYYY-MM-DD.jsonl`

**Optimization:**
- Measure token usage by operation type
- If extraction uses too many tokens, refine prompts or use cheaper models
- If generation quality is insufficient, upgrade to better models despite cost
- Balance cost vs. quality based on metrics

### 9.6 Upgrade Path

**Phase 1: Start Cheap (v1.0 MVP)**
- IOC Extraction: Haiku
- TTP Extraction: Sonnet 3.5
- Rule Generation: Sonnet 3.5 (not Opus yet)
- Documentation: Haiku
- **Target Cost:** <$0.30 per report
- **Target Quality:** >80% accuracy metrics

**Phase 2: Measure (v1.0 post-launch)**
- Run benchmarks on 20+ test reports
- Measure IOC recall, TTP recall, ATT&CK mapping accuracy, rule validation pass rate
- Identify which operations are quality bottlenecks

**Phase 3: Upgrade Selectively (v1.1)**
- If rule generation quality is insufficient: Upgrade to Opus
- If TTP extraction is insufficient: Upgrade to GPT-4o
- Keep cheap models where quality is sufficient
- **Target Cost:** <$0.50 per report with quality upgrades
- **Target Quality:** >90% accuracy metrics

**Phase 4: User Configuration (v1.1)**
- Add config file: `detectforge.config.json`
- Allow model selection per operation type
- Allow cost vs. quality tradeoff preference (fast/cheap, balanced, quality)
- Power users can optimize for their priorities

---

## 10. Data Strategy

### 10.1 MITRE ATT&CK Data Pipeline

**Data Source:** https://github.com/mitre-attack/attack-stix-data (STIX 2.1 JSON bundles)

**Pipeline:**
1. **Download:** Fetch latest `enterprise-attack.json` from GitHub raw URL
2. **Parse:** Parse STIX 2.1 bundle, extract attack-pattern objects (techniques)
3. **Transform:** Build lookup maps:
   - `techniques: Map<string, Technique>` (key: T1059.001)
   - `techniquesByTactic: Map<string, Technique[]>` (key: execution)
   - `techniquesByPlatform: Map<string, Technique[]>` (key: windows)
   - `dataSources: Map<string, DataSource>` (key: DS0009)
4. **Cache:** Write to `src/knowledge/mitre-attack/data/attack-cache.json`
5. **Access:** TypeScript module provides functions: `getTechniqueById()`, `searchTechniques()`, `validateTechniqueId()`, `getTacticsByTechnique()`

**Refresh Strategy:**
- **Frequency:** Weekly automated refresh (GitHub Actions scheduled workflow)
- **On-Demand:** Script `scripts/download-attack-data.ts` for manual refresh
- **Bundled:** Ship v1.0 with bundled snapshot (Jan 2026 data), updates are optional
- **Versioning:** Track ATT&CK version (currently v14.x) in cache metadata

**Data Structure (TypeScript):**

```typescript
interface Technique {
  id: string;                      // T1059.001
  name: string;                    // PowerShell
  description: string;             // Full description
  tactics: string[];               // [execution]
  platforms: string[];             // [windows]
  dataSources: string[];           // [Process: Process Creation, Command: Command Execution]
  detectionRecommendations: string; // From ATT&CK
  isSubtechnique: boolean;         // true for T1059.001
  parentTechnique?: string;        // T1059 (if subtechnique)
  mitigations: string[];           // M1042, M1038
  url: string;                     // https://attack.mitre.org/techniques/T1059/001
}
```

### 10.2 SigmaHQ Reference Corpus (v1.1)

**Data Source:** https://github.com/SigmaHQ/sigma (community-maintained Sigma rules)

**Pipeline:**
1. **Clone:** Clone SigmaHQ repo or download via GitHub API
2. **Curate:** Select representative subset (200-500 rules):
   - Coverage: All major tactics (Initial Access → Impact)
   - Platforms: Windows (primary), Linux, Cloud (secondary)
   - Categories: process_creation, file_event, registry_event, network_connection, dns_query
   - Quality: Focus on `status: stable` or `status: test` (skip `experimental`)
3. **Parse:** Parse each rule YAML with pySigma
4. **Index:** Build index by technique ID, logsource category, rule quality
5. **Store:** Save to `data/sigmahq-rules/` with metadata JSON
6. **Access:** TypeScript module provides functions: `getReferenceRulesByTechnique()`, `compareRuleToReference()`

**Usage:**
- Benchmarking: Compare generated rules to SigmaHQ rules for same technique
- Quality Scoring: Score generated rules against SigmaHQ standards
- Learning: Analyze field usage, condition patterns, FP handling in reference rules

### 10.3 Threat Report Collection (v1.1)

**Data Source:** Public APT reports from CISA, Mandiant, CrowdStrike, Unit 42, The DFIR Report

**Pipeline:**
1. **Sources Registry:** Maintain `data/threat-reports/sources.json` with:
   - Source name, URL, RSS feed, report type, priority
2. **Collection:** Script downloads reports (PDF, HTML) from sources
   - Manual collection initially (10-20 high-quality reports)
   - Automated RSS monitoring (v1.1+)
3. **Format Conversion:** Convert to plain text and Markdown for easier testing
4. **Ground Truth Creation:** Manually create `ground-truth.json` for each report:
   - Known IOCs (verified against report text)
   - Known TTPs with ATT&CK IDs (verified)
   - Expected rule counts (Sigma, YARA, Suricata)
5. **Store:** Save to `data/threat-reports/` organized by source and date
6. **Usage:** Test oracle for measuring extraction and generation accuracy

**Ground Truth Schema:**

```json
{
  "report_id": "apt29-cozy-bear-2024-03",
  "source": "Mandiant",
  "url": "https://...",
  "threat_actor": "APT29 / Cozy Bear",
  "campaign": "SolarWinds follow-up",
  "date": "2024-03-15",
  "ground_truth": {
    "iocs": {
      "ipv4": ["192.0.2.1", "203.0.113.5"],
      "domains": ["malicious-domain.com", "c2-server.net"],
      "sha256": ["abc123..."],
      "urls": ["https://malicious-domain.com/payload"],
      "emails": ["phishing@evil.com"]
    },
    "ttps": [
      {
        "technique_id": "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Sent Word documents with embedded macros",
        "detection_types": ["sigma", "yara"]
      }
    ],
    "expected_rules": {
      "sigma": 5,
      "yara": 2,
      "suricata": 3
    }
  }
}
```

### 10.4 Test Data: Attack Logs (v1.1)

**Data Sources:**
- **EVTX-ATTACK-SAMPLES:** Pre-recorded Windows Event Logs from Atomic Red Team executions (https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- **OTRF Security Datasets:** JSON-formatted attack logs from MITRE CALDERA and other simulations (https://github.com/OTRF/Security-Datasets)
- **Hayabusa Sample EVTX:** Test EVTX files for Sigma rule testing (https://github.com/Yamato-Security/hayabusa-sample-evtx)

**Pipeline:**
1. **Download:** Git clone or download datasets
2. **Organize:** Organize by ATT&CK technique (T1059.001, T1003.001, etc.)
3. **Convert:** Convert EVTX to JSON for easier testing (using python-evtx)
4. **Index:** Map technique → log files for true positive testing
5. **Store:** Save to `test_data/attack_logs/` organized by technique

**Usage:**
- True Positive Testing: Test Sigma rules against logs for corresponding technique
- Coverage Verification: Ensure each technique has sample logs

### 10.5 Test Data: Benign Baselines (v1.1)

**Data Sources:**
- **Generated:** 48-hour recording of clean Windows 10/11 VM with Sysmon (normal user activity)
- **OTRF Benign Datasets:** Normal activity logs from OTRF project
- **CICIDS Benign Traffic:** Benign network traffic from CICIDS dataset

**Pipeline:**
1. **Generate:** Provision Windows VM, enable Sysmon, simulate normal user activity for 48 hours:
   - Web browsing (Chrome, Edge)
   - Office applications (Word, Excel, Outlook)
   - Software installation/updates
   - Legitimate PowerShell use (Get-Process, Get-Service)
   - File operations
2. **Export:** Export Windows Event Logs (Security, Sysmon)
3. **Convert:** Convert EVTX to JSON
4. **Store:** Save to `test_data/benign_logs/`

**Usage:**
- False Positive Testing: Test all rules against benign baseline to measure FP rate

### 10.6 Test Data: PCAPs (v1.1)

**Data Sources:**
- **Malware Traffic Analysis:** Real-world malware PCAPs (https://malware-traffic-analysis.net)
- **CICIDS 2017/2018:** Network intrusion detection dataset with labeled PCAPs
- **Stratosphere IPS:** Malware and botnet traffic captures
- **Generated:** Synthetic PCAPs using Scapy (for specific C2 patterns)

**Pipeline:**
1. **Download:** Download malicious and benign PCAPs
2. **Organize:** Organize by threat type (C2, exfiltration, recon, etc.)
3. **Store:** Save to `test_data/pcaps/malicious/` and `test_data/pcaps/benign/`

**Usage:**
- True Positive Testing: Test Suricata rules against malicious PCAPs
- False Positive Testing: Test Suricata rules against benign network traffic

### 10.7 Data Freshness and Update Strategy

| Dataset | Freshness Requirement | Update Frequency | Automation |
|---------|---------------------|-----------------|------------|
| ATT&CK STIX Data | Quarterly ATT&CK releases | Weekly check, download if updated | GitHub Actions scheduled workflow |
| SigmaHQ Corpus | Weekly rule updates | Weekly | GitHub Actions scheduled workflow (v1.1) |
| Threat Reports | New reports weekly | Manual collection initially, RSS automation (v1.1) | Manual initially, automated (v1.1) |
| Attack Logs | Stable (Atomic Red Team tests) | As needed (new techniques) | Manual |
| Benign Baselines | Re-generate yearly (OS updates) | Yearly | Manual |
| PCAPs | Stable | As needed (new threats) | Manual |

---

## 11. Quality & Testing Strategy

### 11.1 Test Pyramid

```
                    /\
                   /  \
                  / E2E \         E2E: Full pipeline tests
                 / Tests \        (5-10 tests)
                /----------\
               / Integration \    Integration: Component interaction tests
              /    Tests      \   (20-30 tests)
             /----------------\
            /    Unit Tests    \  Unit: Module-level tests
           /                    \ (100+ tests, >80% coverage)
          /______________________\
```

**Unit Tests (>80% code coverage):**
- IOC extraction: regex patterns, defanging/refanging, deduplication
- TTP extraction: AI response parsing, error handling
- ATT&CK mapping: technique ID validation, tactic assignment
- Rule generation: YAML serialization, metadata construction, detection logic formatting
- Validation: syntax checking, field name validation
- Utils: defang/refang, hash validation, network parsing

**Integration Tests (component interaction):**
- Ingestion → Extraction: Parse report → extract IOCs/TTPs
- Extraction → Generation: TTPs → Sigma/YARA/Suricata rules
- Generation → Validation: Rules → syntax check → pass/fail
- Extraction → ATT&CK: TTP → ATT&CK ID → technique details

**End-to-End Tests (full pipeline):**
- Real APT report → full processing → validated rules (5-10 test reports)
- Measure: rules generated, validation pass rate, processing time, API token usage

### 11.2 Quality Gates (from Master Prompt)

All 14 quality gates must pass before v1.0 release:

| Gate | Criteria | Measurement | Priority |
|------|----------|-------------|----------|
| 1. Sigma Syntax Validity | 100% pass YAML + schema validation | sigma-cli check | P0 |
| 2. YARA Syntax Validity | 100% pass compilation | yara -C | P0 |
| 3. Suricata Syntax Validity | 100% pass syntax check | suricata -T | P0 |
| 4. IOC Extraction | >95% recall, >90% precision vs. ground truth | Benchmark vs. 10+ reports | P0 |
| 5. TTP Extraction | >85% recall, >80% precision vs. ground truth | Benchmark vs. 10+ reports | P0 |
| 6. ATT&CK Mapping | >85% correct technique ID (subtechnique level) | Benchmark vs. ground truth | P0 |
| 7. True Positive Rate | >90% of rules match attack logs (v1.1) | Sigma tester vs. EVTX | P1 |
| 8. False Positive Rate | <5% aggregate, <0.1% for critical rules (v1.1) | FP tester vs. benign baseline | P1 |
| 9. Documentation | Every rule has documentation with FP analysis | Automated check | P0 |
| 10. Coverage Transparency | Every report has gap analysis | Automated check | P0 |
| 11. End-to-End | Full pipeline processes 5 real reports without errors | Integration test | P0 |
| 12. Unit Test Coverage | >80% code coverage | Vitest coverage report | P0 |
| 13. CI/CD | All tests pass on GitHub Actions | Green CI badge | P0 |
| 14. README | Explains problem, shows benchmarks, documents limitations | Human review | P0 |

### 11.3 Benchmarking Against Human-Written Rules (v1.1)

**SigmaHQ Comparison:**
- For techniques with existing SigmaHQ rules, compare:
  - Detection logic breadth (coverage of technique variants)
  - Field usage (correct field names, appropriate modifiers)
  - False positive handling (filter conditions)
  - Documentation quality (description, FPs, references)
- Score on 1-10 scale per dimension
- Aggregate: DetectForge avg vs. SigmaHQ avg
- Publish results as table in `docs/BENCHMARKS.md`

**Example Benchmark Result:**

| Technique | Dimension | DetectForge Score | SigmaHQ Avg | Winner |
|-----------|----------|------------------|------------|--------|
| T1059.001 | Detection Breadth | 7/10 | 8/10 | SigmaHQ |
| T1059.001 | Field Usage | 9/10 | 9/10 | Tie |
| T1059.001 | FP Handling | 6/10 | 9/10 | SigmaHQ |
| T1059.001 | Documentation | 8/10 | 7/10 | DetectForge |
| T1059.001 | **Overall** | **7.5/10** | **8.25/10** | **SigmaHQ** |

**Honest Reporting:**
- Publish both wins and losses
- Document specific gaps (e.g., "DetectForge rules miss variant X that SigmaHQ catches")
- Use findings to improve prompts and generation logic

### 11.4 Honest Metrics Publishing

**Philosophy:**
DetectForge is a portfolio project. Demonstrating engineering rigor means publishing honest metrics, including failures. Hiring managers are more impressed by transparent reporting of limitations than by inflated success claims.

**What to Publish (in `docs/BENCHMARKS.md`):**
1. **Extraction Accuracy:**
   - IOC extraction recall/precision per report (table)
   - TTP extraction recall/precision per report (table)
   - ATT&CK mapping accuracy per report (table)
   - Overall averages + standard deviation

2. **Rule Quality:**
   - Syntax validation pass rate (should be 100%)
   - Rules generated per report (Sigma, YARA, Suricata)
   - Validation failures (if any, with explanations)

3. **Testing Results (v1.1):**
   - True positive rate per rule (histogram)
   - False positive rate per rule (histogram)
   - Aggregate TP/FP rates
   - Rules that fail TP testing (with explanations)

4. **Benchmarking (v1.1):**
   - DetectForge vs. SigmaHQ comparison table
   - Dimension-by-dimension scores
   - Specific gaps and weaknesses identified

5. **Performance:**
   - Processing time per report (histogram)
   - API token usage per report (histogram)
   - Estimated cost per report

6. **Failures:**
   - Reports that DetectForge couldn't process (with reasons)
   - Techniques that DetectForge struggles with (with explanations)
   - Known limitations and edge cases

**Example Failure Documentation:**

> **Known Limitation: Memory-Only Techniques**
>
> DetectForge currently struggles to generate high-quality detection rules for memory-only execution techniques (e.g., T1055 Process Injection, T1620 Reflective Code Loading). These techniques leave minimal forensic artifacts in standard log sources (Sysmon, Windows Security).
>
> **Impact:** For reports focused on these techniques, DetectForge generates fewer rules (avg 2 rules vs. 5 for file/process-based techniques).
>
> **Mitigation:** Future versions will incorporate EDR-specific log sources (memory access events, DLL injection alerts) to improve coverage.

---

## 12. Success Metrics

### 12.1 Quantitative Metrics

**Processing Speed:**
- **Target:** Process typical report (20-50 pages, 5-10 TTPs) in <3 minutes (stretch: <2 minutes)
- **Measurement:** Elapsed time from command start to completion
- **Baseline:** Manual process takes 6-14 hours
- **Success:** 100x speedup (6 hours → 3 minutes)

**Extraction Accuracy:**
- **IOC Extraction Recall:** >95% (capture 95%+ of all IOCs in report)
- **IOC Extraction Precision:** >90% (90%+ of extracted IOCs are valid)
- **TTP Extraction Recall:** >85% (capture 85%+ of actionable TTPs)
- **ATT&CK Mapping Accuracy:** >85% (correct technique ID at subtechnique level)

**Rule Quality:**
- **Syntax Validity:** 100% (all generated rules pass syntax validation)
- **True Positive Rate:** >90% per rule (v1.1)
- **False Positive Rate:** <5% aggregate, <0.1% for critical rules (v1.1)
- **Documentation Completeness:** 100% (every rule has documentation)

**Test Coverage:**
- **Unit Test Coverage:** >80% line coverage, >70% branch coverage
- **Integration Tests:** 20+ tests covering key component interactions
- **End-to-End Tests:** 5-10 real reports processed successfully

**Cost Efficiency:**
- **API Cost per Report:** <$0.50 (with cheap model defaults)
- **Token Usage:** Track and optimize (target <50k tokens per report)

### 12.2 Qualitative Metrics

**Rule Quality vs. SigmaHQ:**
- Benchmark generated rules against human-written SigmaHQ rules
- Target: Average score >7/10 across dimensions (detection breadth, field usage, FP handling, documentation)
- Identify specific gaps and iterate to improve

**Documentation Completeness:**
- Every rule has:
  - Clear "What This Detects" section
  - Technical "How It Works" section
  - 3-5 specific false positive scenarios
  - Coverage gaps documented
  - Tuning recommendations

**Coverage Transparency:**
- Every report has gap analysis identifying:
  - TTPs that couldn't be turned into rules (and why)
  - Evasions the rules don't catch
  - Required log sources that may not be available

### 12.3 Portfolio Metrics

**GitHub Engagement:**
- **Stars:** Target >100 stars within 3 months of launch (demonstrates value to security community)
- **Forks:** Target >20 forks (indicates adoption)
- **Issues/PRs:** Active engagement (questions, feature requests, contributions)

**README Quality:**
- Problem-first framing (explain the pain before the solution)
- Quick start (working example in <5 minutes)
- Architecture diagram (visual understanding)
- Honest benchmarks (publish real metrics)
- Clear limitations (transparent about what DetectForge doesn't do)

**Demo Effectiveness:**
- GIF or video showing DetectForge processing a real report
- Before/after comparison (14 hours → 3 minutes)
- Output quality (show generated Sigma rule, documentation)

**Technical Writing:**
- Comprehensive documentation (README, architecture, testing strategy, benchmarks)
- Blog post or case study demonstrating the project (LinkedIn, personal site)
- Conference talk potential (BSides, DEFCON Demo Labs)

---

## 13. Risks & Mitigations

### 13.1 AI Hallucination

**Risk:** AI generates plausible-looking but incorrect IOCs, ATT&CK IDs, or detection rules.

**Likelihood:** High (LLMs hallucinate regularly)

**Impact:** Medium (invalid rules fail validation, but incorrect IOCs/TTPs may pass)

**Mitigations:**
1. **Validation Layer:** Every ATT&CK ID validated against local ATT&CK data. Invalid IDs rejected.
2. **Syntax Validation:** Every generated rule validated with official tooling (pySigma, yara, suricata).
3. **Semantic Validation:** Field names validated against logsource schemas.
4. **Testing (v1.1):** Rules tested against attack logs (catch false negatives) and benign logs (catch false positives).
5. **Human Review:** Users expected to review rules before production deployment (DetectForge outputs rules for review, not auto-deployment).

**Residual Risk:** AI may extract non-existent IOCs or misinterpret TTPs. User review is critical.

### 13.2 Overly Broad Detection Rules

**Risk:** Generated rules are too generic, match benign activity, cause alert fatigue.

**Likelihood:** Medium (AI may generate broad rules if not instructed properly)

**Impact:** High (false positives erode trust in detection platform)

**Mitigations:**
1. **Prompt Engineering:** Instruct AI to include specific indicators, not just tool names (e.g., not just "powershell.exe", but "powershell.exe -enc").
2. **False Positive Analysis:** AI generates expected FP scenarios, documented per rule.
3. **False Positive Testing (v1.1):** Automated testing against benign baseline, measure FP rate, reject rules above threshold.
4. **Filter Conditions:** Prompt AI to include filter conditions for known legitimate use cases.
5. **Experimental Status:** All generated rules start with `status: experimental`, require tuning before promotion to `test` or `stable`.

**Residual Risk:** Some rules may still generate FPs. User tuning expected.

### 13.3 API Cost Overruns

**Risk:** AI API costs are higher than expected, making DetectForge expensive to run.

**Likelihood:** Medium (complex reports or verbose prompts increase token usage)

**Impact:** Medium (cost may deter adoption)

**Mitigations:**
1. **Cheap Models:** Default to cheap models (Haiku, Gemini Flash) for extraction tasks.
2. **Token Tracking:** Log token usage per operation, report in summary, analyze for optimization.
3. **Prompt Optimization:** Refine prompts to minimize verbosity while maintaining quality.
4. **Cost Target:** Set target <$0.50 per report, measure actual cost, adjust model selection if needed.
5. **User Configuration:** Allow users to choose cost vs. quality tradeoff (fast/cheap, balanced, quality).

**Residual Risk:** Very long reports (100+ pages) may exceed cost target.

### 13.4 Stale ATT&CK Data

**Risk:** Local ATT&CK data becomes outdated as MITRE releases new versions.

**Likelihood:** Low (MITRE releases quarterly, but changes are incremental)

**Impact:** Low (new techniques not recognized, but existing techniques still work)

**Mitigations:**
1. **Automated Refresh:** GitHub Actions workflow checks for ATT&CK updates weekly, downloads if available.
2. **Version Tracking:** Log ATT&CK version in cache metadata, report in summary.
3. **Manual Refresh:** Script allows on-demand refresh (`bun run scripts/download-attack-data.ts`).
4. **Bundled Snapshot:** Ship v1.0 with current ATT&CK snapshot, updates are optional.

**Residual Risk:** Users who never update may miss new techniques, but tool remains functional.

### 13.5 Report Format Variations

**Risk:** Threat reports have wildly varying formats (PDF layouts, HTML structures), parser fails.

**Likelihood:** Medium (vendor reports are relatively consistent, but edge cases exist)

**Impact:** Medium (tool fails for unsupported formats)

**Mitigations:**
1. **Robust Parsing:** Test parsers against diverse report formats (Mandiant, CrowdStrike, CISA, Unit 42, The DFIR Report).
2. **Graceful Degradation:** If structured parsing fails, fall back to raw text extraction.
3. **Error Messages:** Clear error messages when parsing fails, suggest alternative input format.
4. **Manual Conversion:** Users can convert to plain text/Markdown manually if needed.

**Residual Risk:** Exotic formats may fail. Recommend plain text/Markdown for unsupported sources.

### 13.6 Dependency Vulnerabilities

**Risk:** npm dependencies have security vulnerabilities.

**Likelihood:** Medium (JavaScript ecosystem has frequent CVEs)

**Impact:** Medium (potential security issues in DetectForge itself)

**Mitigations:**
1. **Minimal Dependencies:** Keep dependency count <50 direct dependencies, justify each.
2. **Automated Scanning:** Dependabot enabled, `npm audit` in CI.
3. **Regular Updates:** Update dependencies monthly or when security alerts appear.
4. **Lock Files:** Use package-lock.json / bun.lockb to ensure reproducible builds.

**Residual Risk:** Zero-day vulnerabilities may exist before patches available.

### 13.7 User Misuse

**Risk:** Users deploy generated rules to production without review, causing operational issues.

**Likelihood:** Low (detection engineers are trained to review rules)

**Impact:** High (false positives in production SOC)

**Mitigations:**
1. **Documentation:** Prominent warnings in README and CLI output: "Review all rules before production deployment."
2. **Experimental Status:** All generated rules have `status: experimental`, indicating they require tuning.
3. **False Positive Documentation:** Every rule includes expected FP scenarios, reminding users to tune.
4. **No Auto-Deployment:** DetectForge outputs rules to files, does not deploy to SIEMs automatically.

**Residual Risk:** Inexperienced users may not review properly. This is a training issue, not a tool issue.

---

## 14. Release Plan

### 14.1 v0.1 (Proof of Concept) - Week 4

**Goal:** Validate core concepts with minimal functionality.

**Features:**
- PDF/HTML ingestion (basic parsing)
- IOC extraction (regex-based, no AI)
- Basic Sigma rule generation (template-based, no AI)
- No validation, no testing, no documentation

**Deliverable:** Working demo that takes a PDF report and outputs a Sigma rule.

**Success Criteria:** End-to-end flow works, generates syntactically valid Sigma rule.

### 14.2 v0.5 (MVP Alpha) - Week 8

**Goal:** Complete core pipeline with AI integration.

**Features:**
- FR-ING: PDF, HTML, Markdown, plain text ingestion
- FR-EXT: IOC extraction (regex + AI context), TTP extraction (AI), ATT&CK mapping (AI + validation)
- FR-GEN: Sigma, YARA, Suricata rule generation (AI-powered)
- FR-VAL: Syntax validation (pySigma, yara, suricata)
- FR-DOC: Per-rule documentation (basic)
- FR-CLI: Generate command with progress indicators
- FR-RPT: JSON + Markdown output

**Not Included:**
- Testing (TP/FP/benchmarking)
- Coverage analysis
- Advanced documentation (FP analysis, gap analysis)
- Data pipelines (ATT&CK download, SigmaHQ corpus)

**Deliverable:** Functional tool that processes real reports and generates validated rules.

**Success Criteria:**
- Process 5 real APT reports end-to-end
- All generated rules pass syntax validation
- Processing time <5 minutes per report
- API cost <$1 per report

### 14.3 v1.0 (MVP) - Week 12

**Goal:** Production-ready MVP with quality gates and documentation.

**Features:**
- All v0.5 features (refined)
- FR-DAT: ATT&CK data pipeline (download + parsing)
- FR-DOC: Advanced documentation (FP analysis, gap analysis)
- FR-CLI: All core commands (generate, extract, validate)
- FR-RPT: Complete reporting (JSON, Markdown, individual rule files)
- NFR-QUAL: All quality gates implemented and passing
- Tests: Unit tests (>80% coverage), integration tests, E2E tests
- CI/CD: GitHub Actions pipeline with automated testing
- Documentation: README, architecture docs, testing strategy

**Not Included (deferred to v1.1):**
- True positive testing (against attack logs)
- False positive testing (against benign baseline)
- Benchmarking (vs. SigmaHQ)
- SARIF output
- ATT&CK Navigator layer generation
- Threat report collection pipeline
- SigmaHQ corpus download

**Deliverable:** Public GitHub release, production-ready for use.

**Success Criteria:**
- All 14 quality gates pass
- Process 10 real APT reports successfully
- All generated rules pass syntax validation
- IOC extraction: >95% recall, >90% precision
- ATT&CK mapping: >85% accuracy
- Unit test coverage: >80%
- README: Problem-first, architecture diagram, honest limitations
- API cost: <$0.50 per report (with cheap models)
- Processing time: <3 minutes per report

### 14.4 v1.1 (Testing & Benchmarking) - Week 16

**Goal:** Add automated testing and benchmarking capabilities.

**Features:**
- FR-TST: Synthetic log generation
- FR-TST: True positive testing (against EVTX-ATTACK-SAMPLES, OTRF)
- FR-TST: False positive testing (against benign baseline)
- FR-TST: Benchmarking vs. SigmaHQ corpus
- FR-DAT: SigmaHQ corpus download and indexing
- FR-DAT: Threat report collection pipeline
- FR-RPT: SARIF output
- FR-RPT: ATT&CK Navigator layer generation
- FR-CLI: Benchmark and coverage commands
- Documentation: Benchmark results published in `docs/BENCHMARKS.md`

**Deliverable:** Enhanced release with automated testing and honest metrics.

**Success Criteria:**
- TP testing: >90% rules match attack logs
- FP testing: <5% aggregate FP rate
- Benchmarking: Average score >7/10 vs. SigmaHQ
- Benchmark results published (successes and failures)
- Coverage: ATT&CK Navigator layers generated

### 14.5 v1.2+ (Future Enhancements) - Week 20+

**Potential Features (prioritized based on user feedback):**
- Cloud detection rules (AWS CloudTrail, Azure, GCP)
- Linux/macOS detection rules
- Advanced Sigma features (aggregation, timeframes)
- Sigma-to-SIEM conversion (SPL, KQL, Lucene via pySigma)
- STIX JSON ingestion
- URL ingestion (download + parse)
- RSS feed monitoring
- Atomic Red Team integration (generate logs on-demand)
- Enhanced AI features (confidence scoring, rule quality prediction)
- Web UI (optional, CLI remains primary)
- Multi-language support (currently English-only)

---

## 15. Constraints

### 15.1 Technical Constraints

**TypeScript Throughout:**
- All application code must be TypeScript (not JavaScript).
- Python only for validation tool subprocesses (pySigma, yara-python) if no TypeScript alternative exists.
- Rationale: Type safety, maintainability, consistency, Adam's preference.

**bun as Package Manager:**
- Use bun for package management and script execution.
- Rationale: Faster than npm/yarn, TypeScript-native, modern.

**OpenRouter for AI Inference:**
- Do not use Anthropic SDK directly. Use OpenRouter for multi-model access and cost efficiency.
- Rationale: Cost optimization, model flexibility, single API key.

**CLI-First, No Web UI in v1:**
- DetectForge v1.x is CLI-only. No web UI, no GUI.
- Rationale: Detection engineers live in terminals. CLI is faster to build and test. Web UI is v2+ feature.

**All Test Data from Public Sources:**
- No proprietary threat intel feeds, no commercial datasets.
- Use CISA, Mandiant/CrowdStrike/Unit 42 public reports, EVTX-ATTACK-SAMPLES, OTRF Security Datasets, MalwareBazaar, etc.
- Rationale: Open-source project, accessible to all users.

**No Actual Malware in Repository:**
- Do not commit malware binaries or samples to Git.
- Use hashes and references only. Download samples on-demand for testing (MalwareBazaar API).
- Rationale: Security, repository size, GitHub ToS.

**Honest Benchmarks:**
- Publish real metrics, including failures and limitations.
- Do not cherry-pick success cases or inflate numbers.
- Rationale: Portfolio project credibility, engineering integrity.

**Minimize Dependencies:**
- Keep npm dependency count <50 direct dependencies.
- Prefer Node.js built-in APIs when feasible (fs, path, crypto, etc.).
- Justify each dependency (document rationale in `docs/ARCHITECTURE.md`).
- Rationale: Security (smaller attack surface), maintainability (fewer breaking changes).

### 15.2 Operational Constraints

**API Key Management:**
- ANTHROPIC_API_KEY or OPENROUTER_API_KEY stored in `.env` only.
- Never commit API keys to repository (enforce with .gitignore and pre-commit hooks).
- Provide `.env.example` template.
- Rationale: Security, credential management best practices.

**Processing Time:**
- Target <3 minutes per report. If processing takes >5 minutes, investigate and optimize.
- Rationale: User experience, cost efficiency (longer processing = more API calls).

**API Cost:**
- Target <$0.50 per report with cheap model defaults.
- Track actual cost, report in summary, optimize if exceeds target.
- Rationale: Cost efficiency, user adoption (expensive tools won't be used).

**Offline Operation:**
- DetectForge should work with cached ATT&CK data if internet is unavailable (after initial download).
- AI inference requires internet (OpenRouter API), but data access should be local.
- Rationale: Usability in restricted environments, reliability.

### 15.3 Quality Constraints

**Syntax Validity:**
- 100% of generated rules must pass syntax validation. Zero tolerance for syntax errors.
- Rationale: Invalid rules are useless, validation is automatable.

**Documentation Completeness:**
- 100% of generated rules must have documentation (per-rule Markdown file).
- Rationale: Undocumented rules are hard to use and tune.

**Unit Test Coverage:**
- Minimum 80% code coverage (line coverage). Target 85%+.
- Rationale: Reliability, maintainability, confidence in changes.

**Accuracy Thresholds:**
- IOC extraction: >95% recall (detect 95%+ of IOCs in report).
- ATT&CK mapping: >85% accuracy (correct technique ID at subtechnique level).
- Rationale: Tool must be accurate to be useful. Set high but achievable thresholds.

### 15.4 Scope Constraints

**v1.0 Excludes:**
- Web UI
- Real-time threat feed integration
- Automated SIEM deployment
- Machine learning model training
- Commercial/paid threat intel platforms
- Live attack simulation
- Multi-tenancy / SaaS deployment

**v1.0 Platform Support:**
- Windows detection rules: Yes (primary focus)
- Linux detection rules: Limited (basic Sigma support, defer advanced to v1.1+)
- macOS detection rules: Limited (basic Sigma support, defer to v1.1+)
- Cloud detection rules: No (defer to v1.1+)
- Network detection rules: Yes (Suricata)
- File detection rules: Yes (YARA)

**v1.0 Language Support:**
- English-only (threat reports, documentation, CLI output)
- Rationale: Simplify MVP, most threat intel is in English. Multi-language is v2+ feature.

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **ATT&CK** | MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) - A knowledge base of adversary tactics and techniques based on real-world observations. |
| **Detection Rule** | A structured query or pattern that identifies malicious activity in logs, files, or network traffic. |
| **False Positive (FP)** | A detection alert triggered by benign activity (incorrectly flagged as malicious). |
| **True Positive (TP)** | A detection alert correctly identifying malicious activity. |
| **IOC** | Indicator of Compromise - Observable artifact of an intrusion (IP, domain, hash, etc.). |
| **TTP** | Tactics, Techniques, and Procedures - Adversary behavior patterns. |
| **Sigma** | Generic SIEM detection rule format (YAML-based, platform-agnostic). |
| **YARA** | Pattern-matching tool for identifying and classifying malware samples. |
| **Suricata** | Open-source network IDS/IPS engine. |
| **pySigma** | Official Python library for Sigma rule parsing, validation, and conversion. |
| **OpenRouter** | API gateway providing access to multiple LLM providers (Anthropic, OpenAI, Google, etc.) with a single API key. |
| **STIX** | Structured Threat Information Expression - A standardized language for describing cyber threat intelligence. |
| **Logsource** | In Sigma, the specification of where log events come from (e.g., Windows Security Event Log, Sysmon). |
| **Subtechnique** | In ATT&CK, a specific implementation of a technique (e.g., T1059.001 PowerShell is a subtechnique of T1059 Command and Scripting Interpreter). |
| **Ground Truth** | Manually verified correct answers used as a test oracle for measuring accuracy. |
| **Defanging** | Modifying IOCs to prevent accidental clicks/execution (e.g., `evil[.]com` instead of `evil.com`). |
| **Coverage Gap** | A threat behavior that is not detected by any generated rule. |

---

## Appendix B: Reference Documents

1. **MASTER_PROMPT.md** - Complete build specification, architecture, phases, quality gates
2. **DetectForge_Technical_Reference.md** - Detailed specs for Sigma, YARA, Suricata, ATT&CK, pySigma, threat intel sources
3. **DetectForge_Testing_Strategy.md** - Comprehensive testing approach, datasets, benchmarking methodology

---

## Appendix C: Key URLs

| Resource | URL |
|----------|-----|
| **Sigma Specification** | https://github.com/SigmaHQ/sigma-specification |
| **SigmaHQ Rules** | https://github.com/SigmaHQ/sigma |
| **pySigma** | https://github.com/SigmaHQ/pySigma |
| **YARA** | https://github.com/VirusTotal/yara |
| **Suricata** | https://suricata.io/ |
| **MITRE ATT&CK** | https://attack.mitre.org/ |
| **ATT&CK STIX Data** | https://github.com/mitre-attack/attack-stix-data |
| **OpenRouter** | https://openrouter.ai/ |
| **CISA Advisories** | https://www.cisa.gov/news-events/cybersecurity-advisories |
| **EVTX-ATTACK-SAMPLES** | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| **OTRF Security Datasets** | https://github.com/OTRF/Security-Datasets |
| **MalwareBazaar** | https://bazaar.abuse.ch/ |
| **The DFIR Report** | https://thedfirreport.com/ |
| **Atomic Red Team** | https://github.com/redcanaryco/atomic-red-team |

---

**END OF PRODUCT REQUIREMENTS DOCUMENT**

This PRD serves as the definitive specification for DetectForge v1.0. All implementation decisions should reference this document. Updates to requirements must be reflected here with version tracking.
