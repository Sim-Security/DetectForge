# DetectForge — Master Build Prompt

## PROJECT IDENTITY

**Name:** DetectForge
**Tagline:** AI-Powered Detection Rule Generation from Threat Intelligence Reports
**Repo:** `detectforge`
**Author:** Adam (ranomis)
**License:** MIT

---

## THE PROBLEM (This Goes in the README First)

Security operations teams receive dozens of threat intelligence reports weekly — from Mandiant, CrowdStrike, Unit 42, CISA, and others. Each report describes adversary TTPs (Tactics, Techniques, and Procedures), indicators of compromise, and behavioral patterns. To actually DEFEND against these threats, detection engineers must manually:

1. Read the full report (30-60 min)
2. Extract IOCs (IPs, domains, hashes, URLs) (15-30 min)
3. Identify behavioral TTPs and map them to MITRE ATT&CK (30-60 min)
4. Write detection rules — Sigma for SIEM, YARA for file analysis, Suricata for network (2-8 hours per technique)
5. Document each rule: what it detects, expected false positives, coverage gaps (1-2 hours)
6. Validate rules against the specification (30 min)
7. Test against sample data (1-2 hours)

**Total: 6-14 hours of skilled labor per report.** Most SOC teams have a backlog of 50-100 reports they've never operationalized. DetectForge reduces this to minutes.

**What makes this different from existing tools:**
- **Uncoder.io / SOC Prime:** Convert between rule formats but don't GENERATE rules from threat intel
- **ChatGPT/Claude raw prompting:** Generates plausible-looking rules but with no validation, no false positive analysis, no ATT&CK mapping, no benchmarking against known-good rules
- **DetectForge:** Full pipeline from report ingestion through validated, documented, tested detection rules with honest accuracy metrics

---

## TECH STACK

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Runtime** | Node.js + TypeScript | Adam's preferred stack, strong CLI tooling ecosystem |
| **Package Manager** | bun | Fast, TypeScript-native |
| **CLI Framework** | Commander.js or yargs | Standard, well-documented |
| **AI Inference** | Claude API (via Anthropic SDK) | Best reasoning for complex extraction + generation tasks |
| **MITRE ATT&CK Data** | STIX 2.1 JSON bundles from GitHub | Official machine-readable format |
| **Sigma Validation** | pySigma (Python subprocess) OR custom TS validator | pySigma is the standard; fallback to custom if we want pure TS |
| **YARA Validation** | yara-python (Python subprocess) OR YARA binary | Standard tooling |
| **Suricata Validation** | suricata --engine-analysis | Official validation mode |
| **Testing** | Vitest | Fast, TS-native test runner |
| **Output Formats** | YAML (Sigma), YARA text, Suricata text, JSON, Markdown |
| **CI/CD** | GitHub Actions | Standard, free for public repos |

---

## ARCHITECTURE

```
detectforge/
├── src/
│   ├── cli/                          # CLI entry points and command definitions
│   │   ├── index.ts                  # Main CLI entry point
│   │   ├── commands/
│   │   │   ├── generate.ts           # Main command: report → rules
│   │   │   ├── validate.ts           # Validate existing rules
│   │   │   ├── benchmark.ts          # Benchmark against SigmaHQ
│   │   │   ├── extract.ts            # Extract IOCs/TTPs only (no rule gen)
│   │   │   └── coverage.ts           # ATT&CK coverage analysis
│   │   └── options.ts                # Shared CLI options
│   │
│   ├── ingestion/                    # Threat report ingestion pipeline
│   │   ├── parsers/
│   │   │   ├── pdf.ts                # PDF report parser
│   │   │   ├── html.ts               # HTML report parser (web-scraped reports)
│   │   │   ├── markdown.ts           # Markdown report parser
│   │   │   ├── plaintext.ts          # Plain text parser
│   │   │   ├── stix.ts               # STIX/TAXII bundle parser
│   │   │   └── json.ts               # Structured JSON intel parser
│   │   ├── normalizer.ts             # Normalize all formats to internal representation
│   │   └── types.ts                  # ThreatReport, IOC, TTP type definitions
│   │
│   ├── extraction/                   # IOC and TTP extraction engine
│   │   ├── ioc-extractor.ts          # Extract IPs, domains, hashes, URLs, emails
│   │   ├── ttp-extractor.ts          # Extract behavioral TTPs using AI
│   │   ├── attack-mapper.ts          # Map extracted TTPs to MITRE ATT&CK technique IDs
│   │   ├── ioc-enrichment.ts         # Enrich IOCs (defang, classify, deduplicate)
│   │   └── types.ts                  # ExtractionResult types
│   │
│   ├── generation/                   # Detection rule generation engine
│   │   ├── sigma/
│   │   │   ├── generator.ts          # Generate Sigma rules from extraction results
│   │   │   ├── templates.ts          # Sigma rule templates by logsource category
│   │   │   ├── validator.ts          # Validate generated Sigma YAML
│   │   │   └── converter.ts          # Convert Sigma to SPL/KQL/Lucene (stretch goal)
│   │   ├── yara/
│   │   │   ├── generator.ts          # Generate YARA rules from extraction results
│   │   │   ├── templates.ts          # YARA rule templates by file type
│   │   │   └── validator.ts          # Validate generated YARA rules
│   │   ├── suricata/
│   │   │   ├── generator.ts          # Generate Suricata rules from extraction results
│   │   │   ├── templates.ts          # Suricata rule templates by protocol
│   │   │   └── validator.ts          # Validate generated Suricata rules
│   │   ├── documentation.ts          # Generate human-readable documentation per rule
│   │   ├── false-positive-analyzer.ts # Analyze and document expected false positives
│   │   ├── coverage-gap-analyzer.ts   # Identify what the rules DON'T cover
│   │   └── types.ts                  # GeneratedRule, RuleDocumentation types
│   │
│   ├── knowledge/                    # Reference data and knowledge base
│   │   ├── mitre-attack/
│   │   │   ├── loader.ts             # Load ATT&CK STIX data
│   │   │   ├── techniques.ts         # Technique lookup, search, relationships
│   │   │   ├── datasources.ts        # Data source requirements per technique
│   │   │   └── data/                 # Downloaded ATT&CK STIX JSON bundles
│   │   ├── sigma-reference/
│   │   │   ├── loader.ts             # Load reference SigmaHQ rules
│   │   │   ├── quality-scorer.ts     # Score rule quality against reference corpus
│   │   │   └── data/                 # Downloaded SigmaHQ rule samples (curated subset)
│   │   └── logsource-catalog/
│   │       ├── windows.ts            # Windows Event Log ID mappings
│   │       ├── sysmon.ts             # Sysmon event ID mappings
│   │       ├── linux.ts              # Linux audit log mappings
│   │       └── cloud.ts              # AWS CloudTrail, Azure, GCP log mappings
│   │
│   ├── testing/                      # Detection rule testing framework
│   │   ├── sigma-tester.ts           # Test Sigma rules against sample logs
│   │   ├── yara-tester.ts            # Test YARA rules against sample files
│   │   ├── suricata-tester.ts        # Test Suricata rules against PCAPs
│   │   ├── log-generator.ts          # Generate synthetic attack + benign logs
│   │   ├── fp-evaluator.ts           # False positive rate evaluation
│   │   └── test-data/                # Sample logs, PCAPs, files for testing
│   │       ├── attack-logs/          # Simulated attack telemetry
│   │       ├── benign-logs/          # Normal/benign activity logs
│   │       ├── malware-samples/      # Hash references (NOT actual malware)
│   │       └── pcaps/               # Network capture samples
│   │
│   ├── reporting/                    # Output formatting and reporting
│   │   ├── json-reporter.ts          # Machine-readable JSON output
│   │   ├── markdown-reporter.ts      # Human-readable Markdown report
│   │   ├── sarif-reporter.ts         # SARIF format for CI integration
│   │   ├── attack-navigator.ts       # ATT&CK Navigator layer JSON export
│   │   └── summary-reporter.ts       # Executive summary of generated detections
│   │
│   ├── ai/                           # AI inference abstraction layer
│   │   ├── client.ts                 # Claude API client wrapper
│   │   ├── prompts/                  # Engineered prompts (the core IP)
│   │   │   ├── ioc-extraction.ts     # Prompt: extract IOCs from report text
│   │   │   ├── ttp-extraction.ts     # Prompt: extract TTPs with ATT&CK mapping
│   │   │   ├── sigma-generation.ts   # Prompt: generate Sigma rules
│   │   │   ├── yara-generation.ts    # Prompt: generate YARA rules
│   │   │   ├── suricata-generation.ts # Prompt: generate Suricata rules
│   │   │   ├── fp-analysis.ts        # Prompt: analyze false positive scenarios
│   │   │   ├── gap-analysis.ts       # Prompt: identify coverage gaps
│   │   │   └── documentation.ts      # Prompt: generate rule documentation
│   │   ├── response-parser.ts        # Parse structured AI responses
│   │   └── retry.ts                  # Retry logic with exponential backoff
│   │
│   ├── utils/
│   │   ├── defang.ts                 # Defang/refang IOCs for safe handling
│   │   ├── hash.ts                   # Hash validation (MD5/SHA1/SHA256)
│   │   ├── network.ts               # IP/domain/URL validation and parsing
│   │   ├── yaml.ts                   # YAML parsing/serialization
│   │   └── logger.ts                 # Structured logging
│   │
│   └── types/                        # Shared type definitions
│       ├── threat-report.ts          # Core threat report types
│       ├── detection-rule.ts         # Detection rule types (Sigma, YARA, Suricata)
│       ├── mitre-attack.ts           # ATT&CK technique/tactic types
│       └── config.ts                 # Configuration types
│
├── tests/                            # Test suite
│   ├── unit/                         # Unit tests per module
│   │   ├── extraction/
│   │   │   ├── ioc-extractor.test.ts
│   │   │   ├── ttp-extractor.test.ts
│   │   │   └── attack-mapper.test.ts
│   │   ├── generation/
│   │   │   ├── sigma-generator.test.ts
│   │   │   ├── yara-generator.test.ts
│   │   │   └── suricata-generator.test.ts
│   │   ├── validation/
│   │   │   ├── sigma-validator.test.ts
│   │   │   ├── yara-validator.test.ts
│   │   │   └── suricata-validator.test.ts
│   │   └── utils/
│   │       ├── defang.test.ts
│   │       ├── hash.test.ts
│   │       └── network.test.ts
│   │
│   ├── integration/                  # Integration tests
│   │   ├── full-pipeline.test.ts     # End-to-end: report → validated rules
│   │   ├── apt-report-processing.test.ts # Test with real APT reports
│   │   └── multi-format-input.test.ts    # Test all input formats
│   │
│   ├── benchmark/                    # Benchmarking suite
│   │   ├── sigmahq-comparison.test.ts # Compare generated vs SigmaHQ rules
│   │   ├── coverage-metrics.test.ts   # ATT&CK coverage measurement
│   │   ├── fp-rate-evaluation.test.ts # False positive rate measurement
│   │   └── quality-scoring.test.ts    # Overall quality metrics
│   │
│   └── fixtures/                     # Test fixtures
│       ├── reports/                  # Sample threat intel reports
│       │   ├── apt29-cozy-bear.md    # APT29 report (curated sample)
│       │   ├── apt41-double-dragon.md # APT41 report
│       │   ├── lazarus-group.md      # Lazarus Group report
│       │   ├── fin7-carbanak.md      # FIN7 report
│       │   └── cisa-advisory-sample.md # CISA advisory
│       ├── expected-outputs/         # Expected extraction/generation results
│       │   ├── apt29-iocs.json
│       │   ├── apt29-ttps.json
│       │   └── apt29-sigma-rules/
│       ├── sigma-reference/          # Known-good Sigma rules for comparison
│       ├── sample-logs/              # Log samples for rule testing
│       └── benign-baselines/         # Normal activity baselines
│
├── data/                             # Downloaded/scraped reference data
│   ├── mitre-attack/                 # ATT&CK STIX bundles
│   │   └── enterprise-attack.json
│   ├── sigmahq-rules/               # Curated SigmaHQ rule subset
│   ├── threat-reports/               # Collected public threat reports
│   │   ├── sources.json              # Registry of report sources and URLs
│   │   └── reports/                  # Downloaded reports
│   └── log-samples/                  # Collected log samples for testing
│
├── scripts/                          # Build and data collection scripts
│   ├── download-attack-data.ts       # Download latest ATT&CK STIX data
│   ├── download-sigmahq-samples.ts   # Download curated SigmaHQ rules
│   ├── collect-threat-reports.ts     # Scrape/download public threat reports
│   ├── generate-test-logs.ts         # Generate synthetic test log data
│   └── run-benchmarks.ts             # Run full benchmark suite
│
├── docs/                             # Documentation
│   ├── ARCHITECTURE.md               # Technical architecture
│   ├── THREAT-MODEL.md               # Threat model of DetectForge itself
│   ├── BENCHMARKS.md                 # Published benchmark results
│   ├── PROMPT-ENGINEERING.md         # How the AI prompts were designed
│   └── RULE-QUALITY.md              # Rule quality standards and metrics
│
├── .github/
│   └── workflows/
│       ├── ci.yml                    # Run tests on every PR
│       ├── benchmark.yml             # Weekly benchmark runs
│       └── release.yml               # Automated releases
│
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── .env.example                      # ANTHROPIC_API_KEY placeholder
├── .gitignore
├── LICENSE
└── README.md                         # The README that explains the PROBLEM first
```

---

## PHASE 1: DATA COLLECTION & RESEARCH (Agents: 3 parallel)

### Agent 1: MITRE ATT&CK Data Pipeline
Build `scripts/download-attack-data.ts` that:
1. Downloads the latest Enterprise ATT&CK STIX 2.1 bundle from `https://github.com/mitre-attack/attack-stix-data`
2. Parses the STIX JSON into a queryable TypeScript data structure
3. Builds lookup maps:
   - Technique ID → Name, Description, Tactics, Data Sources, Platforms
   - Tactic → Techniques list
   - Data Source → Techniques that can be detected with it
   - Technique → Detection recommendations from ATT&CK
4. Exports as `src/knowledge/mitre-attack/data/enterprise-attack-parsed.json`
5. Includes subtechniques (e.g., T1059.001 PowerShell under T1059 Command and Scripting Interpreter)
6. Total techniques as of 2025: ~200 techniques, ~400 subtechniques

### Agent 2: SigmaHQ Reference Corpus
Build `scripts/download-sigmahq-samples.ts` that:
1. Clones or downloads rules from `https://github.com/SigmaHQ/sigma/tree/master/rules`
2. Curates a representative subset (~200-500 rules) covering:
   - Windows: process_creation, image_load, registry, file_event, network_connection, dns_query, sysmon
   - Linux: process_creation, auditd, file_event
   - Cloud: aws_cloudtrail, azure_activitylogs, gcp_audit
3. Parses each rule to extract: logsource, detection logic patterns, field names, condition syntax
4. Builds a quality reference: "For technique T1059.001, here's how SigmaHQ writes the detection"
5. This corpus is used for benchmarking (comparing AI-generated rules against human-written ones)

### Agent 3: Threat Report Collection
Build `scripts/collect-threat-reports.ts` that:
1. Collects 10-20 high-quality public APT/threat reports from these sources:
   - **CISA Advisories**: `https://www.cisa.gov/news-events/cybersecurity-advisories` (structured, consistent format)
   - **Mandiant/Google Threat Intel**: Public blog posts about APT groups
   - **CrowdStrike Threat Intel**: Public reports on named threat actors
   - **Unit 42 (Palo Alto)**: Public threat research
   - **Microsoft Threat Intelligence**: Public blog posts
   - **The DFIR Report**: `https://thedfirreport.com/` (extremely detailed, includes IOCs + TTPs)
2. Saves in multiple formats: plain text, markdown, and original HTML
3. For each report, manually creates a `ground-truth.json` with:
   - Known IOCs (verified against the report)
   - Known TTPs with ATT&CK technique IDs (verified against the report)
   - Expected detection rule types (Sigma for host-based, YARA for file-based, Suricata for network)
4. These ground-truth files are the test oracle for measuring extraction accuracy

**Critical data to collect per report:**
```json
{
  "report_id": "apt29-cozy-bear-2024",
  "source": "Mandiant",
  "url": "https://...",
  "threat_actor": "APT29 / Cozy Bear",
  "campaign": "SolarWinds follow-up activity",
  "date": "2024-03-15",
  "ground_truth": {
    "iocs": {
      "ipv4": ["192.168.1.1", "10.0.0.1"],
      "domains": ["malicious-domain.com"],
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
        "detection_type": ["sigma", "yara"]
      },
      {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "description": "Used encoded PowerShell commands for C2",
        "detection_type": ["sigma"]
      }
    ],
    "expected_sigma_rules": 5,
    "expected_yara_rules": 2,
    "expected_suricata_rules": 3
  }
}
```

---

## PHASE 2: CORE ENGINE IMPLEMENTATION (Agents: 4 parallel)

### Agent 4: Ingestion Pipeline
Build the `src/ingestion/` module:

**Requirements:**
- Accept input in: PDF, HTML, Markdown, plain text, STIX JSON
- PDF parsing: Use `pdf-parse` npm package. Extract text with layout preservation. Handle multi-column PDFs (common in vendor reports).
- HTML parsing: Use `cheerio` or `jsdom`. Strip navigation/chrome, extract article body. Handle common report platforms (WordPress, Ghost, custom vendor sites).
- All formats normalize to `ThreatReport` type:

```typescript
interface ThreatReport {
  id: string;
  title: string;
  source: string;
  date: string;
  rawText: string;              // Full text content
  sections: ReportSection[];    // Structured sections if parseable
  metadata: {
    threatActor?: string;
    campaign?: string;
    targetSectors?: string[];
    targetRegions?: string[];
    malwareFamilies?: string[];
  };
}

interface ReportSection {
  heading: string;
  content: string;
  type: 'overview' | 'technical_details' | 'iocs' | 'ttps' | 'recommendations' | 'other';
}
```

**Testing:**
- Unit tests for each parser with real report samples
- Test PDF parsing handles vendor-specific formatting (Mandiant vs CrowdStrike vs CISA)
- Test graceful degradation: corrupt PDF, malformed HTML, empty input

### Agent 5: Extraction Engine
Build the `src/extraction/` module:

**IOC Extraction (`ioc-extractor.ts`):**
- Regex-based extraction for deterministic IOC types:
  - IPv4 addresses (with defanged variants: `192.168.1[.]1`, `192.168.1.1`)
  - IPv6 addresses
  - Domains (with defanged variants: `evil[.]com`, `evil(.)com`)
  - URLs (with defanged variants)
  - MD5 hashes (32 hex chars)
  - SHA1 hashes (40 hex chars)
  - SHA256 hashes (64 hex chars)
  - Email addresses
  - File paths (Windows and Linux)
  - Registry keys
  - CVE IDs
  - MITRE ATT&CK technique IDs (T####.###)
- AI-enhanced extraction for context-dependent IOCs:
  - Distinguish between IOCs mentioned as examples vs. actual threat indicators
  - Extract IOCs from tables, code blocks, and inline references
  - Identify IOC relationships (this IP hosted this domain, which served this hash)
- Deduplication: normalize all IOCs (lowercase domains, expand defanged, remove duplicates)
- Classification: tag each IOC with type, confidence, and context from the report

**TTP Extraction (`ttp-extractor.ts`):**
- Uses Claude API to analyze report text and extract behavioral patterns
- For each TTP extracts:
  - Plain-English description of the behavior
  - Tools/utilities used (e.g., "Mimikatz", "PsExec", "certutil.exe")
  - Target systems/platforms
  - Artifacts created (files, registry keys, event log entries)
  - Detection opportunities identified in the report
- AI prompt engineering is CRITICAL here — the prompt must:
  - Extract TTPs at the right granularity (not too broad, not too narrow)
  - Distinguish between what the ADVERSARY did vs. what DEFENDERS should do
  - Handle when reports describe multiple campaigns or variants

**ATT&CK Mapping (`attack-mapper.ts`):**
- Takes extracted TTPs and maps to MITRE ATT&CK technique IDs
- Uses a two-pass approach:
  1. **AI mapping:** Claude maps behavior descriptions to technique IDs
  2. **Validation:** Cross-reference against ATT&CK data to verify technique exists, is correct tactic, and platforms match
- Handles:
  - Subtechnique specificity (T1059 vs T1059.001)
  - Multiple techniques per behavior
  - Confidence scoring (high/medium/low based on description specificity)

**Testing:**
- Test IOC extraction against ground-truth files from Phase 1
- Measure precision/recall for IOC extraction (target: >95% recall, >90% precision)
- Test TTP extraction against ground-truth
- Measure ATT&CK mapping accuracy (target: >85% correct technique ID at subtechnique level)
- Test with reports of varying quality: detailed (The DFIR Report) vs. brief (CISA alert)

### Agent 6: Rule Generation Engine — Sigma
Build `src/generation/sigma/`:

**Generator (`generator.ts`):**
- Takes extraction results and generates Sigma rules
- One rule per detected TTP (where Sigma is appropriate)
- Each rule MUST include:
  ```yaml
  title: Descriptive title following SigmaHQ naming convention
  id: UUID v4
  status: experimental
  description: >
    Detects [specific behavior] associated with [threat actor/campaign].
    Generated by DetectForge from [report source].
  references:
    - [URL to original report]
    - [ATT&CK technique URL]
  author: DetectForge (automated)
  date: YYYY/MM/DD
  modified: YYYY/MM/DD
  tags:
    - attack.[tactic]
    - attack.t[technique_id]
  logsource:
    category: [process_creation|image_load|file_event|registry_event|network_connection|dns_query|...]
    product: [windows|linux|...]
    service: [sysmon|security|system|...]
  detection:
    selection:
      [field]: [value]
    condition: selection
  falsepositives:
    - [Specific false positive scenario 1]
    - [Specific false positive scenario 2]
  level: [informational|low|medium|high|critical]
  ```
- Sigma logsource categories to support:
  - `process_creation` (Windows Event ID 1, Sysmon Event ID 1)
  - `image_load` (Sysmon Event ID 7)
  - `file_event` (Sysmon Event IDs 11, 15, 23)
  - `registry_event` (Sysmon Event IDs 12, 13, 14)
  - `network_connection` (Sysmon Event ID 3)
  - `dns_query` (Sysmon Event ID 22)
  - `pipe_created` (Sysmon Event IDs 17, 18)
  - `wmi_event` (Sysmon Event IDs 19, 20, 21)
  - `ps_script` (PowerShell Script Block Logging Event ID 4104)
  - `security` (Windows Security Event Log)
  - Cloud: `aws_cloudtrail`, `azure_activitylogs`, `gcp_audit`
- Detection logic patterns:
  - Simple field matching (`CommandLine|contains: 'Invoke-Mimikatz'`)
  - Regex patterns where needed (`CommandLine|re: '...'`)
  - Multiple selection conditions with AND/OR logic
  - Negative conditions for FP reduction (`filter_legitimate:`)
  - Aggregation conditions where applicable (`count() > 5`)
- Rule quality requirements:
  - No overly broad rules (e.g., just matching on `powershell.exe` without additional specificity)
  - Every rule must have at least one false positive documented
  - Level must be justified (not everything is "critical")
  - Tags must include correct ATT&CK tactic and technique

**Templates (`templates.ts`):**
- Provide structural templates for each logsource category
- Include field name reference (e.g., for process_creation: `Image`, `CommandLine`, `ParentImage`, `User`, etc.)
- Include common false positive patterns per logsource

**Validator (`validator.ts`):**
- Validate generated YAML is syntactically correct
- Validate required Sigma fields are present
- Validate logsource category/product/service combinations are valid
- Validate detection condition references exist
- Validate ATT&CK technique IDs are real
- Validate no duplicate rule IDs

### Agent 7: Rule Generation Engine — YARA + Suricata
Build `src/generation/yara/` and `src/generation/suricata/`:

**YARA Generator:**
- Generate YARA rules for file-based IOCs (malware samples, malicious documents, scripts)
- Each rule includes:
  ```yara
  rule APT29_Malicious_Document : apt29 maldoc {
      meta:
          description = "Detects malicious document associated with APT29 campaign"
          author = "DetectForge (automated)"
          date = "2024-03-15"
          reference = "https://..."
          mitre_attack = "T1566.001"
          hash1 = "abc123..."

      strings:
          $macro1 = "AutoOpen" ascii
          $cmd1 = "powershell" ascii nocase
          $encoded = /[A-Za-z0-9+\/]{50,}={0,2}/ ascii
          $domain = "malicious-domain.com" ascii

      condition:
          uint16(0) == 0xD0CF and   // OLE header
          filesize < 5MB and
          $macro1 and
          ($cmd1 or $encoded) and
          $domain
  }
  ```
- Rule categories:
  - Malicious documents (OLE/OOXML with macros)
  - Script-based payloads (PowerShell, VBScript, JScript)
  - Binary indicators (specific byte patterns, strings, imports)
  - Webshells
- Quality requirements:
  - Must include file type constraints (magic bytes) to avoid scanning everything
  - Must include filesize constraint
  - Must not rely solely on generic strings ("http://", "cmd.exe")
  - Each string must be justified in the meta description

**Suricata Generator:**
- Generate Suricata rules for network-based IOCs
- Each rule follows the format:
  ```
  alert http $HOME_NET any -> $EXTERNAL_NET any (
      msg:"DetectForge - APT29 C2 Communication to malicious-domain.com";
      flow:established,to_server;
      http.host; content:"malicious-domain.com";
      reference:url,https://...;
      metadata:mitre_attack T1071.001, created_at 2024_03_15, by DetectForge;
      classtype:trojan-activity;
      sid:9000001; rev:1;
  )
  ```
- Rule categories:
  - DNS queries to malicious domains
  - HTTP/HTTPS connections to malicious IPs/domains
  - TLS certificate patterns (JA3/JA3S fingerprints if available)
  - Specific URI patterns associated with C2 frameworks
  - File download patterns (specific content types, sizes)
- SID allocation: Use range 9000000-9999999 (local rules range)

---

## PHASE 3: DOCUMENTATION & ANALYSIS ENGINE (Agent: 1)

### Agent 8: Rule Documentation Generator
Build `src/generation/documentation.ts`, `false-positive-analyzer.ts`, and `coverage-gap-analyzer.ts`:

**Rule Documentation:**
For each generated rule, produce a companion document:
```markdown
## Rule: [Title]

### What This Detects
[Plain English: what specific adversary behavior this rule catches]

### How It Works
[Technical explanation of each detection logic component]
- `selection.Image|endswith: '\powershell.exe'` — Matches PowerShell execution
- `selection.CommandLine|contains|all: ['-enc', '-nop']` — Matches encoded, no-profile execution
- `filter_admin: ...` — Excludes known IT admin workstations

### MITRE ATT&CK Mapping
- **Technique:** T1059.001 (PowerShell)
- **Tactic:** Execution
- **Platform:** Windows

### Expected False Positives
1. **IT Administrators** — Legitimate encoded PowerShell used in deployment scripts. Tune by excluding known admin accounts or source workstations.
2. **SCCM/Intune** — Software deployment may trigger this. Tune by excluding the SCCM service account.
3. **Monitoring tools** — Some RMM tools use encoded PowerShell. Tune by excluding the RMM tool's parent process.

### What This Rule DOES NOT Catch
- PowerShell execution via `System.Management.Automation` .NET assembly (no powershell.exe process)
- PowerShell Constrained Language Mode bypass techniques
- Encoded commands passed via environment variables rather than command line

### Recommended Log Sources
- Windows Event Log: Security (Event ID 4688) with command-line logging enabled
- Sysmon: Event ID 1 (Process Creation) — preferred, provides parent process chain
- PowerShell: Script Block Logging (Event ID 4104) — catches the decoded script content

### Tuning Recommendations
- Start with the rule as-is for 7 days to establish baseline
- Document all false positives
- Add exclusions for verified legitimate patterns
- Consider promoting from `experimental` to `test` after tuning
```

**False Positive Analysis:**
- For each rule, use Claude API to generate 3-5 realistic false positive scenarios
- Each scenario must be SPECIFIC, not generic:
  - BAD: "Legitimate administrative activity"
  - GOOD: "SCCM task sequences executing encoded PowerShell with `-ExecutionPolicy Bypass -NonInteractive -EncodedCommand` to deploy software packages. The parent process chain would be `svchost.exe → CCMExec.exe → powershell.exe`."
- Include tuning recommendation for each FP scenario

**Coverage Gap Analysis:**
- For the set of generated rules, identify what's NOT covered:
  - TTPs from the report that couldn't be translated to detection rules (and why)
  - Alternative implementations of the same technique that would evade the rules
  - Required log sources that may not be available in all environments
  - Time-based detection gaps (rules that only work during active attack, not for historical hunting)

---

## PHASE 4: TESTING FRAMEWORK (Agents: 2 parallel)

### Agent 9: Test Data Generation & Validation Tests
Build `src/testing/` and `tests/`:

**Synthetic Attack Log Generator (`log-generator.ts`):**
- For each generated Sigma rule, create synthetic log entries that SHOULD trigger the detection
- Log format: JSON matching the Sigma field specification
- Example for a process_creation rule:
  ```json
  {
    "EventID": 1,
    "UtcTime": "2024-03-15 14:32:47.123",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA...",
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "ParentCommandLine": "cmd.exe /c start /min powershell.exe -nop -enc ...",
    "User": "DOMAIN\\john.smith",
    "LogonId": "0x3e7",
    "Hashes": "SHA256=abc123..."
  }
  ```
- Also generate BENIGN log entries that should NOT trigger:
  ```json
  {
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -Command Get-Service | Where-Object {$_.Status -eq 'Running'}",
    "ParentImage": "C:\\Windows\\explorer.exe",
    "User": "DOMAIN\\admin.user"
  }
  ```

**Sigma Rule Tester (`sigma-tester.ts`):**
- Load a Sigma rule and test logs
- Implement Sigma detection logic evaluation in TypeScript:
  - Field matching (exact, contains, startswith, endswith, re)
  - Wildcards (* and ?)
  - Modifiers (|all, |base64, |utf16le, etc.)
  - Condition evaluation (AND/OR/NOT/1 of X)
- For each rule, report:
  - True Positives (attack logs correctly matched)
  - True Negatives (benign logs correctly not matched)
  - False Positives (benign logs incorrectly matched)
  - False Negatives (attack logs incorrectly not matched)
- Output confusion matrix per rule

**Unit Tests:**
- Every module gets unit tests
- IOC extractor: test against known reports with ground truth
- TTP extractor: test against known reports with ground truth
- ATT&CK mapper: test technique ID accuracy
- Sigma generator: test YAML validity
- YARA generator: test syntax validity
- Suricata generator: test syntax validity
- Each parser: test with malformed/edge-case inputs
- Defanging/refanging: comprehensive test cases

### Agent 10: Benchmark Suite
Build `tests/benchmark/`:

**SigmaHQ Comparison (`sigmahq-comparison.test.ts`):**
- For techniques where both DetectForge and SigmaHQ have rules:
  1. Compare detection logic breadth (does DetectForge cover the same variants?)
  2. Compare false positive handling (does DetectForge identify the same FP scenarios?)
  3. Compare field usage (does DetectForge use the right log fields?)
  4. Score on 1-10 scale across dimensions: completeness, precision, documentation quality
- Publish results as a table in `docs/BENCHMARKS.md`

**ATT&CK Coverage Metrics (`coverage-metrics.test.ts`):**
- Given a set of generated rules from a report, calculate:
  - Number of unique ATT&CK techniques covered
  - Percentage of report's identified TTPs that have corresponding detection rules
  - Distribution across tactics (kill chain coverage)
  - Export as ATT&CK Navigator JSON layer for visualization
- Output a heat map showing coverage by tactic:
  ```
  Initial Access:     ██████░░░░ 60%
  Execution:          ████████░░ 80%
  Persistence:        ████░░░░░░ 40%
  Privilege Escalation: ██░░░░░░░░ 20%
  ...
  ```

**False Positive Rate Evaluation (`fp-rate-evaluation.test.ts`):**
- Run every generated rule against a corpus of benign logs
- Measure FP rate per rule and aggregate
- Target: < 5% FP rate across the corpus
- Identify rules with highest FP rates and explain why

**End-to-End Pipeline Test (`full-pipeline.test.ts`):**
- Take 5 real APT reports
- Run full pipeline: ingest → extract → generate → validate → test
- For each, measure:
  - Total rules generated
  - Rules that pass validation
  - Rules that correctly match simulated attack logs
  - Rules with acceptable FP rates
  - Time to process
  - API token usage (cost tracking)
- Output a comprehensive test report

---

## PHASE 5: CLI, REPORTING, AND POLISH (Agent: 1)

### Agent 11: CLI Interface & Reporting
Build `src/cli/` and `src/reporting/`:

**CLI Commands:**

```bash
# Primary command: generate detection rules from a threat report
detectforge generate --input report.pdf --output ./rules/ --format sigma,yara,suricata
detectforge generate --input report.md --output ./rules/ --sigma-only
detectforge generate --input https://thedfirreport.com/2024/... --output ./rules/

# Extract IOCs and TTPs without generating rules
detectforge extract --input report.pdf --output extracted.json

# Validate existing rules
detectforge validate --input ./rules/ --format sigma

# Benchmark against SigmaHQ
detectforge benchmark --input ./rules/ --sigmahq-path ./sigmahq-rules/

# ATT&CK coverage analysis
detectforge coverage --input ./rules/ --output coverage.json --navigator-layer

# Full pipeline with testing
detectforge generate --input report.pdf --output ./rules/ --test --benchmark --verbose
```

**CLI Output:**
- Progress indicators for each stage (ingestion → extraction → generation → validation → testing)
- Color-coded: green for valid rules, yellow for warnings, red for failures
- Summary table at the end:
  ```
  ╔══════════════════════════════════════════════════╗
  ║  DetectForge — Generation Summary                ║
  ╠══════════════════════════════════════════════════╣
  ║  Report:       APT29 Cozy Bear Campaign Report   ║
  ║  Source:       Mandiant                          ║
  ║  ───────────────────────────────────────         ║
  ║  IOCs Extracted:       47 (12 IP, 8 domain, ...) ║
  ║  TTPs Identified:      12                        ║
  ║  ATT&CK Techniques:    9                         ║
  ║  ───────────────────────────────────────         ║
  ║  Sigma Rules:          7  (7 valid, 0 invalid)   ║
  ║  YARA Rules:           3  (3 valid, 0 invalid)   ║
  ║  Suricata Rules:       5  (5 valid, 0 invalid)   ║
  ║  ───────────────────────────────────────         ║
  ║  Test Results:         14/15 passing (93%)       ║
  ║  FP Rate:              2.1%                      ║
  ║  ATT&CK Coverage:      75% of report TTPs       ║
  ║  ───────────────────────────────────────         ║
  ║  Processing Time:      47s                       ║
  ║  API Tokens Used:      ~12,400                   ║
  ╚══════════════════════════════════════════════════╝
  ```

**Report Outputs:**
- `--json`: Machine-readable JSON with all extracted data + generated rules
- `--markdown`: Human-readable report with rule documentation
- `--sarif`: SARIF format for GitHub Advanced Security / CI integration
- `--navigator`: ATT&CK Navigator layer JSON file
- Default: all rules written as individual files + summary report

---

## PHASE 6: README, THREAT MODEL, AND PORTFOLIO PRESENTATION (Agent: 1)

### Agent 12: Documentation & Portfolio Packaging

**README.md Structure:**
1. **The Problem** (not the tool — the PROBLEM. 2-3 paragraphs on why this matters)
2. **Quick Start** (install + run in < 60 seconds)
3. **Demo** (GIF or screenshot of CLI output processing a real report)
4. **How It Works** (architecture diagram, data flow)
5. **Benchmark Results** (honest metrics — precision, recall, FP rate, comparison to SigmaHQ)
6. **Supported Input Formats** (PDF, HTML, Markdown, STIX, JSON)
7. **Generated Rule Types** (Sigma, YARA, Suricata with examples)
8. **Installation** (npm install, bun, from source)
9. **Configuration** (API key, output preferences)
10. **Testing** (how to run tests, what they measure)
11. **Limitations & Known Gaps** (HONEST — where does the AI fail?)
12. **Contributing**
13. **License**

**Threat Model of DetectForge Itself (`docs/THREAT-MODEL.md`):**
- What happens if the AI hallucinates a technique ID that doesn't exist? → Validation catches it
- What happens if a generated rule is too broad and matches everything? → FP testing catches it
- What happens if the AI misses a critical TTP from the report? → Coverage gap analysis documents it
- What happens if someone feeds a poisoned report designed to generate backdoored rules? → Input validation + output review
- What happens if the API key is leaked? → .env.example pattern, .gitignore, not in repo
- Supply chain risk of DetectForge's own dependencies → package-lock.json, minimal deps

**Benchmark Results (`docs/BENCHMARKS.md`):**
- Publish real numbers from the benchmark suite:
  - IOC extraction accuracy per report
  - TTP extraction accuracy per report
  - ATT&CK mapping accuracy
  - Rule validation pass rate
  - True positive detection rate
  - False positive rate
  - Comparison to SigmaHQ rules
  - Processing time per report
  - API cost per report
- Be HONEST about failures. Where the tool fails is as important as where it succeeds. This is what impresses hiring managers.

---

## QUALITY GATES — Must Pass Before Considering Complete

| Gate | Criteria | Measurement |
|------|----------|-------------|
| **Syntax Validity** | 100% of generated Sigma rules pass YAML validation + Sigma schema validation | Automated test |
| **Syntax Validity** | 100% of generated YARA rules pass yara compilation | Automated test |
| **Syntax Validity** | 100% of generated Suricata rules pass syntax check | Automated test |
| **IOC Extraction** | >95% recall, >90% precision against ground truth | Benchmark vs 10+ reports |
| **TTP Extraction** | >85% recall, >80% precision against ground truth | Benchmark vs 10+ reports |
| **ATT&CK Mapping** | >85% correct technique ID at subtechnique level | Benchmark vs ground truth |
| **True Positive Rate** | >90% of generated rules match their corresponding simulated attack logs | Sigma tester output |
| **False Positive Rate** | <5% aggregate FP rate across benign log corpus | FP evaluation output |
| **Documentation** | Every rule has companion documentation with FP analysis | Automated check |
| **Coverage Transparency** | Every report's gap analysis identifies uncovered TTPs | Automated check |
| **End-to-End** | Full pipeline processes 5 real reports without errors | Integration test |
| **Unit Test Coverage** | >80% code coverage | Vitest coverage report |
| **CI/CD** | All tests pass on GitHub Actions | Green CI badge |
| **README** | Explains the problem, shows real benchmarks, documents limitations | Human review |

---

## EXECUTION ORDER

```
PHASE 1: Data Collection (3 parallel agents, ~2-3 hours)
   ├── Agent 1: MITRE ATT&CK data pipeline
   ├── Agent 2: SigmaHQ reference corpus
   └── Agent 3: Threat report collection + ground truth creation

PHASE 2: Core Engine (4 parallel agents, ~4-6 hours)
   ├── Agent 4: Ingestion pipeline (parsers + normalizer)
   ├── Agent 5: Extraction engine (IOC + TTP + ATT&CK mapper)
   ├── Agent 6: Sigma rule generator + validator
   └── Agent 7: YARA + Suricata generators + validators

PHASE 3: Documentation Engine (1 agent, ~2 hours)
   └── Agent 8: Rule documentation + FP analysis + gap analysis

PHASE 4: Testing Framework (2 parallel agents, ~3-4 hours)
   ├── Agent 9: Test data generation + unit/integration tests
   └── Agent 10: Benchmark suite

PHASE 5: CLI & Reporting (1 agent, ~2-3 hours)
   └── Agent 11: CLI interface + output formatters

PHASE 6: Polish & Portfolio (1 agent, ~1-2 hours)
   └── Agent 12: README, threat model, benchmark docs

TOTAL ESTIMATED: 12 agents, ~6-8 hours with parallelism
```

---

## CRITICAL CONSTRAINTS

1. **TypeScript throughout.** Python only as subprocess calls for validation tools (pySigma, yara-python) if needed.
2. **bun as package manager.** All scripts run with `bun run`.
3. **Claude API via Anthropic SDK.** No direct API calls. Use `@anthropic-ai/sdk`.
4. **CLI-first.** No web UI in v1. Security practitioners live in terminals.
5. **Machine-readable output.** JSON + SARIF for CI integration. Human-readable is a layer on top.
6. **No actual malware in the repo.** Use hashes, references, and synthetic samples only.
7. **All test data must be from public sources.** No proprietary threat intel.
8. **Honest benchmarks.** Publish failures alongside successes. This IS the differentiator.
9. **Minimize dependencies.** Every npm package is attack surface. Keep it lean.
10. **ANTHROPIC_API_KEY in .env only.** Never in code, never in commits.
