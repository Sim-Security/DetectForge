# DetectForge — Project Backlog

**Version:** 1.0 | **Date:** 2026-02-10 | **Methodology:** Sprint-based, aligned with MASTER_PROMPT phases

---

## Sprint Overview

| Sprint | Phase | Focus | Key Deliverables |
|--------|-------|-------|-----------------|
| **S0** | Foundation | Project scaffolding, types, utils, CI | Repo, types, tests, CI green |
| **S1** | Data Collection | ATT&CK pipeline, SigmaHQ corpus, threat reports | Reference data + ground truth |
| **S2** | Core Engine | Ingestion, extraction, ATT&CK mapping | Report → structured data pipeline |
| **S3** | Rule Generation | Sigma, YARA, Suricata generators + validators | Extraction → validated rules |
| **S4** | Documentation Engine | FP analysis, coverage gaps, rule docs | Every rule has companion docs |
| **S5** | Testing Framework | Sigma tester, log gen, benchmarks | TP/FP rates, quality metrics |
| **S6** | CLI & Reporting | CLI polish, reporters, output formats | Production CLI with all outputs |
| **S7** | Portfolio Polish | README, threat model, benchmark docs | Portfolio-ready presentation |

---

## S0: Foundation (COMPLETE)

> Project scaffolding, type system, utility modules, CI pipeline.

- [x] **S0-001** Initialize git repo with remote `https://github.com/Sim-Security/DetectForge.git`
- [x] **S0-002** Create `package.json` with dependencies (commander, yaml, chalk, ora, uuid, cheerio, pdf-parse, dotenv, zod)
- [x] **S0-003** Configure `tsconfig.json` (ES2022, strict, path aliases)
- [x] **S0-004** Configure `vitest.config.ts` (V8 coverage, 80% thresholds)
- [x] **S0-005** Create `.env.example` with OpenRouter config (3 model tiers: fast/standard/quality)
- [x] **S0-006** Create `.gitignore` (node_modules, dist, .env, data downloads, test artifacts)
- [x] **S0-007** Create core type definitions (`src/types/`: threat-report, detection-rule, mitre-attack, extraction, config)
- [x] **S0-008** Build OpenRouter AI client (`src/ai/client.ts`) with model tiers + cost tracking
- [x] **S0-009** Build utility modules (`src/utils/`: defang, hash, network, yaml, logger)
- [x] **S0-010** Write unit tests for all utilities (38 tests passing)
- [x] **S0-011** Create CLI entry point with stubbed commands (generate, extract, validate, benchmark, coverage)
- [x] **S0-012** Configure GitHub Actions CI workflow
- [x] **S0-013** Create PRD document (`docs/PRD.md`)
- [x] **S0-014** Create MIT LICENSE

---

## S1: Data Collection & Reference Pipelines

> Download and parse MITRE ATT&CK data, curate SigmaHQ reference rules, collect threat reports with ground truth.

### ATT&CK Data Pipeline

- [ ] **S1-001** Build `scripts/download-attack-data.ts` — download Enterprise ATT&CK STIX 2.1 bundle from GitHub
  - Source: `https://github.com/mitre-attack/attack-stix-data`
  - Parse STIX JSON into queryable TypeScript structures
  - **AC:** Script downloads, parses, and saves `data/mitre-attack/enterprise-attack.json`

- [ ] **S1-002** Build `src/knowledge/mitre-attack/loader.ts` — load and index ATT&CK data
  - Technique ID → name, description, tactics, data sources, platforms
  - Tactic → techniques list
  - Data source → techniques detectable with it
  - **AC:** Can look up any technique by ID, get all techniques for a tactic

- [ ] **S1-003** Build `src/knowledge/mitre-attack/techniques.ts` — technique lookup, search, relationships
  - Search by keyword, tactic, platform
  - Subtechnique resolution (T1059.001 → parent T1059)
  - Detection recommendations from ATT&CK data
  - **AC:** Unit tests for lookup, search, subtechnique resolution

- [ ] **S1-004** Build `src/knowledge/mitre-attack/datasources.ts` — data source requirements per technique
  - Map which log sources are needed to detect each technique
  - **AC:** Given T1059.001, returns required data sources (process creation, script block logging)

### SigmaHQ Reference Corpus

- [ ] **S1-005** Build `scripts/download-sigmahq-samples.ts` — download curated SigmaHQ rules
  - Clone/download from `https://github.com/SigmaHQ/sigma/tree/master/rules`
  - Curate 200-500 representative rules covering Windows, Linux, Cloud categories
  - **AC:** Saves rules to `data/sigmahq-rules/`, indexed by ATT&CK technique

- [ ] **S1-006** Build `src/knowledge/sigma-reference/loader.ts` — load and index reference rules
  - Parse each rule: logsource, detection patterns, field names, condition syntax
  - Index by ATT&CK technique ID for benchmarking
  - **AC:** Can retrieve SigmaHQ rules by technique ID

- [ ] **S1-007** Build `src/knowledge/sigma-reference/quality-scorer.ts` — score rule quality
  - Compare generated rules against SigmaHQ reference
  - Dimensions: field coverage, condition complexity, FP documentation, metadata completeness
  - **AC:** Returns quality score 1-10 for a generated rule vs reference

### Logsource Catalog

- [ ] **S1-008** Build `src/knowledge/logsource-catalog/windows.ts` — Windows event log ID mappings
  - Security log event IDs (4688, 4624, 4625, 4672, etc.)
  - System log event IDs
  - **AC:** Event ID → category mapping, field name reference

- [ ] **S1-009** Build `src/knowledge/logsource-catalog/sysmon.ts` — Sysmon event ID mappings
  - Event IDs 1-26 with field name reference
  - **AC:** Sysmon event ID → Sigma logsource category mapping

- [ ] **S1-010** Build `src/knowledge/logsource-catalog/linux.ts` — Linux audit log mappings
  - auditd, syslog, auth.log patterns
  - **AC:** Linux log type → field name reference

### Threat Report Collection

- [ ] **S1-011** Build `scripts/collect-threat-reports.ts` — download public threat reports
  - Collect 10-20 public APT reports (CISA, Mandiant, CrowdStrike, Unit 42, DFIR Report)
  - Save in markdown and plain text formats
  - **AC:** Saves reports to `data/threat-reports/reports/`

- [ ] **S1-012** Create ground truth files for 5+ reports
  - `tests/fixtures/reports/` — curated report text
  - `tests/fixtures/expected-outputs/` — verified IOCs, TTPs, ATT&CK mappings per report
  - **AC:** At least 5 reports with complete ground truth JSON

- [ ] **S1-013** Create report source registry (`data/threat-reports/sources.json`)
  - Catalog of report sources with URLs, quality ratings, format details
  - **AC:** JSON registry with 20+ sources

---

## S2: Core Engine — Ingestion & Extraction

> Parse threat reports into structured data. Extract IOCs and TTPs. Map to MITRE ATT&CK.

### Ingestion Pipeline

- [ ] **S2-001** Build `src/ingestion/parsers/pdf.ts` — PDF report parser
  - Uses `pdf-parse` package
  - Handles multi-column layouts, tables, code blocks
  - Preserves IOC formatting (including defanged)
  - **AC:** Parses 5+ real vendor PDFs correctly, unit tests pass

- [ ] **S2-002** Build `src/ingestion/parsers/html.ts` — HTML report parser
  - Uses `cheerio` for DOM parsing
  - Strips nav/chrome, extracts article body
  - Handles WordPress, Medium, Ghost, vendor-specific layouts
  - **AC:** Parses 5+ real blog post URLs correctly

- [ ] **S2-003** Build `src/ingestion/parsers/markdown.ts` — Markdown report parser
  - CommonMark spec support
  - Preserves section structure, tables, code blocks
  - **AC:** Round-trips structure through parse → ThreatReport

- [ ] **S2-004** Build `src/ingestion/parsers/plaintext.ts` — Plain text parser
  - UTF-8/ASCII support
  - Section boundary detection heuristics
  - **AC:** Handles CISA-style plain text advisories

- [ ] **S2-005** Build `src/ingestion/normalizer.ts` — normalize all formats to `ThreatReport`
  - Unified interface for all parsers
  - Auto-detect format from file extension / content
  - Section classification: overview, technical_details, iocs, ttps, recommendations
  - Metadata extraction: threat actor, campaign, target sectors, malware families
  - **AC:** Any supported input produces valid `ThreatReport` object

- [ ] **S2-006** Write ingestion unit tests
  - Tests for each parser with real report samples
  - Edge cases: corrupt PDF, malformed HTML, empty input, huge documents
  - **AC:** >90% code coverage for ingestion module

### IOC Extraction

- [ ] **S2-007** Build `src/extraction/ioc-extractor.ts` — regex + AI IOC extraction
  - Regex patterns: IPv4/IPv6, domains, URLs, email, MD5/SHA1/SHA256, file paths, registry keys, CVE IDs
  - Handle defanged variants: `[.]`, `(.)`, `[dot]`, `hxxp`, `[@]`, `[at]`
  - AI-enhanced context extraction: distinguish threat IOCs from examples
  - **AC:** >95% recall, >90% precision on ground truth reports

- [ ] **S2-008** Build `src/extraction/ioc-enrichment.ts` — IOC enrichment and classification
  - Deduplication (normalize canonical form)
  - Type classification (C2 server, phishing domain, payload hash, etc.)
  - Relationship extraction (IP hosted domain, domain served hash)
  - **AC:** Enriched IOCs include type, confidence, context

### TTP Extraction

- [ ] **S2-009** Build `src/extraction/ttp-extractor.ts` — AI-powered TTP extraction
  - Use AI to extract behavioral patterns from report text
  - For each TTP: description, tools used, target systems, artifacts, detection opportunities
  - Confidence scoring (high/medium/low)
  - **AC:** >85% recall, >80% precision on ground truth reports

- [ ] **S2-010** Build `src/extraction/attack-mapper.ts` — MITRE ATT&CK technique mapping
  - Two-pass approach: AI mapping → validation against ATT&CK data
  - Subtechnique specificity (prefer T1059.001 over T1059)
  - Multiple techniques per TTP, tactic assignment, platform matching
  - Confidence scoring
  - **AC:** >85% correct technique ID at subtechnique level

- [ ] **S2-011** Build AI prompts for extraction (`src/ai/prompts/ioc-extraction.ts`, `ttp-extraction.ts`)
  - Engineered prompts for IOC extraction with structured JSON output
  - Engineered prompts for TTP extraction with ATT&CK context
  - System prompts with schema definitions and examples
  - **AC:** Prompts produce parseable, high-quality structured responses

- [ ] **S2-012** Build `src/ai/response-parser.ts` — parse structured AI responses
  - JSON extraction from AI responses
  - Zod schema validation for all AI outputs
  - Graceful handling of malformed responses
  - **AC:** Validates and parses all AI response formats

- [ ] **S2-013** Build `src/ai/retry.ts` — retry logic with backoff
  - Exponential backoff for API rate limits
  - Configurable max retries
  - **AC:** Handles 429 errors, network failures gracefully

- [ ] **S2-014** Write extraction unit tests
  - IOC extractor against ground truth files
  - TTP extractor against ground truth files
  - ATT&CK mapper accuracy tests
  - Edge cases: reports with no IOCs, reports with thousands of IOCs
  - **AC:** >90% code coverage for extraction module

---

## S3: Rule Generation Engine

> Generate Sigma, YARA, and Suricata rules from extraction results. Validate all output.

### Sigma Generation

- [ ] **S3-001** Build `src/generation/sigma/templates.ts` — Sigma rule templates
  - Templates by logsource category: process_creation, image_load, file_event, registry_event, network_connection, dns_query, pipe_created, wmi_event, ps_script, security
  - Field name reference per category
  - Common FP patterns per logsource
  - **AC:** Templates cover all supported logsource categories

- [ ] **S3-002** Build `src/generation/sigma/generator.ts` — Sigma rule generator
  - Takes extraction results → generates Sigma YAML rules
  - One rule per detected TTP (where Sigma is appropriate)
  - Includes all required fields: title, id (UUIDv4), status, description, references, author, date, tags, logsource, detection, falsepositives, level
  - Detection logic: field matching, wildcards, regex, multiple selections, filter conditions
  - **AC:** Generates valid Sigma YAML for all supported logsource categories

- [ ] **S3-003** Build `src/generation/sigma/validator.ts` — Sigma rule validator
  - YAML syntax validation
  - Required field presence check
  - Logsource category/product/service combination validation
  - Detection condition references validation
  - ATT&CK technique ID validation against loaded data
  - Duplicate rule ID detection
  - **AC:** 100% of valid rules pass, 100% of invalid rules caught

- [ ] **S3-004** Build Sigma generation AI prompt (`src/ai/prompts/sigma-generation.ts`)
  - Prompt with Sigma spec context, logsource field references, examples
  - Structured output format for rule YAML
  - **AC:** AI generates spec-compliant Sigma rules

### YARA Generation

- [ ] **S3-005** Build `src/generation/yara/templates.ts` — YARA rule templates
  - Templates by file type: malicious documents (OLE/OOXML), scripts (PS, VBS, JS), binaries, webshells
  - Magic byte references, common string patterns
  - **AC:** Templates cover all supported file categories

- [ ] **S3-006** Build `src/generation/yara/generator.ts` — YARA rule generator
  - Takes file-based IOCs → generates YARA rules
  - Includes: meta (description, author, date, reference, mitre_attack, hashes), strings, condition
  - File type constraints (magic bytes), filesize constraints
  - Quality: no overly generic strings, justified patterns
  - **AC:** Generates compilable YARA rules for file-based threats

- [ ] **S3-007** Build `src/generation/yara/validator.ts` — YARA rule validator
  - Syntax validation (YARA grammar check)
  - Required metadata field check
  - Condition logic validation
  - **AC:** Validates YARA syntax without requiring yara binary

- [ ] **S3-008** Build YARA generation AI prompt (`src/ai/prompts/yara-generation.ts`)
  - Prompt with YARA syntax spec, file type patterns, examples
  - **AC:** AI generates compilable YARA rules

### Suricata Generation

- [ ] **S3-009** Build `src/generation/suricata/templates.ts` — Suricata rule templates
  - Templates by protocol: DNS, HTTP/HTTPS, TLS, generic TCP/UDP
  - Variable references ($HOME_NET, $EXTERNAL_NET, etc.)
  - **AC:** Templates cover all supported network detection categories

- [ ] **S3-010** Build `src/generation/suricata/generator.ts` — Suricata rule generator
  - Takes network IOCs → generates Suricata rules
  - Format: action, header, options (msg, flow, content, metadata, classtype, sid, rev)
  - SID range 9000000-9999999 (local rules)
  - Rule categories: DNS queries, HTTP connections, TLS patterns, URI patterns, file downloads
  - **AC:** Generates valid Suricata rules for network-based threats

- [ ] **S3-011** Build `src/generation/suricata/validator.ts` — Suricata rule validator
  - Syntax validation (Suricata grammar)
  - Required fields check
  - SID range validation
  - **AC:** Validates Suricata syntax without requiring Suricata binary

- [ ] **S3-012** Build Suricata generation AI prompt (`src/ai/prompts/suricata-generation.ts`)
  - Prompt with Suricata format spec, keyword references, examples
  - **AC:** AI generates valid Suricata rules

- [ ] **S3-013** Write rule generation unit tests
  - Sigma: YAML validity, required fields, logsource validation, condition parsing
  - YARA: syntax validity, metadata, condition logic
  - Suricata: syntax validity, header format, keyword validation
  - **AC:** >90% code coverage for generation module

---

## S4: Documentation & Analysis Engine

> Generate companion documentation for every rule. Analyze false positives and coverage gaps.

- [ ] **S4-001** Build `src/generation/documentation.ts` — rule documentation generator
  - For each rule: what it detects, how it works, ATT&CK mapping, log source recommendations, tuning guidance
  - Technical explanation of each detection logic component
  - **AC:** Every generated rule has companion documentation

- [ ] **S4-002** Build `src/generation/false-positive-analyzer.ts` — FP analysis
  - AI generates 3-5 SPECIFIC FP scenarios per rule (not generic)
  - Each includes: scenario description, parent process chain, tuning recommendation
  - **AC:** FP scenarios are realistic and actionable

- [ ] **S4-003** Build `src/generation/coverage-gap-analyzer.ts` — gap analysis
  - Identifies TTPs that couldn't be translated to rules (and why)
  - Alternative technique implementations that would evade rules
  - Required log sources that may not be available
  - Time-based detection gaps
  - **AC:** Gap report identifies uncovered TTPs with explanations

- [ ] **S4-004** Build FP analysis AI prompt (`src/ai/prompts/fp-analysis.ts`)
  - Prompt produces specific, environment-aware FP scenarios
  - **AC:** Responses include tuning recommendations

- [ ] **S4-005** Build gap analysis AI prompt (`src/ai/prompts/gap-analysis.ts`)
  - Prompt identifies evasion vectors and coverage blind spots
  - **AC:** Gap analysis covers technique variants and log source dependencies

- [ ] **S4-006** Build documentation AI prompt (`src/ai/prompts/documentation.ts`)
  - Prompt generates clear, technical rule documentation
  - **AC:** Documentation is useful to a SOC analyst deploying the rule

- [ ] **S4-007** Write documentation engine unit tests
  - Test documentation generation for each rule format
  - Test FP analysis specificity
  - Test gap analysis completeness
  - **AC:** >80% code coverage for documentation module

---

## S5: Testing Framework & Benchmarks

> Build Sigma tester, synthetic log generator, benchmark suite. Measure quality metrics.

### Sigma Testing Engine

- [ ] **S5-001** Build `src/testing/sigma-tester.ts` — Sigma rule evaluation engine
  - Implement Sigma detection logic in TypeScript
  - Field matching: exact, contains, startswith, endswith, re, base64
  - Wildcards (* and ?)
  - Modifiers: |all, |base64, |utf16le, |endswith, |startswith, |contains
  - Condition evaluation: AND/OR/NOT/1 of X/all of X
  - **AC:** Correctly evaluates Sigma rules against log entries

- [ ] **S5-002** Build `src/testing/log-generator.ts` — synthetic log generator
  - For each Sigma rule: generate attack logs that SHOULD trigger
  - Generate benign logs that should NOT trigger
  - JSON format matching Sigma field specifications
  - **AC:** Generates matched attack + benign log pairs per rule

- [ ] **S5-003** Build `src/testing/fp-evaluator.ts` — false positive rate evaluation
  - Run rules against benign log corpus
  - Measure FP rate per rule and aggregate
  - Identify highest-FP rules with explanations
  - **AC:** Reports FP rate with target <5% aggregate

### YARA & Suricata Testing

- [ ] **S5-004** Build `src/testing/yara-tester.ts` — YARA rule testing
  - Test against sample files (synthetic + hash references)
  - Compilation check as baseline validation
  - **AC:** Reports TP/FP for each YARA rule

- [ ] **S5-005** Build `src/testing/suricata-tester.ts` — Suricata rule testing
  - Syntax validation as baseline
  - Generate sample network events for TP testing
  - **AC:** Reports TP/FP for each Suricata rule

### Benchmark Suite

- [ ] **S5-006** Build `tests/benchmark/sigmahq-comparison.test.ts` — SigmaHQ comparison
  - For overlapping techniques: compare detection logic breadth, FP handling, field usage
  - Score 1-10: completeness, precision, documentation quality
  - **AC:** Comparison table for 20+ overlapping techniques

- [ ] **S5-007** Build `tests/benchmark/coverage-metrics.test.ts` — ATT&CK coverage
  - Count unique techniques covered
  - Percentage of report TTPs with detection rules
  - Distribution across tactics (kill chain coverage)
  - Export ATT&CK Navigator JSON layer
  - **AC:** Generates coverage heat map per report

- [ ] **S5-008** Build `tests/benchmark/fp-rate-evaluation.test.ts` — FP rate measurement
  - Aggregate FP rate across benign corpus
  - Per-rule FP breakdown
  - **AC:** Target <5% aggregate FP rate

- [ ] **S5-009** Build `tests/benchmark/quality-scoring.test.ts` — overall quality metrics
  - Composite quality score per rule
  - Aggregate quality metrics per report
  - **AC:** Quality dashboard data for benchmarks doc

- [ ] **S5-010** Build `tests/integration/full-pipeline.test.ts` — end-to-end pipeline test
  - 5 real APT reports → full pipeline → validated rules
  - Measures: rules generated, validation pass rate, TP rate, FP rate, processing time, API cost
  - **AC:** All 5 reports process without errors, comprehensive test report

- [ ] **S5-011** Build `scripts/run-benchmarks.ts` — benchmark runner
  - Orchestrates all benchmark tests
  - Outputs results to `docs/BENCHMARKS.md`
  - **AC:** Single command runs all benchmarks

- [ ] **S5-012** Build `scripts/generate-test-logs.ts` — test log generation script
  - Generate comprehensive test log datasets
  - Both attack and benign samples
  - **AC:** Test data available for all rule types

---

## S6: CLI & Reporting Polish

> Full CLI experience with progress indicators, colored output, and multiple report formats.

### CLI Commands

- [ ] **S6-001** Implement `detectforge generate` command (`src/cli/commands/generate.ts`)
  - `--input` (file or URL), `--output` (directory), `--format` (sigma,yara,suricata)
  - `--sigma-only`, `--yara-only`, `--suricata-only` flags
  - `--test` flag to run validation after generation
  - `--benchmark` flag to compare against SigmaHQ
  - `--verbose` flag for detailed output
  - Progress indicators for each pipeline stage
  - **AC:** Full pipeline executes from CLI with all options

- [ ] **S6-002** Implement `detectforge extract` command (`src/cli/commands/extract.ts`)
  - `--input` (file), `--output` (JSON file)
  - Outputs structured IOCs and TTPs without rule generation
  - **AC:** Produces clean JSON extraction output

- [ ] **S6-003** Implement `detectforge validate` command (`src/cli/commands/validate.ts`)
  - `--input` (directory or file), `--format` (sigma/yara/suricata)
  - Validates existing rules against format specifications
  - Color-coded pass/fail output
  - **AC:** Validates any rule file or directory

- [ ] **S6-004** Implement `detectforge benchmark` command (`src/cli/commands/benchmark.ts`)
  - `--input` (rules directory), `--sigmahq-path` (reference rules)
  - Comparative analysis output
  - **AC:** Produces benchmark comparison report

- [ ] **S6-005** Implement `detectforge coverage` command (`src/cli/commands/coverage.ts`)
  - `--input` (rules directory), `--output` (JSON), `--navigator-layer` flag
  - ATT&CK Navigator layer export
  - Coverage heat map in terminal
  - **AC:** Generates coverage report with Navigator layer

- [ ] **S6-006** Build shared CLI options (`src/cli/options.ts`)
  - Common option definitions, validation, defaults
  - **AC:** Consistent option handling across all commands

### Report Outputs

- [ ] **S6-007** Build `src/reporting/json-reporter.ts` — JSON output
  - Machine-readable JSON with all extracted data + generated rules
  - **AC:** Valid JSON with complete pipeline data

- [ ] **S6-008** Build `src/reporting/markdown-reporter.ts` — Markdown report
  - Human-readable report with rule documentation, FP analysis, coverage
  - **AC:** Clean, readable Markdown output

- [ ] **S6-009** Build `src/reporting/sarif-reporter.ts` — SARIF output
  - SARIF format for GitHub Advanced Security / CI integration
  - **AC:** Valid SARIF JSON

- [ ] **S6-010** Build `src/reporting/attack-navigator.ts` — Navigator layer export
  - ATT&CK Navigator JSON layer with technique coloring by coverage
  - **AC:** Importable into ATT&CK Navigator web app

- [ ] **S6-011** Build `src/reporting/summary-reporter.ts` — CLI summary
  - Formatted summary table (IOCs, TTPs, rules, test results, coverage, cost)
  - Color-coded terminal output
  - **AC:** Summary table matches MASTER_PROMPT spec

---

## S7: Portfolio Polish & Documentation

> README, threat model, benchmark docs, honest metrics.

- [ ] **S7-001** Write `README.md` — portfolio-grade documentation
  - Structure: Problem → Quick Start → Demo → Architecture → Benchmarks → Supported Formats → Rule Types → Installation → Config → Testing → Limitations → Contributing → License
  - Problem-first framing (not tool-first)
  - Real benchmark numbers
  - **AC:** README explains problem, shows benchmarks, documents limitations

- [ ] **S7-002** Write `docs/ARCHITECTURE.md` — technical architecture
  - Data flow diagram (report → extraction → generation → validation → output)
  - Module dependency graph
  - AI prompt engineering decisions
  - **AC:** Clear architectural overview for code reviewers

- [ ] **S7-003** Write `docs/THREAT-MODEL.md` — threat model of DetectForge itself
  - AI hallucination risks + mitigations
  - Overly broad rule risks + mitigations
  - Missed TTP risks + mitigations
  - Poisoned input risks + mitigations
  - API key exposure risks + mitigations
  - Supply chain risks + mitigations
  - **AC:** Comprehensive threat model demonstrates security thinking

- [ ] **S7-004** Write `docs/BENCHMARKS.md` — published benchmark results
  - IOC extraction accuracy per report
  - TTP extraction accuracy per report
  - ATT&CK mapping accuracy
  - Rule validation pass rate
  - TP/FP rates
  - SigmaHQ comparison
  - Processing time and API cost per report
  - HONEST about failures
  - **AC:** Real numbers from benchmark suite, failures included

- [ ] **S7-005** Write `docs/PROMPT-ENGINEERING.md` — prompt design decisions
  - How extraction prompts were designed
  - How generation prompts were iterated
  - Lessons learned about AI rule generation
  - **AC:** Demonstrates prompt engineering expertise

- [ ] **S7-006** Write `docs/RULE-QUALITY.md` — quality standards
  - Quality scoring methodology
  - Validation criteria per format
  - FP rate thresholds
  - Coverage expectations
  - **AC:** Clear quality framework documentation

- [ ] **S7-007** Create demo GIF/screenshot of CLI processing a real report
  - Show full pipeline execution
  - **AC:** Visual demo for README

- [ ] **S7-008** Final quality gate validation
  - Run all 14 quality gates from MASTER_PROMPT
  - Document pass/fail for each
  - **AC:** All gates pass or failures documented honestly

---

## Quality Gates (from MASTER_PROMPT)

| # | Gate | Criteria | Sprint |
|---|------|----------|--------|
| 1 | Sigma Syntax | 100% valid YAML + Sigma schema | S3 |
| 2 | YARA Syntax | 100% compilation success | S3 |
| 3 | Suricata Syntax | 100% pass syntax check | S3 |
| 4 | IOC Extraction | >95% recall, >90% precision | S2 |
| 5 | TTP Extraction | >85% recall, >80% precision | S2 |
| 6 | ATT&CK Mapping | >85% correct at subtechnique level | S2 |
| 7 | True Positive Rate | >90% rules match attack logs | S5 |
| 8 | False Positive Rate | <5% aggregate FP rate | S5 |
| 9 | Documentation | Every rule has companion docs + FP analysis | S4 |
| 10 | Coverage Transparency | Gap analysis for every report | S4 |
| 11 | End-to-End | 5 real reports process without errors | S5 |
| 12 | Unit Test Coverage | >80% code coverage | S5 |
| 13 | CI/CD | All tests pass on GitHub Actions | S0+ |
| 14 | README | Problem-first, real benchmarks, honest limitations | S7 |

---

## Backlog Item Counts

| Sprint | Items | Status |
|--------|-------|--------|
| S0 | 14 | COMPLETE |
| S1 | 13 | NEXT |
| S2 | 14 | Blocked by S1 |
| S3 | 13 | Blocked by S2 |
| S4 | 7 | Blocked by S3 |
| S5 | 12 | Blocked by S3, S4 |
| S6 | 11 | Blocked by S2-S5 |
| S7 | 8 | Blocked by S5, S6 |
| **Total** | **92** | |

---

## Dependencies

```
S0 (Foundation) ─── COMPLETE
  │
  ├── S1 (Data Collection) ── NEXT
  │     │
  │     ├── S2 (Core Engine: Ingestion + Extraction)
  │     │     │
  │     │     ├── S3 (Rule Generation)
  │     │     │     │
  │     │     │     ├── S4 (Documentation Engine)
  │     │     │     │     │
  │     │     │     │     └── S5 (Testing & Benchmarks) ←── also needs S3
  │     │     │     │           │
  │     │     │     │           └── S7 (Portfolio Polish)
  │     │     │     │
  │     │     │     └── S6 (CLI & Reporting) ←── also needs S2, S4, S5
  │     │     │
  │     │     └── (feeds into S3, S4, S5, S6)
  │     │
  │     └── (feeds into S2, S5)
  │
  └── (feeds into everything)
```

---

## Notes

- **AI Provider:** OpenRouter (not direct Anthropic SDK). Three model tiers for cost control:
  - Fast: `google/gemini-2.0-flash-001` (~$0.10/M tokens)
  - Standard: `anthropic/claude-3.5-haiku` (~$0.80/M tokens)
  - Quality: `anthropic/claude-sonnet-4` (~$3.00/M tokens)
- **Cost Tracking:** Built into AI client. Track per-report API costs.
- **No Malware:** Repository contains hashes and references only, never actual samples.
- **Honest Metrics:** Publish failures alongside successes in benchmarks.
