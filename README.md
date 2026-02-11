# DetectForge

> AI-Powered Detection Rule Generation from Threat Intelligence Reports

DetectForge is an end-to-end pipeline that transforms threat intelligence reports (PDF, HTML, Markdown) into validated detection rules for Sigma (SIEM), YARA (file-based), and Suricata (network IDS). It uses AI to extract IOCs, identify TTPs, map to MITRE ATT&CK, generate rules, and then validates, quality-scores, and documents every output -- reducing the detection engineering cycle from hours to minutes.

---

## The Problem

Security operations teams receive dozens of threat intelligence reports weekly from sources like Mandiant, CrowdStrike, Unit 42, and CISA. Each report contains actionable intelligence, but converting it into operational detections is a manual, labor-intensive process: reading the report, extracting IOCs, mapping TTPs to ATT&CK, writing rules for multiple formats (Sigma, YARA, Suricata), validating syntax, documenting coverage, and testing for false positives. This typically takes **6-14 hours of skilled labor per report**. Most SOC teams carry a backlog of 50-100+ reports they have never operationalized. Threat actors evolve faster than defenders can write rules. The result is a strategic vulnerability: teams know about threats but cannot detect them.

## How DetectForge Solves It

DetectForge automates the full detection engineering workflow in a single CLI command:

```
Threat Report (PDF/HTML/MD)
        |
        v
  [1] INGESTION       Parse and normalize report text, classify sections
        |
        v
  [2] EXTRACTION       Extract IOCs (regex) + TTPs (AI) + ATT&CK mapping (AI)
        |
        v
  [3] GENERATION       Generate Sigma, YARA, and Suricata rules via AI
        |
        v
  [4] VALIDATION       Validate syntax and schema for every generated rule
        |
        v
  [5] ENRICHMENT       AI-generated documentation, FP analysis, coverage gaps
        |
        v
  [6] TESTING          Quality scoring, Sigma rule testing engine, FP evaluation
        |
        v
  [7] REPORTING        JSON, Markdown, SARIF, ATT&CK Navigator layer output
```

**Value proposition:** Drop in a threat report. Get validated, documented, ATT&CK-mapped detection rules with quality scores and coverage gap analysis -- ready for review and deployment.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/Sim-Security/DetectForge.git
cd DetectForge
bun install
cp .env.example .env
# Add your OpenRouter API key to .env

# Generate rules from a threat report
bun run dev generate --input report.pdf --output ./rules/

# Extract IOCs and TTPs only (no rule generation)
bun run dev extract --input report.pdf --output extracted.json

# Validate existing detection rules
bun run dev validate --input ./rules/ --format sigma

# Quality benchmark generated rules
bun run dev benchmark --input ./rules/

# ATT&CK technique coverage analysis
bun run dev coverage --input ./rules/ --navigator-layer
```

---

## Architecture

```mermaid
flowchart TD
    subgraph Input
        PDF[PDF Report]
        HTML[HTML Report]
        MD[Markdown Report]
        TXT[Plaintext Report]
    end

    subgraph Ingestion["1. Ingestion"]
        Parser[Format-Specific Parser]
        Normalizer[Report Normalizer]
        Classifier[Section Classifier]
    end

    subgraph Extraction["2. Extraction"]
        IOC[IOC Extractor<br/><i>Regex + Defanging</i>]
        TTP[TTP Extractor<br/><i>AI - Fast/Standard tier</i>]
        ATT[ATT&CK Mapper<br/><i>AI + Validation</i>]
    end

    subgraph Generation["3. Generation"]
        SG[Sigma Generator<br/><i>AI - Quality tier</i>]
        YG[YARA Generator<br/><i>AI - Quality tier</i>]
        SUG[Suricata Generator<br/><i>AI - Quality tier</i>]
    end

    subgraph Validation["4. Validation"]
        SV[Sigma Validator]
        YV[YARA Validator]
        SUV[Suricata Validator]
    end

    subgraph Enrichment["5. Enrichment"]
        DOC[Documentation<br/><i>AI</i>]
        FPA[FP Analyzer<br/><i>AI</i>]
        GAP[Gap Analyzer<br/><i>AI</i>]
    end

    subgraph Testing["6. Testing"]
        QS[Quality Scorer<br/><i>Heuristic</i>]
        ST[Sigma Tester]
        FPE[FP Evaluator]
        CM[Coverage Metrics]
    end

    subgraph Output["7. Reporting"]
        JSON[JSON Report]
        MKD[Markdown Report]
        SARIF[SARIF Report]
        NAV[ATT&CK Navigator Layer]
        RULES[Rule Files<br/>.yml .yar .rules]
    end

    PDF & HTML & MD & TXT --> Parser --> Normalizer --> Classifier
    Classifier --> IOC & TTP
    TTP --> ATT
    IOC & TTP & ATT --> SG & YG & SUG
    SG --> SV
    YG --> YV
    SUG --> SUV
    SV & YV & SUV --> DOC & FPA & GAP
    DOC & FPA & GAP --> QS & ST & FPE & CM
    QS & ST & FPE & CM --> JSON & MKD & SARIF & NAV & RULES
```

### Pipeline Stages

| Stage | Module | Description |
|-------|--------|-------------|
| **Ingestion** | `src/ingestion/` | Parse PDF, HTML, Markdown, and plaintext reports into a normalized `ThreatReport` structure with classified sections |
| **IOC Extraction** | `src/extraction/ioc-extractor.ts` | Regex-based extraction of 12+ IOC types including defanged variants (hxxp, [.], [@]); context-aware deduplication |
| **TTP Extraction** | `src/extraction/ttp-extractor.ts` | AI-powered behavioral pattern identification with tools, artifacts, platforms, and detection opportunities |
| **ATT&CK Mapping** | `src/extraction/attack-mapper.ts` | AI maps TTPs to specific ATT&CK technique IDs (preferring subtechniques); cross-validated against ATT&CK dataset |
| **Sigma Generation** | `src/generation/sigma/` | Template-driven AI generation with 10+ logsource categories, field constraints, and example-guided prompts |
| **YARA Generation** | `src/generation/yara/` | AI generates file-based rules with string patterns, hex sequences, conditions, and magic byte constraints |
| **Suricata Generation** | `src/generation/suricata/` | AI generates network rules with protocol-specific keywords, sticky buffers, and SID management |
| **Validation** | `src/generation/*/validator.ts` | Format-specific syntax and schema validation for every generated rule |
| **Documentation** | `src/generation/documentation.ts` | AI generates SOC analyst-facing documentation: what it detects, how, FPs, gaps, tuning advice |
| **FP Analysis** | `src/generation/false-positive-analyzer.ts` | AI identifies 3-7 specific false positive scenarios per rule with actionable tuning guidance |
| **Gap Analysis** | `src/generation/coverage-gap-analyzer.ts` | AI evaluates uncovered TTPs, evasion vectors, log source gaps, and coverage percentages |
| **Quality Scoring** | `src/testing/quality-scorer.ts` | Heuristic scoring (1-10) across 5 dimensions: syntax, logic, docs, ATT&CK mapping, FP handling |
| **Testing** | `src/testing/sigma-tester.ts` | Sigma rule testing engine with synthetic log generation and TP/FP rate evaluation |
| **Reporting** | `src/reporting/` | JSON, Markdown, SARIF (CI integration), and ATT&CK Navigator layer output |

---

## Supported Rule Formats

### Sigma Rules (SIEM)
- Full YAML schema compliance with structural validation
- 10+ logsource category templates: `process_creation`, `network_connection`, `dns_query`, `file_event`, `registry_event`, `image_load`, and more
- Detection blocks with named selections, filters, and boolean conditions
- ATT&CK tags in standard format (`attack.t1059.001`, `attack.execution`)
- False positive annotations and severity levels
- Field-constrained generation -- the AI can only use fields valid for each logsource

### YARA Rules (File/Malware)
- Text, hex, and regex string patterns with modifiers (`ascii`, `wide`, `nocase`, `fullword`, `xor`, `base64`)
- Magic byte checks for file type identification (PE, ELF, OLE, ZIP)
- Filesize constraints for scan performance
- Condition complexity with `N of ($s*)` patterns
- Full meta section: description, author, date, reference, mitre_attack, hash

### Suricata Rules (Network IDS)
- Protocol-specific detection: HTTP, DNS, TLS, TCP, UDP
- Sticky buffer keywords: `dns.query`, `http.uri`, `http.host`, `tls.sni`, `http.user_agent`
- Flow directives for TCP state awareness
- SID management in the 9000000-9999999 range
- Classtype classification and metadata tagging
- PCRE regex support for complex pattern matching

---

## CLI Commands

| Command | Description | Key Options |
|---------|-------------|-------------|
| `detectforge generate` | Full pipeline: report to rules | `--input`, `--output`, `--format`, `--model`, `--test`, `--verbose` |
| `detectforge extract` | IOC/TTP extraction only | `--input`, `--output`, `--model` |
| `detectforge validate` | Validate existing rules | `--input`, `--format` (auto-detect or explicit) |
| `detectforge benchmark` | Quality scoring | `--input`, `--sigmahq-path` |
| `detectforge coverage` | ATT&CK coverage analysis | `--input`, `--output`, `--navigator-layer` |

### Model Tiers

| Tier | Use Case | Default Model |
|------|----------|---------------|
| `fast` | IOC extraction, classification | `google/gemini-2.0-flash-001` |
| `standard` | General tasks, TTP extraction | `anthropic/claude-3.5-haiku` |
| `quality` | Rule generation, complex reasoning | `anthropic/claude-sonnet-4` |

Select with `--model fast|standard|quality`. All tiers route through OpenRouter for cost-efficient model selection.

---

## Output Formats

| Format | File Extension | Use Case |
|--------|---------------|----------|
| **Sigma YAML** | `.yml` | SIEM-agnostic detection rules (Splunk, Elastic, Microsoft Sentinel, etc.) |
| **YARA** | `.yar` | File-based and memory-based malware detection |
| **Suricata** | `.rules` | Network IDS/IPS rules |
| **JSON Report** | `.json` | Machine-readable pipeline output with full metadata |
| **Markdown Report** | `.md` | Human-readable analysis and rule documentation |
| **SARIF** | `.sarif` | GitHub Advanced Security / CI pipeline integration |
| **ATT&CK Navigator Layer** | `.json` | Visual technique coverage overlay at mitre-attack.github.io/attack-navigator |

---

## Quality Assurance

### Test Suite
- **51 test files** across unit, integration, and benchmark categories
- **1,617 passing tests** covering every module: parsers, extractors, generators, validators, prompts, reporters, knowledge bases, and utilities
- **80% code coverage thresholds** enforced across branches, functions, lines, and statements

### Quality Scoring
Every generated rule is scored on a 1-10 scale across five weighted dimensions:

| Dimension | Weight | What It Measures |
|-----------|--------|------------------|
| Syntax Validity | 25% | Passes format-specific validation with no errors or warnings |
| Detection Logic | 30% | Number of detection patterns, condition complexity, field specificity |
| Documentation | 15% | Completeness of what-it-detects, how-it-works, tuning recommendations |
| ATT&CK Mapping | 15% | Valid technique ID format, tactic association, technique name |
| FP Handling | 15% | Number of FP scenarios, tuning advice quality, coverage gap identification |

### Validation Pipeline
- **Sigma:** YAML parse, required fields (title, logsource, detection, condition, level), valid field names, tag format
- **YARA:** Rule structure (meta, strings, condition), string identifier format, hex pattern validity, condition syntax
- **Suricata:** Rule header format, required keywords (msg, sid, rev), content string syntax, SID range checks

---

## Testing

```bash
bun run test              # Run all tests
bun run test:unit         # Unit tests only
bun run test:integration  # Integration tests
bun run test:coverage     # Coverage report with V8 provider
bun run test:watch        # Watch mode during development
```

---

## Configuration

```bash
# .env (copy from .env.example)
OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxxxxxxxxxx

# Model tiers — customize for cost/quality tradeoff
OPENROUTER_MODEL_FAST=google/gemini-2.0-flash-001
OPENROUTER_MODEL_STANDARD=anthropic/claude-3.5-haiku
OPENROUTER_MODEL_QUALITY=anthropic/claude-sonnet-4

# Optional: Direct Anthropic API
# ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxx

# Logging and cost tracking
LOG_LEVEL=info
TRACK_API_COSTS=true
```

Cost tracking is built in. Every API call logs input/output tokens, model used, and cost estimate. The generate command prints a summary:

```
  API cost:        $0.0234
  Total tokens:    12,847
  Duration:        8.3s
```

---

## Limitations

This section is intentionally honest -- these are real constraints, not disclaimers:

- **Rule quality depends on AI model capability.** AI-generated rules are a starting point, not production-ready detections. Always have a human detection engineer review before deploying. The quality scorer helps identify weak rules, but it cannot replace domain expertise.
- **Complex multi-stage attacks may not be fully captured.** The pipeline processes each TTP independently. Kill chain correlations and multi-step attack sequences require manual synthesis.
- **YARA and Suricata validation is simulated.** Rules are validated structurally (syntax, required fields, pattern format) but not compiled against actual YARA/Suricata engines. Sigma validation is the most thorough.
- **False positive rates are based on synthetic logs, not production data.** The FP analysis uses AI assessment and heuristic scoring. Real-world FP rates will vary by environment and require tuning.
- **Requires an OpenRouter API key (paid service).** AI inference costs are transparent (tracked per-call), but the tool does require API access. Typical cost per report is $0.01-0.10 depending on model tier and report length.
- **STIX and raw JSON ingestion are not yet implemented.** The normalizer currently supports PDF, HTML, Markdown, and plaintext. STIX/JSON parsers are planned but not yet built.

---

## Project Structure

```
src/
  ai/
    client.ts                    # OpenRouter AI client with 3-tier model selection
    response-parser.ts           # JSON extraction + Zod schema validation
    retry.ts                     # Exponential backoff with jitter
    prompts/
      ioc-extraction.ts          # IOC extraction + disambiguation prompts
      ttp-extraction.ts          # TTP extraction + ATT&CK mapping prompts
      sigma-generation.ts        # Sigma rule generation prompts + Zod schema
      yara-generation.ts         # YARA rule generation prompts + Zod schema
      suricata-generation.ts     # Suricata rule generation prompts + Zod schema
      documentation.ts           # Rule documentation prompts + Zod schema
      fp-analysis.ts             # False positive analysis prompts + Zod schema
      gap-analysis.ts            # Coverage gap analysis prompts + Zod schema
  cli/
    index.ts                     # CLI entry point (Commander.js)
    options.ts                   # Shared option helpers and path resolution
    commands/
      generate.ts                # Full pipeline command
      extract.ts                 # IOC/TTP extraction command
      validate.ts                # Rule validation command
      benchmark.ts               # Quality scoring command
      coverage.ts                # ATT&CK coverage analysis command
  ingestion/
    normalizer.ts                # Format detection + parser delegation
    parsers/
      pdf.ts                     # PDF parsing (pdf-parse)
      html.ts                    # HTML parsing (cheerio)
      markdown.ts                # Markdown section parsing
      plaintext.ts               # Plaintext parsing
  extraction/
    ioc-extractor.ts             # Regex-based IOC extraction (12+ types, defanged support)
    ioc-enrichment.ts            # IOC deduplication, classification, confidence adjustment
    ttp-extractor.ts             # AI-powered TTP extraction
    attack-mapper.ts             # AI-powered ATT&CK technique mapping
  generation/
    documentation.ts             # AI-generated rule documentation
    false-positive-analyzer.ts   # AI-powered FP scenario analysis
    coverage-gap-analyzer.ts     # AI-powered coverage gap analysis
    sigma/
      generator.ts               # Sigma rule generation orchestrator
      templates.ts               # 10+ logsource category templates with field constraints
      validator.ts               # Sigma YAML syntax + schema validator
    yara/
      generator.ts               # YARA rule generation orchestrator
      templates.ts               # File category templates (PE, ELF, script, etc.)
      validator.ts               # YARA syntax + structure validator
    suricata/
      generator.ts               # Suricata rule generation orchestrator
      templates.ts               # Protocol-specific templates (HTTP, DNS, TLS, etc.)
      validator.ts               # Suricata rule syntax + keyword validator
  knowledge/
    mitre-attack/
      loader.ts                  # ATT&CK Enterprise JSON loader
      techniques.ts              # Technique/subtechnique lookup
      datasources.ts             # Data source to technique mapping
    sigma-reference/
      loader.ts                  # SigmaHQ rule corpus loader
      quality-scorer.ts          # Reference-based quality comparison
    logsource-catalog/
      index.ts                   # Logsource registry
      windows.ts                 # Windows logsource definitions
      linux.ts                   # Linux logsource definitions
      sysmon.ts                  # Sysmon-specific logsource definitions
  testing/
    quality-scorer.ts            # 5-dimension heuristic quality scoring
    sigma-tester.ts              # Sigma rule testing engine
    yara-tester.ts               # YARA rule testing engine
    suricata-tester.ts           # Suricata rule testing engine
    log-generator.ts             # Synthetic attack/benign log generation
    fp-evaluator.ts              # False positive rate evaluation
    coverage-metrics.ts          # ATT&CK coverage calculation + Navigator export
  reporting/
    json-reporter.ts             # Machine-readable JSON pipeline report
    markdown-reporter.ts         # Human-readable Markdown report
    sarif-reporter.ts            # SARIF output for CI integration
    attack-navigator.ts          # ATT&CK Navigator layer generation
    summary-reporter.ts          # Terminal summary table
  types/
    threat-report.ts             # ThreatReport, ReportSection, InputFormat
    extraction.ts                # ExtractedIOC, ExtractedTTP, AttackMappingResult
    detection-rule.ts            # SigmaRule, YaraRule, SuricataRule, GeneratedRule
    mitre-attack.ts              # AttackTechnique, AttackTactic, CoverageReport
    config.ts                    # DetectForgeConfig, AIConfig, APIUsage
  utils/
    defang.ts                    # IOC defanging/refanging utilities
    hash.ts                      # Hash type detection (MD5, SHA1, SHA256)
    network.ts                   # IP/domain/email validation helpers
    logger.ts                    # Structured logging
    yaml.ts                      # YAML serialization helpers
tests/
  unit/                          # 50 unit test files covering every module
  integration/                   # End-to-end pipeline tests
  benchmark/                     # Performance benchmarks
```

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Runtime | Bun | Fast TypeScript execution without compilation step |
| Language | TypeScript (ES2022 strict) | Type safety with strict mode, path aliases, source maps |
| CLI Framework | Commander.js | Command parsing, option registration, help generation |
| AI Inference | OpenRouter API | Cost-efficient access to multiple LLM providers |
| Schema Validation | Zod | Runtime validation of all AI responses against typed schemas |
| PDF Parsing | pdf-parse | Extract text from PDF threat reports |
| HTML Parsing | cheerio | Server-side DOM manipulation for HTML report parsing |
| YAML | yaml | Sigma rule serialization/deserialization |
| Test Framework | Vitest | Fast test runner with V8 coverage and watch mode |
| Output | chalk + ora | Terminal styling and progress spinners |

---

## License

MIT

## Author

Built by [Adam](https://github.com/Sim-Security) as a detection engineering portfolio project demonstrating the intersection of AI, security automation, and software engineering.
