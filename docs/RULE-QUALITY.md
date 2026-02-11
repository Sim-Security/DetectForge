# Rule Quality Standards and Scoring Methodology

## Why Quality Scoring Matters

Detection rules sit at the boundary between threat intelligence and operational
security. A rule that fires on every build server is worse than no rule at all
-- it trains analysts to ignore alerts. A rule that misses the exact technique
described in a threat report gives a false sense of coverage. Both failure modes
erode SOC trust.

DetectForge scores every generated rule across five measurable dimensions so
that operators know, before deployment, how much confidence to place in each
detection. The scoring is entirely heuristic-based and runs locally with no AI
calls, which means it can gate CI pipelines, filter low-quality output during
batch generation, and feed back into the generation loop for iterative
improvement.

The goals are concrete:

- **Reduce false positives.** Rules with narrow, well-documented logic
  generate fewer tickets that waste analyst time.
- **Reduce false negatives.** Rules with rich detection patterns and broad
  condition logic are harder for adversaries to evade with minor variations.
- **Ensure operational readiness.** Rules with complete documentation, ATT&CK
  mapping, and tuning guidance can be deployed by a SOC that did not write them.

---

## The 5-Dimension Scoring Model

Every rule receives a score from 1 to 10 on each of five dimensions. These
dimension scores are combined into a single overall score using a weighted
average:

| Dimension               | Weight |
|-------------------------|--------|
| Syntax Validity         | 0.25   |
| Detection Logic         | 0.30   |
| Documentation           | 0.15   |
| ATT&CK Mapping          | 0.15   |
| False Positive Handling | 0.15   |

Detection logic carries the highest weight because a rule that cannot detect
the threat is useless regardless of how well it is documented. Syntax validity
is second because a rule that does not parse never fires at all. The remaining
three dimensions share equal weight and address operational concerns.

The overall score is clamped to the range 1--10 after rounding to one decimal
place.

### 1. Syntax Validity (weight: 0.25)

**What it measures.** Whether the rule will parse and load without errors in
its target engine (Sigma backend, YARA compiler, Suricata).

**How it is scored.** The dimension starts at 10 and applies two deductions:

- Each validation **error** subtracts **2 points** (e.g., missing required
  field, invalid UUID, unbalanced braces).
- Each validation **warning** subtracts **1 point** (e.g., missing author,
  unquoted content value, unknown logsource combination).

The result is clamped to a floor of 1.

**Why it matters.** A syntax error means the rule cannot load. Even a single
error drops the score to 8 at best, signaling that the rule needs a fix before
deployment. Warnings flag issues that will not block loading but may cause
unexpected behavior or reduce portability.

### 2. Detection Logic (weight: 0.30)

**What it measures.** The specificity and resilience of the rule's matching
logic -- how many patterns it inspects and how complex the condition logic is.

**How it is scored.** Scoring starts at a baseline of **5** and adds or
subtracts points based on format-specific heuristics:

**Sigma rules:**

- Count detection selections (keys in the `detection` block excluding
  `condition`). Three or more selections: **+3**. Two: **+2**. One: **+1**.
- Count logical operators in the condition string (`and`, `or`, `not`,
  `selection`, `filter`, `any of`, `all of`, `for any`, `for all`, `1 of`).
  Two or more operators: **+1**.

**YARA rules:**

- Count defined strings. Five or more: **+3**. Three or four: **+2**. Two:
  **+1**. Zero strings: **-2**.
- Count condition operators (same keyword set as above). Three or more: **+2**.
  One or two: **+1**.

**Suricata rules:**

- Count `content` and `pcre` options. Three or more: **+3**. Two: **+2**.
  One: **+1**. Zero: **-2**.
- Presence of a `flow` option: **+1** (constrains the rule to established
  sessions, reducing noise).

The result is clamped to 1--10. A perfectly specific YARA rule with five
strings and a complex condition can reach 10; a Suricata rule with no content
matches scores 3.

**Why it matters.** Rules with a single broad pattern are trivially evaded.
Multiple independent indicators combined with logical operators force an
adversary to change many aspects of their tooling simultaneously.

### 3. Documentation (weight: 0.15)

**What it measures.** Whether the rule ships with enough context for a SOC
analyst to triage, tune, and maintain it without reverse-engineering the logic.

**How it is scored.** DetectForge checks for the presence and non-emptiness of
seven documentation fields:

1. `whatItDetects` -- plain-language description of the threat behavior.
2. `howItWorks` -- explanation of the detection mechanism.
3. `attackMapping` -- structured ATT&CK technique reference (must contain at
   least a non-empty `techniqueId`).
4. `falsePositives` -- list of known FP scenarios.
5. `coverageGaps` -- acknowledged blind spots.
6. `recommendedLogSources` -- data sources the rule depends on.
7. `tuningRecommendations` -- guidance for adapting the rule to a specific
   environment.

The score is the ratio of populated fields to total fields, scaled to 1--10.
All seven fields populated yields a 10. No documentation object at all yields
a 1.

**Why it matters.** The number one reason detection rules rot in production is
that nobody remembers what they do. Complete documentation is a prerequisite
for sustainable detection engineering.

### 4. ATT&CK Mapping (weight: 0.15)

**What it measures.** Whether the rule is anchored to the MITRE ATT&CK
framework with a valid technique identifier and tactic context.

**How it is scored.** The dimension starts at **1** and builds up:

- Valid technique ID matching `T\d{4}` or `T\d{4}.\d{3}`: **+4**.
  Partially valid (starts with `T` but malformed): **+2**.
- Non-empty tactic string: **+3**.
- Documentation `attackMapping` contains a `techniqueName`: **+1**.
- Documentation `attackMapping` contains a `platform`: **+1**.

Maximum reachable: 10. A rule with no technique ID and no tactic scores 1.

**Why it matters.** ATT&CK mapping is how organizations measure detection
coverage against known adversary behavior. Rules without valid mappings
cannot feed coverage dashboards, gap analyses, or purple team exercises.

### 5. False Positive Handling (weight: 0.15)

**What it measures.** How thoroughly the rule anticipates and documents
scenarios that would produce benign alerts, and whether it provides actionable
tuning guidance.

**How it is scored.** Starts at **1** and accumulates points:

- **FP scenario count.** Three or more documented scenarios: **+4**. Two:
  **+3**. One: **+2**.
- **Tuning advice ratio.** For each documented scenario that includes a
  non-empty `tuningAdvice` field, a proportional bonus up to **+3** is
  awarded (`Math.round(tuningRatio * 3)` where `tuningRatio` is the fraction
  of scenarios with tuning advice).
- **Document-level tuning recommendations** (non-empty
  `tuningRecommendations` array): **+1**.
- **Coverage gaps identified** (non-empty `coverageGaps` array): **+1**.

Maximum reachable: 10. A rule with no documentation object scores 1.

**Why it matters.** False positives are the operational cost of detection. A
rule that documents three realistic FP scenarios with specific tuning advice
(e.g., "exclude `svchost.exe` launched by `services.exe`") saves hours of
analyst time during the first week of deployment.

---

## Score Interpretation

### Score 1--3: Needs Significant Improvement

Rules in this range have fundamental problems. They may fail to parse, lack
any detection logic beyond a single trivial pattern, or ship with no
documentation at all. These rules should not be deployed without manual review
and rework. The quality report flags them explicitly:

> *"N rule(s) scored 3 or below and need immediate attention."*

Common causes: generation from vague threat descriptions, incomplete ATT&CK
data, or AI responses that could not be parsed into complete rule structures.

### Score 4--6: Acceptable with Room for Improvement

Rules that parse correctly and have reasonable detection logic but are missing
one or more operational dimensions -- typically documentation, ATT&CK mapping,
or FP handling. These rules can be deployed in test or experimental status but
should go through the quality improvement pipeline (documentation engine, FP
analyzer, coverage gap analyzer) before production use.

### Score 7--10: High Quality, Production-Ready

Rules with strong detection logic, clean syntax, complete documentation, valid
ATT&CK mapping, and documented false positive scenarios. The quality report
describes them as:

> *"High quality rule with strong detection logic."*

A score of 8+ indicates the rule is ready for production deployment. A score
of 10 is rare and indicates that every dimension is fully satisfied.

---

## Per-Format Quality Checks

Each detection format has a dedicated validator that runs before quality
scoring. Validation errors directly reduce the syntax validity dimension.

### Sigma Validation

Source: `src/generation/sigma/validator.ts`

The Sigma validator checks both structured `SigmaRule` objects and raw YAML
strings. For structured rules:

| Check                        | Severity | Details                                                                                       |
|------------------------------|----------|-----------------------------------------------------------------------------------------------|
| Required fields              | Error    | `title`, `id`, `status`, `description`, `logsource`, `detection`, `level` must be present.    |
| UUID v4 format               | Error    | The `id` field must match RFC 4122 UUID v4 (`/^[0-9a-f]{8}-...-4.../i`).                     |
| Valid status                 | Error    | Must be one of: `experimental`, `test`, `stable`, `deprecated`, `unsupported`.                |
| Valid level                  | Error    | Must be one of: `informational`, `low`, `medium`, `high`, `critical`.                         |
| Logsource completeness       | Error    | Must have at least `product` or `category`.                                                   |
| Logsource catalog lookup     | Warning  | Product/category/service combination is checked against the DetectForge logsource catalog.    |
| Detection condition          | Error    | `detection` must contain a string `condition` field.                                          |
| Condition reference validity | Error    | Every identifier in the condition must exist as a key in the detection block.                  |
| ATT&CK tag format            | Warning  | Tags starting with `attack.` must match `attack.tXXXX` or `attack.tactic_name`.              |
| Missing tags                 | Warning  | Rules with no tags at all receive a warning.                                                  |
| Missing date                 | Warning  | Absence of a `date` field.                                                                    |
| Missing author               | Warning  | Absence of an `author` field.                                                                 |
| Missing false positives      | Warning  | No `falsepositives` entries documented.                                                       |

For raw YAML, the validator first confirms the string is parseable YAML, then
delegates to the structural checks above.

### YARA Validation

Source: `src/generation/yara/validator.ts`

The YARA validator checks both structured `YaraRule` objects and raw rule text.
For structured rules:

| Check                        | Severity | Details                                                                                       |
|------------------------------|----------|-----------------------------------------------------------------------------------------------|
| Rule name                    | Error    | Must match `/^[a-zA-Z_][a-zA-Z0-9_]*$/`.                                                     |
| Required meta fields         | Error    | `description`, `author`, `date` must be present and non-empty.                                |
| Date format                  | Warning  | `date` should use `YYYY-MM-DD` format.                                                        |
| At least one string          | Error    | The `strings` section must contain at least one definition.                                    |
| String identifier format     | Error    | Must match `$` followed by a valid identifier.                                                |
| Duplicate identifiers        | Error    | No two strings may share the same `$name`.                                                    |
| Non-empty string value       | Error    | Each string must have a non-empty value.                                                      |
| Valid string type             | Error    | Must be `text`, `hex`, or `regex`.                                                            |
| Hex string characters        | Error    | Hex bodies may only contain `0-9`, `A-F`, spaces, `??`, `[]`, `-`, `()`, and `\|`.            |
| Text string modifiers        | Warning  | Only `ascii`, `wide`, `nocase`, `fullword`, `xor`, `base64`, `base64wide`, `private` allowed. |
| Non-empty condition          | Error    | The condition section must not be empty.                                                      |
| Condition references         | Warning  | `$`-prefixed identifiers in the condition must correspond to defined strings.                  |
| Tag format                   | Warning  | Tags should be simple alphanumeric identifiers.                                               |

For raw text, a lightweight plausibility check verifies presence of `rule`,
`meta:`, `strings:`, and `condition:` sections; balanced curly braces; valid
rule name; at least one `$identifier` in the strings section; and non-empty
condition content.

### Suricata Validation

Source: `src/generation/suricata/validator.ts`

The Suricata validator checks structured `SuricataRule` objects, raw rule text,
and entire rule sets (batch duplicate detection).

**Structured rule checks:**

| Check                  | Severity | Details                                                                                     |
|------------------------|----------|---------------------------------------------------------------------------------------------|
| Action                 | Error    | Must be one of: `alert`, `pass`, `drop`, `reject`, `rejectsrc`, `rejectdst`, `rejectboth`. |
| Protocol               | Error    | Must be a recognized Suricata protocol (22 supported, including app-layer protocols).       |
| Source/Dest IP         | Error    | Must be a valid variable (`$HOME_NET`, etc.), IPv4, IPv6, CIDR, negation, or group.         |
| Source/Dest Port       | Error    | Must be `any`, a variable, a port number (0--65535), a range, negation, or group.           |
| Direction              | Error    | Must be `->` or `<>`.                                                                       |
| Required `msg` option  | Error    | The options array must contain a `msg` keyword.                                             |
| SID range              | Error    | SID must be an integer between 1 and 9,999,999.                                            |
| Revision               | Error    | `rev` must be a positive integer.                                                           |
| SID/rev consistency    | Warning  | SID and rev in the options array must match the top-level `sid` and `rev` fields.           |
| Content quoting        | Warning  | `content` values should be enclosed in double quotes.                                       |

**Raw text checks** additionally verify the 7-part header format
(`action protocol src_ip src_port direction dest_ip dest_port`), the presence
of a parenthesized options block, and that the options block ends with a
semicolon.

**Rule set checks** validate each rule individually, then scan for duplicate
SIDs across the entire set.

---

## Common Quality Issues

The following patterns consistently reduce quality scores. Awareness of these
anti-patterns helps both rule authors and the AI generation pipeline produce
better output.

**Overly broad detection logic (Detection Logic: low).** A Sigma rule with a
single selection containing one field match, or a Suricata rule with no
`content` keywords, is nearly guaranteed to produce false positives in
production. The detection logic scorer penalizes rules with zero or one
pattern and rewards rules with three or more independent indicators.

**Missing false positive documentation (FP Handling: low).** Rules that ship
with zero FP scenarios score 1 on the false positive handling dimension. Even
a single documented scenario with tuning advice raises the score to 4. The
most common omission is failing to consider legitimate administrative tools
that produce identical telemetry.

**Invalid or missing ATT&CK technique IDs (ATT&CK Mapping: low).** A
technique ID of "T1059" scores full credit; "T1059.001" scores full credit;
"TA0001" (a tactic ID used where a technique ID is expected) scores only
partial credit. Missing technique IDs entirely result in a score of 1.

**Incomplete documentation (Documentation: low).** The seven documentation
fields are scored proportionally. Rules that have `whatItDetects` and
`howItWorks` but skip `coverageGaps`, `recommendedLogSources`, and
`tuningRecommendations` will plateau around 4/10.

**Condition references to non-existent selections (Syntax Validity: low).**
Sigma rules where the condition string references `selection_network` but the
detection block only defines `selection` produce a validation error that costs
2 points on syntax validity.

**Unquoted Suricata content values (Syntax Validity: reduced).** Content
keywords without double quotes generate a warning, costing 1 point on syntax
validity. While some Suricata engines tolerate this, it is not portable.

**Zero strings in YARA rules (Detection Logic: reduced).** A YARA rule that
relies entirely on file size or entry point checks with no string patterns is
penalized by -2 on the detection logic dimension.

---

## Quality Improvement Pipeline

DetectForge does not just score quality -- it provides three AI-powered
analyzers that systematically improve rule quality before final output.

### Documentation Engine

Source: `src/generation/documentation.ts`

The documentation engine takes a `GeneratedRule` and produces a comprehensive
`RuleDocumentation` object by sending the rule content to an AI model through
a structured prompt. The AI analyzes the rule and generates all seven
documentation fields:

- What the rule detects (plain language)
- How the detection mechanism works
- ATT&CK technique mapping with technique name and platform
- False positive scenarios
- Coverage gaps and blind spots
- Recommended log sources
- Tuning recommendations for environment-specific adaptation

The engine uses `withRetry` for resilience against transient API failures and
the `standard` model tier by default. The returned documentation is parsed and
validated before being attached to the rule, directly boosting the
Documentation, ATT&CK Mapping, and False Positive Handling dimension scores.

### False Positive Analyzer

Source: `src/generation/false-positive-analyzer.ts`

The FP analyzer is a dedicated pipeline that goes deeper than the
documentation engine on false positive analysis. It uses a SOC analyst persona
prompt to evaluate the rule and produces:

- **Individual FP scenarios** -- each with a description, likelihood rating
  (`high`, `medium`, `low`), and specific tuning advice.
- **Overall FP risk assessment** -- a single `high`/`medium`/`low` rating for
  the rule as a whole.
- **Recommendations** -- general guidance for improving the signal-to-noise
  ratio.

Configuration options include model tier, max retries (default: 3), max tokens
(default: 2048), and sampling temperature (default: 0.3 -- low temperature for
deterministic, focused analysis). The validated output maps directly to
`FalsePositiveScenario` objects that populate the rule's documentation and
improve the FP Handling dimension score.

### Coverage Gap Analyzer

Source: `src/generation/coverage-gap-analyzer.ts`

The coverage gap analyzer operates at the rule-set level rather than on
individual rules. It takes all generated rules alongside extracted TTPs and
ATT&CK mappings and produces a comprehensive gap analysis:

- **Uncovered TTPs** -- techniques from the threat report that could not be
  translated into rules, with reasons and alternative detection approaches.
- **Evasion vectors** -- specific techniques that would bypass existing rules,
  with mitigation suggestions.
- **Log source gaps** -- data sources required for detection that may be
  unavailable in the target environment.
- **Overall coverage statistics** -- covered technique count, total technique
  count, coverage percentage, strongest tactic, and weakest tactic.
- **Prioritized recommendations** -- ordered list of actions to improve
  detection coverage.

This analyzer defaults to the `quality` model tier (higher reasoning
capability) because gap analysis requires cross-referencing multiple rules
against the full ATT&CK matrix. Its output feeds back into the rule
documentation as `coverageGaps` entries, improving both the Documentation and
FP Handling dimension scores.

### Pipeline Effect on Scores

Running all three analyzers on a rule set typically lifts quality scores as
follows:

| Dimension               | Before pipeline | After pipeline |
|-------------------------|-----------------|----------------|
| Syntax Validity         | No change       | No change      |
| Detection Logic         | No change       | No change      |
| Documentation           | 1--3            | 7--10          |
| ATT&CK Mapping          | 3--5            | 7--10          |
| False Positive Handling | 1--3            | 6--9           |

The pipeline does not modify detection logic or fix syntax errors -- those
dimensions depend on the quality of the initial AI generation and the
format-specific validators. However, the three documentation-oriented
dimensions can be fully populated through the pipeline, lifting a typical
overall score from ~4 to ~7.

---

## Comparison to Industry Standards

### SigmaHQ Community Rules

The SigmaHQ repository is the de facto standard for community Sigma rules.
DetectForge's quality model was designed to meet or exceed SigmaHQ standards
on several axes:

**Schema compliance.** SigmaHQ requires `title`, `id` (UUID), `status`,
`description`, `logsource`, `detection`, and `level`. DetectForge's Sigma
validator enforces the same required fields and additionally validates UUID v4
format, status/level enum values, and condition-to-selection reference
integrity.

**Logsource validation.** SigmaHQ relies on manual review and CI linting for
logsource validity. DetectForge validates logsource combinations against a
built-in catalog, catching non-standard product/category/service triples that
would fail backend conversion.

**ATT&CK tagging.** SigmaHQ rules use `tags:` with `attack.tXXXX` and
`attack.tactic_name` patterns. DetectForge validates these patterns and scores
rules without ATT&CK tags lower, incentivizing complete mapping.

**False positive documentation.** SigmaHQ encourages a `falsepositives:`
field but many community rules leave it as `- Unknown` or omit it entirely.
DetectForge's FP analyzer generates concrete, actionable scenarios rather than
placeholder text.

**Documentation depth.** SigmaHQ rules include a `description` field.
DetectForge generates seven structured documentation fields including
detection mechanism explanation, coverage gaps, required log sources, and
tuning recommendations -- information that SigmaHQ rules rarely provide.

### Where SigmaHQ Excels

SigmaHQ benefits from community review, real-world testing, and iterative
refinement over years. DetectForge-generated rules are new and untested.
DetectForge compensates by:

- Scoring detection logic complexity to flag rules that are too simple.
- Running format-specific validation to catch structural issues that would
  surface during real deployment.
- Generating FP analysis and coverage gaps proactively rather than waiting
  for production incidents.

### Cross-Format Advantage

Unlike SigmaHQ (Sigma-only), DetectForge applies consistent quality standards
across Sigma, YARA, and Suricata formats. The same 5-dimension model scores
all three formats, enabling apples-to-apples quality comparison across a
detection rule set that spans endpoint, file, and network layers.

---

## Quality Report Output

The `generateQualityReport` function produces a structured report for any set
of rules:

```typescript
interface QualityReport {
  totalRules: number;
  averageScore: number;
  scoreDistribution: Record<string, number>; // "1-3", "4-6", "7-10"
  perRuleScores: RuleQualityScore[];
  recommendations: string[];
}
```

The `recommendations` array contains actionable guidance generated from
aggregate dimension averages:

- Syntax validity average below 7: *"Improve syntax validity: review
  validation errors and fix rule structure issues."*
- Detection logic average below 6: *"Enhance detection logic: add more
  content matches, conditions, or string patterns to improve specificity."*
- Documentation average below 5: *"Add comprehensive documentation: include
  what the rule detects, how it works, and tuning recommendations."*
- ATT&CK mapping average below 5: *"Improve ATT&CK mapping: ensure each rule
  has a valid technique ID (e.g., T1059.001) and tactic."*
- FP handling average below 5: *"Document false positive scenarios: add at
  least 2-3 FP scenarios with tuning advice per rule."*

These thresholds are deliberately conservative. An average below the threshold
means a significant fraction of rules are operationally deficient in that
dimension.
