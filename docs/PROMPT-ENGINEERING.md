# Prompt Engineering in DetectForge

This document describes the prompt design decisions, patterns, and lessons learned from building DetectForge's AI-powered detection rule generation pipeline. DetectForge uses eight distinct prompt types across three operational categories: extraction, generation, and analysis. Every prompt follows the same architectural pattern: structured system prompt, data-rich user prompt, and Zod-validated response.

---

## Table of Contents

1. [Prompt Architecture Overview](#prompt-architecture-overview)
2. [The Three Prompt Categories](#the-three-prompt-categories)
3. [Design Patterns](#design-patterns)
4. [Extraction Prompts](#extraction-prompts)
5. [Generation Prompts](#generation-prompts)
6. [Analysis Prompts](#analysis-prompts)
7. [Response Parsing Strategy](#response-parsing-strategy)
8. [Model Tier Selection Rationale](#model-tier-selection-rationale)
9. [Lessons Learned](#lessons-learned)

---

## Prompt Architecture Overview

Every AI interaction in DetectForge follows a consistent three-layer architecture:

```
[Prompt Builder]  -->  [AI Client]  -->  [Response Parser + Zod Schema]
   ai/prompts/*.ts       ai/client.ts       ai/response-parser.ts + co-located schemas
```

**Each prompt file exports three things:**
1. A **prompt builder function** that takes typed inputs and returns `{ system: string; user: string }`
2. A **Zod schema** that defines the exact JSON structure the AI must return
3. A **response parser function** that extracts JSON from the raw response and validates it

This co-location is deliberate. The prompt, the expected output format, and the validation schema evolve together. When you change what you ask the AI to produce, you change the schema in the same file.

### File Inventory

| File | Category | Purpose |
|------|----------|---------|
| `ai/prompts/ioc-extraction.ts` | Extraction | IOC discovery and disambiguation |
| `ai/prompts/ttp-extraction.ts` | Extraction | TTP identification and ATT&CK mapping |
| `ai/prompts/sigma-generation.ts` | Generation | Sigma rule generation |
| `ai/prompts/yara-generation.ts` | Generation | YARA rule generation |
| `ai/prompts/suricata-generation.ts` | Generation | Suricata rule generation |
| `ai/prompts/documentation.ts` | Analysis | Rule documentation for SOC analysts |
| `ai/prompts/fp-analysis.ts` | Analysis | False positive scenario identification |
| `ai/prompts/gap-analysis.ts` | Analysis | Detection coverage gap analysis |

---

## The Three Prompt Categories

### Extraction Prompts
**Goal:** Convert unstructured report text into structured data.
**Input:** Raw report text (thousands of words).
**Output:** Typed arrays of IOCs, TTPs, or ATT&CK mappings.
**Challenge:** The model must understand cybersecurity context to distinguish malicious indicators from benign references, and behavioral patterns from background narrative.

### Generation Prompts
**Goal:** Produce syntactically valid detection rules in a specific format.
**Input:** Structured extraction data (TTPs, IOCs, ATT&CK mappings) + format-specific template context.
**Output:** JSON objects that can be transformed into Sigma YAML, YARA rules, or Suricata rules.
**Challenge:** The model must produce rules that are not only syntactically valid but also operationally useful -- detecting real threat behavior without excessive false positives.

### Analysis Prompts
**Goal:** Evaluate and document generated rules.
**Input:** Complete rule content + metadata.
**Output:** Documentation, false positive scenarios, or coverage gap assessments.
**Challenge:** The model must reason about how the rule will behave in production environments and anticipate real-world edge cases.

---

## Design Patterns

### Pattern 1: Persona Specification

Every system prompt begins with a clear persona that establishes the model's domain expertise:

```
"You are an expert detection engineer specializing in Sigma rule creation."
```
```
"You are a senior SOC analyst and detection engineer who has deployed thousands of
detection rules across enterprise environments."
```
```
"You are a senior detection engineering manager performing a rigorous review of
detection rule coverage against a threat intelligence report."
```

The persona is not decorative. It activates domain-specific knowledge and reasoning patterns within the model. The gap analysis prompt explicitly says "be brutally honest" and "think like a red teamer" because the default AI behavior is to be optimistic and agreeable, which is counterproductive for security analysis.

### Pattern 2: Embedded Specification Reference

Generation prompts include a compressed but complete specification reference for the target format. The Sigma generation prompt contains the full detection block syntax rules:

```
## Detection Block Rules

- Name selection blocks descriptively: `selection_process`, `selection_commandline`
- Use lists for OR logic within a field: `CommandLine: ["*-enc*", "*-encoded*"]`
- Use wildcards (`*`) for partial matching.
- The `condition` field is a boolean expression referencing selection names
- Prefer specific field values over overly broad wildcards.
```

The YARA prompt includes string types, modifier syntax, and condition operators. The Suricata prompt includes keyword reference, sticky buffer documentation, and protocol variables. This in-context specification prevents the model from relying on potentially outdated training knowledge.

### Pattern 3: Field Constraints

The Sigma generation prompt dynamically injects the available fields for the selected logsource category:

```
## Available Fields for This Logsource

- Image
- OriginalFileName
- CommandLine
- ParentImage
- ParentCommandLine
- User
...

Only use fields from the list above. Do not invent fields that do not exist in this logsource.
```

This is a critical quality control. Without field constraints, AI models frequently invent plausible-sounding field names that do not exist in any SIEM product. By providing the exact field list from the template, we ensure the generated rule references real fields.

### Pattern 4: Few-Shot Examples

Generation prompts include a complete, high-quality example of the expected output:

```json
{
  "title": "Suspicious PowerShell Download Cradle via Invoke-WebRequest",
  "description": "Detects execution of PowerShell with download cradle patterns...",
  "tags": ["attack.execution", "attack.t1059.001"],
  "logsource": { "product": "windows", "category": "process_creation" },
  "detection": {
    "selection_parent": { "ParentImage": ["*\\\\cmd.exe", "*\\\\explorer.exe"] },
    "selection_ps": { "Image": ["*\\\\powershell.exe"], "CommandLine": ["*Invoke-WebRequest*"] },
    "condition": "selection_parent and selection_ps"
  },
  "falsepositives": ["Administrative scripts that download updates"],
  "level": "high"
}
```

The example demonstrates:
- Proper naming conventions for selection blocks
- Correct wildcard and backslash escaping
- Multi-selection conditions with `and`
- Appropriate level of specificity in string patterns
- Realistic false positive entries

### Pattern 5: Anti-Patterns and Quality Guidelines

Prompts explicitly describe what NOT to do:

**YARA prompt:**
```
1. No overly generic strings. Avoid single-word strings like "http" or "cmd".
   Combine them with context (e.g., "cmd.exe /c" instead of "cmd").
```

**Suricata prompt:**
```
7. Generate one focused rule per IOC or tightly related IOC group.
8. Do NOT include sid or rev in options -- they are assigned automatically.
```

**FP analysis prompt:**
```
GOOD: "SCCM client (CcmExec.exe) executing PowerShell scripts from
       C:\Windows\ccmcache\ during software deployment cycles"
BAD:  "Administrative tools running scripts"
```

Negative examples are often more effective than positive ones. They address the specific failure modes we observed during development.

### Pattern 6: Structured Output Enforcement

Every prompt ends with strict output format requirements:

```
Respond with ONLY a JSON object (no markdown fences, no explanation)
matching the structure above.
Do NOT include fields like id, status, date, author, or raw --
those are added programmatically.
```

The "no markdown fences" instruction is necessary because many models wrap JSON in ` ```json ``` ` blocks by default. The response parser handles this anyway (see [Response Parsing Strategy](#response-parsing-strategy)), but reducing the variation reduces parsing failures.

### Pattern 7: Context-Aware IOC Filtering

The Sigma generation prompt includes a `filterRelevantIocs()` function that pre-filters IOCs before including them in the prompt:

```typescript
// Network logsource categories get IP/domain IOCs
if (networkCategories.has(category)) {
  return ['ipv4', 'ipv6', 'domain', 'url'].includes(ioc.type);
}
// Process logsource categories get file/hash IOCs
if (fileCategories.has(category)) {
  return ['filepath_windows', 'sha256', 'domain', 'url'].includes(ioc.type);
}
```

This prevents the prompt from being cluttered with irrelevant IOCs (e.g., feeding file hashes to a network_connection rule template) which would confuse the model and waste tokens.

---

## Extraction Prompts

### IOC Extraction (`ioc-extraction.ts`)

**Two modes of operation:**

1. **Full extraction** (`buildIocExtractionPrompt`): Asks the AI to discover all IOCs in the report, including those mentioned in natural language. Used when regex extraction is insufficient.

2. **Disambiguation** (`buildIocDisambiguationPrompt`): Feeds regex-extracted candidate IOCs to the AI for malicious/benign classification. This is the more common mode -- regex finds potential IOCs, AI determines if they are actually part of the threat.

**Key design decision: Disambiguation over full extraction.**

The production pipeline uses regex for IOC extraction (`extractIocs()` in `ioc-extractor.ts`) because regex is deterministic, fast, and free. The AI disambiguation prompt is an optional enhancement for ambiguous cases. This hybrid approach gives us the speed and reliability of regex with the contextual understanding of AI when needed.

**Disambiguation prompt example:**
```
Your task is to:
1. Determine if each candidate is a TRUE IOC (part of the threat) or FALSE POSITIVE
2. Enhance the confidence level based on context
3. Add relationships between IOCs if they exist
```

### TTP Extraction (`ttp-extraction.ts`)

This is purely AI-driven -- there is no regex fallback for behavioral pattern extraction. The TTP extraction prompt is the most detailed of all extraction prompts because it defines exactly what constitutes a "good" TTP:

**Artifacts taxonomy:** The prompt defines six artifact types (file, registry, event_log, network, process, other) with concrete examples:
```
- File: Dropper executable written to %TEMP%, named "update.exe"
- Registry: Persistence key created at HKCU\...\Run
- Event Log: Windows Event ID 4688 (process creation)
- Network: HTTP POST to C2 server every 60 seconds
- Process: powershell.exe with encoded command parameter
```

**Detection opportunities examples:** The prompt teaches the model what actionable detection ideas look like:
```
- Monitor for PowerShell with network connections and encoded commands
- Alert on LSASS memory access by non-system processes
- Detect PsExec service creation on multiple hosts in short time window
```

### ATT&CK Mapping (`ttp-extraction.ts`)

The mapping prompt enforces subtechnique preference:
```
1. Prefer subtechniques over parent techniques
   - GOOD: T1059.001 (PowerShell)
   - AVOID: T1059 (Command and Scripting Interpreter) when subtechnique exists
```

It also guides format selection:
```
DETECTION FORMAT GUIDANCE:
- sigma: Process creation, registry modifications, file events
- yara: Malware file signatures, memory patterns, PE characteristics
- suricata: Network traffic patterns, C2 communication, HTTP/TLS behavior
```

This `suggestedRuleFormats` field in the response drives which generators are invoked downstream.

---

## Generation Prompts

### Sigma Generation (`sigma-generation.ts`)

**The most complex prompt** because Sigma rules have the richest schema and the most ways to go wrong.

**System prompt structure:**
1. Persona: "expert detection engineer specializing in Sigma rule creation"
2. Sigma specification: Required fields, types, valid values
3. Detection block rules: Selection naming, wildcards, conditions, OR logic
4. Target logsource: Dynamic -- injected from template
5. Available fields: Dynamic -- injected from template
6. Example detection block: Dynamic -- injected from template
7. Full example rule: Static high-quality reference
8. Output format: Strict JSON requirements

**User prompt structure:**
1. ATT&CK technique details (ID, name, tactic, confidence, reasoning)
2. TTP description
3. Tools used
4. Artifacts observed (with type tags)
5. Detection opportunities
6. Relevant IOCs (pre-filtered by logsource category)
7. Target logsource category and available fields
8. Explicit requirements (8 numbered items)

**Zod schema for Sigma response:**
```typescript
const SigmaAIResponseSchema = z.object({
  title: z.string().min(10).max(256),
  description: z.string().min(20),
  tags: z.array(z.string()).min(1),
  logsource: z.object({
    product: z.string(),
    category: z.string().optional(),
    service: z.string().optional(),
  }),
  detection: z.record(z.unknown()).refine(
    (det) => typeof det['condition'] === 'string',
    { message: 'detection must contain a "condition" key of type string' },
  ),
  falsepositives: z.array(z.string()).default([]),
  level: z.enum(['informational', 'low', 'medium', 'high', 'critical']),
});
```

Note that `detection` uses `z.record(z.unknown())` with a custom refinement. This is intentional -- Sigma detection blocks have dynamic keys (selection names chosen by the rule author), so we cannot define a fixed schema. We only enforce that a `condition` string exists.

### YARA Generation (`yara-generation.ts`)

**Key difference from Sigma:** The YARA prompt generates multiple rules per call (`rules: z.array(YaraRuleSchema).min(1)`), while Sigma generates one rule per TTP.

**String validation is strict:**
```typescript
const YaraStringSchema = z.object({
  identifier: z.string().regex(/^\$[a-zA-Z_][a-zA-Z0-9_]*$/),
  value: z.string().min(1),
  type: z.enum(['text', 'hex', 'regex']),
  modifiers: z.array(z.string()).default([]),
});
```

The `$` prefix on identifiers and the `text|hex|regex` type enum catch common AI mistakes like generating identifiers without `$` or mixing up string types.

**Template integration:** The YARA prompt dynamically includes magic bytes, common strings, and condition skeletons from the selected template:
```
Magic bytes for file identification: 4D 5A (PE), 7F 45 4C 46 (ELF)
Common strings seen in this category: ...
Suggested condition skeleton: uint16(0) == 0x5A4D and filesize < 5MB and ...
```

### Suricata Generation (`suricata-generation.ts`)

**Key design difference:** The Suricata prompt asks for rule *options* and *metadata* rather than a complete rule string. The rule header (action, protocol, source, destination) is assembled programmatically from the template defaults. This prevents the most common AI error: malformed rule headers.

```typescript
const SuricataRuleResponseSchema = z.object({
  msg: z.string(),
  options: z.array(z.object({
    keyword: z.string(),
    value: z.string().optional(),
  })),
  classtype: z.string(),
  metadata: z.record(z.string()).optional(),
  rationale: z.string(),
});
```

**Keyword reference block:** The prompt includes a condensed Suricata keyword reference (msg, flow, content, nocase, depth, offset, distance, within, dns.query, http.uri, etc.) because Suricata syntax is less commonly seen in AI training data than Sigma or YARA.

---

## Analysis Prompts

### Documentation (`documentation.ts`)

The documentation prompt generates SOC analyst-facing rule documentation. Its key design principle is **specificity over completeness:**

```
## Documentation Quality Principles

1. Explain the "what" clearly: Describe the specific threat behavior
2. Explain the "how" in detail: Walk through the detection logic step-by-step
3. Map to ATT&CK precisely
4. Anticipate false positives
5. Identify coverage gaps: Honestly state what the rule does NOT detect
6. Recommend log sources
7. Provide tuning guidance
```

The `RuleDocumentation` response requires all seven fields to be populated. The Zod schema enforces minimum lengths:
```typescript
whatItDetects: z.string().min(20),
howItWorks: z.string().min(20),
falsePositives: z.array(FalsePositiveScenarioSchema).min(1),
coverageGaps: z.array(z.string().min(1)).min(1),
```

### False Positive Analysis (`fp-analysis.ts`)

This is the most operationally critical analysis prompt. False positives are the primary reason detection rules fail in production.

**Key design decisions:**

1. **Good/bad examples are essential.** Without explicit examples of what "specific" means, models produce vague outputs:
   ```
   GOOD: "Windows Update service (wuauclt.exe) spawning svchost.exe with
          network connections to Microsoft CDN endpoints"
   BAD:  "Legitimate network traffic"
   ```

2. **Environment diversity is required.** The prompt lists five enterprise environment types (corporate workstations, developer machines, CI/CD, servers, cloud) so the model considers FPs across deployment contexts.

3. **Tuning advice must be format-specific.** The prompt requires:
   - Sigma: Specific `filter_*` selection blocks
   - YARA: Condition refinements, filesize constraints, imphash checks
   - Suricata: Flowbits, threshold, or suppress directives

4. **The schema requires 3-7 scenarios.** Too few means the analysis is incomplete. Too many means padding with low-quality scenarios:
   ```typescript
   falsePositives: z.array(...).min(3).max(7)
   ```

5. **Minimum string lengths enforce quality.** Each scenario description and tuning advice must be at least 20 characters, preventing one-liners.

### Coverage Gap Analysis (`gap-analysis.ts`)

The gap analysis prompt is the most complex analysis prompt. It evaluates the entire rule set against all extracted TTPs and ATT&CK mappings.

**Four analysis dimensions:**
1. **Uncovered TTPs:** Which TTPs from the report lack detection rules, and why
2. **Evasion vectors:** How a sophisticated adversary could bypass each generated rule
3. **Log source gaps:** Which data sources are needed but may be missing
4. **Overall coverage:** Percentage of ATT&CK techniques covered, strongest/weakest tactics

**The user prompt includes quick stats** so the model can ground its analysis:
```
## Quick Stats

- Unique ATT&CK techniques identified: ${uniqueTechniques.size}
- Techniques with at least one rule: ${coveredTechniques.size}
- Rule formats generated: sigma, yara, suricata
```

**The persona is deliberately adversarial:** "Be brutally honest... do not sugarcoat coverage." This counters the model's tendency to describe partial coverage as "good."

---

## Response Parsing Strategy

### The Three-Layer Parser

AI responses are parsed through three layers in `ai/response-parser.ts`:

**Layer 1: Extraction.** Strip markdown code fences and find JSON boundaries:
```typescript
// Remove markdown code blocks
const codeBlockMatch = cleaned.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
if (codeBlockMatch) {
  cleaned = codeBlockMatch[1].trim();
}
// Find JSON object boundaries
const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
```

**Layer 2: Standard repair.** Fix common JSON errors (trailing commas, unclosed brackets):
```typescript
// Remove trailing commas before closing brackets/braces
repaired = repaired.replace(/,(\s*[}\]])/g, '$1');
// Track nesting stack and close unclosed structures
while (stack.length > 0) {
  repaired += stack.pop();
}
```

**Layer 3: Aggressive repair.** For badly truncated responses, count unmatched openers and insert closers:
```typescript
const missingBrackets = openBrackets - closeBrackets;
// Insert missing ] before the last } (common: array not closed before object end)
```

### Zod Validation

After JSON parsing, the result is validated against the operation-specific Zod schema. Validation errors include the full path and message for debugging:

```typescript
if (error instanceof z.ZodError) {
  const formattedErrors = error.errors.map(err =>
    `  - ${err.path.join('.')}: ${err.message}`
  ).join('\n');
  throw new Error(
    `Sigma AI response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`
  );
}
```

This means a schema violation like a missing `condition` field in a Sigma detection block produces:
```
Sigma AI response validation failed:
  - detection: detection must contain a "condition" key of type string

Raw response:
{"title":"Suspicious PowerShell Execution",...}
```

---

## Model Tier Selection Rationale

### Why Three Tiers?

Cost and latency vary by an order of magnitude between model tiers. Not every operation needs the most capable model:

| Operation | Recommended Tier | Reasoning |
|-----------|-----------------|-----------|
| IOC disambiguation | fast | Simple classification task, small context |
| TTP extraction | standard | Requires understanding behavioral descriptions |
| ATT&CK mapping | standard | Pattern matching against known framework |
| Sigma rule generation | quality | Complex structured output, field constraints |
| YARA rule generation | quality | Requires understanding of binary patterns |
| Suricata rule generation | quality | Network protocol expertise needed |
| Documentation | standard | Descriptive writing, less constrained output |
| FP analysis | standard/quality | Requires operational experience reasoning |
| Gap analysis | quality | Complex multi-rule reasoning |

### Cost Impact

A typical threat report with 5 TTPs and 10 IOCs produces approximately:

| Tier | Approximate Cost | Tokens |
|------|-----------------|--------|
| All fast | $0.005 | ~15,000 |
| All standard | $0.02 | ~15,000 |
| All quality | $0.10 | ~15,000 |
| Mixed (recommended) | $0.03-0.05 | ~15,000 |

The CLI's `--model` flag sets a single tier for the entire run. In practice, the default `standard` tier provides good results. The `quality` tier is recommended for production rule generation where accuracy matters most.

---

## Lessons Learned

### 1. Specification embedding beats reliance on training data

Early versions of the prompts assumed the model knew Sigma, YARA, and Suricata syntax from its training data. This produced rules with invented field names, incorrect syntax, and non-existent keywords. Embedding a compressed specification reference in every system prompt eliminated most syntax errors.

### 2. Field constraints are essential for Sigma

Without an explicit list of available fields per logsource category, models generate fields like `ProcessName`, `SourceIP`, or `FileName` that do not exist in any SIEM's Sigma implementation. The template system's `availableFields` array, combined with the instruction "Only use fields from the list above," reduced invalid field usage dramatically.

### 3. Negative examples outperform positive-only guidance

For the FP analysis prompt, adding BAD examples alongside GOOD examples had a larger impact on output quality than adding more GOOD examples. Models tend to produce output at the quality floor of the examples shown. Showing the floor explicitly ("This is BAD: 'Legitimate network traffic'") raised the actual floor.

### 4. JSON mode is not sufficient -- you need structural repair

Even with `response_format: { type: 'json_object' }`, models occasionally produce malformed JSON (particularly with deeply nested structures or long outputs that hit token limits). The three-layer repair strategy handles the majority of these cases without requiring a retry.

### 5. Zod schemas catch AI errors early

Without Zod validation, malformed AI responses would propagate through the pipeline and cause confusing downstream failures (e.g., a missing `condition` field in a Sigma detection block would crash the YAML serializer). Zod catches these at the parsing boundary with clear error messages.

### 6. Template-driven generation produces more consistent output

Providing the model with a specific template context (logsource, fields, example detection block) produces significantly more consistent and correct output than open-ended generation. The template acts as a "slot" the model fills in, rather than asking it to generate everything from scratch.

### 7. Separation of rule header from rule options (Suricata)

The Suricata prompt asks for rule options in JSON format, not complete rule strings. The rule header (`alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS`) is assembled programmatically from template defaults. This separation eliminated the most common class of Suricata generation errors: malformed rule headers.

### 8. Cost tracking changes behavior

When API cost is visible per-call and aggregated per-run, it naturally encourages using the right model tier for each task. The cost summary at the end of every `generate` run creates accountability for model selection decisions.

### 9. Disambiguation is cheaper than full AI extraction for IOCs

Regex-first IOC extraction with optional AI disambiguation is significantly cheaper and more reliable than asking the AI to find all IOCs from scratch. Regex catches the obvious patterns. AI adds value only for the ambiguous cases (is `google.com` an IOC or a benign reference?).

### 10. Prompt length matters less than prompt structure

The Sigma generation system prompt is over 2,000 tokens. This is fine. What matters is clear section headers, consistent formatting, and logical flow. Models handle long, well-structured prompts better than short, ambiguous ones. Every section has a clear purpose, and the most important constraints (field list, output format) appear last, closest to the model's attention window.
