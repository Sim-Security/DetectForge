/**
 * Prompt templates and response schema for AI-driven YARA rule generation.
 *
 * Provides:
 * - A system prompt with YARA syntax reference, quality guidelines,
 *   and the relevant template context.
 * - A user prompt that feeds IOCs, TTPs, and ATT&CK mapping details
 *   to the model.
 * - A Zod schema for validating the structured JSON the AI returns.
 * - A convenience parser that extracts and validates the response.
 */

import { z } from 'zod';
import { extractJsonFromResponse } from '@/ai/response-parser.js';
import type { ExtractedIOC, ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';
import type { YaraTemplate } from '@/generation/yara/templates.js';

// ---------------------------------------------------------------------------
// Zod Schema
// ---------------------------------------------------------------------------

/**
 * Schema for a single YARA string as returned by the AI.
 */
const YaraStringSchema = z.object({
  identifier: z.string().regex(/^\$[a-zA-Z_][a-zA-Z0-9_]*$/, 'Invalid YARA string identifier'),
  value: z.string().min(1, 'String value must not be empty'),
  type: z.enum(['text', 'hex', 'regex']),
  modifiers: z.array(z.string()).default([]),
});

/**
 * Schema for a single YARA rule as returned by the AI.
 */
const YaraRuleSchema = z.object({
  name: z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/, 'Invalid YARA rule name'),
  tags: z.array(z.string()).default([]),
  meta: z.object({
    description: z.string().min(1),
    author: z.string().min(1),
    date: z.string().min(1),
    reference: z.string().default(''),
    mitre_attack: z.string().default(''),
    hash: z.string().optional(),
  }).passthrough(),
  strings: z.array(YaraStringSchema).min(1, 'At least one string is required'),
  condition: z.string().min(1, 'Condition must not be empty'),
});

/**
 * Top-level schema for the complete AI response.
 */
export const YaraAIResponseSchema = z.object({
  rules: z.array(YaraRuleSchema).min(1, 'At least one rule is required'),
});

export type YaraAIResponse = z.infer<typeof YaraAIResponseSchema>;

// ---------------------------------------------------------------------------
// Prompt Builders
// ---------------------------------------------------------------------------

/**
 * Build the system and user prompts used to generate YARA rules via AI.
 *
 * @param iocs      - Extracted indicators of compromise.
 * @param ttps      - Extracted tactics, techniques, and procedures.
 * @param mapping   - The ATT&CK mapping result associated with the TTPs.
 * @param template  - The YARA template providing category-specific guidance.
 * @returns An object with `system` and `user` prompt strings.
 */
export function buildYaraGenerationPrompt(
  iocs: ExtractedIOC[],
  ttps: ExtractedTTP[],
  mapping: AttackMappingResult,
  template: YaraTemplate,
): { system: string; user: string } {
  // ------- System prompt -------
  const system = `You are an expert YARA rule author specializing in malware detection and threat hunting. You write precise, well-documented YARA rules that minimize false positives while maximizing detection coverage.

## YARA Rule Syntax Reference

A YARA rule follows this structure:

\`\`\`
rule RuleName : tag1 tag2 {
    meta:
        key = "value"
    strings:
        $identifier = "text string" ascii wide nocase
        $hex_identifier = { AA BB CC DD }
        $regex_identifier = /regex pattern/i
    condition:
        boolean expression referencing strings
}
\`\`\`

### Meta Section
- \`description\`: What the rule detects (required).
- \`author\`: Who wrote the rule (required).
- \`date\`: Creation date in YYYY-MM-DD format (required).
- \`reference\`: URL or report reference.
- \`mitre_attack\`: MITRE ATT&CK technique ID(s).
- \`hash\`: Sample hash if available.

### String Types
1. **Text strings**: \`$s = "text" ascii wide nocase fullword\`
   - Modifiers: \`ascii\`, \`wide\`, \`nocase\`, \`fullword\`, \`xor\`, \`base64\`
2. **Hex strings**: \`$h = { 4D 5A 90 00 }\`
   - Wildcards: \`??\` matches any byte, e.g., \`{ 4D 5A ?? 00 }\`
   - Jumps: \`[4-6]\` matches 4 to 6 arbitrary bytes
   - Alternatives: \`( AA | BB )\`
   - Valid characters: 0-9, A-F (uppercase), spaces, ??, [], (), |
3. **Regex strings**: \`$r = /pattern/\`
   - Modifiers: \`i\` (case-insensitive), \`s\` (dot matches newline)

### Condition Operators
- \`and\`, \`or\`, \`not\`
- \`any of ($s*)\`, \`all of ($s*)\`, \`2 of ($s*)\`, \`3 of them\`
- \`uint16(0) == 0x5A4D\` — PE magic number check
- \`uint32(0) == 0xE011CFD0\` — OLE magic number check
- \`uint32(0) == 0x04034B50\` — ZIP/OOXML magic number check
- \`uint32(0) == 0x464C457F\` — ELF magic number check
- \`filesize < 10MB\`, \`filesize > 1KB\`
- \`at\`, \`in\`, \`for\`, \`of\`, \`them\`
- String counts: \`#s1 > 2\` (string appears more than twice)

## Template Context — Category: ${template.category}

${template.description}

${template.magicBytes ? `Magic bytes for file identification: ${template.magicBytes.join(', ')}` : 'No magic byte constraint for this category.'}

Common strings seen in this category:
${template.commonStrings.map(s => `- "${s}"`).join('\n')}

Suggested condition skeleton:
\`${template.conditionTemplate}\`

## Quality Guidelines

1. **No overly generic strings.** Avoid single-word strings like "http" or "cmd". Combine them with context (e.g., "cmd.exe /c" instead of "cmd").
2. **Use filesize constraints** to limit scope and improve scan performance.
3. **Prefer multiple specific strings** over a few broad ones; use "N of ($s*)" conditions.
4. **Include magic byte checks** when targeting specific file formats.
5. **Use modifiers wisely**: \`ascii wide\` for strings in both encodings, \`nocase\` sparingly.
6. **Descriptive rule names** that indicate the threat (e.g., \`APT29_Cobalt_Strike_Loader\`).
7. **Meaningful tags** such as \`apt\`, \`malware\`, \`trojan\`, \`webshell\`, \`exploit\`.
8. **Avoid false positives** by requiring a combination of indicators rather than a single string.

## Output Format

Return a JSON object matching this schema:

\`\`\`json
{
  "rules": [
    {
      "name": "RuleName",
      "tags": ["tag1", "tag2"],
      "meta": {
        "description": "What this rule detects",
        "author": "DetectForge",
        "date": "YYYY-MM-DD",
        "reference": "source URL or report",
        "mitre_attack": "Txxxx.xxx",
        "hash": "optional sample hash"
      },
      "strings": [
        {
          "identifier": "$s1",
          "value": "string value",
          "type": "text",
          "modifiers": ["ascii", "wide"]
        },
        {
          "identifier": "$hex1",
          "value": "4D 5A 90 00",
          "type": "hex",
          "modifiers": []
        }
      ],
      "condition": "uint16(0) == 0x5A4D and filesize < 5MB and 3 of ($s*)"
    }
  ]
}
\`\`\`

IMPORTANT:
- Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.
- Every rule MUST have at least one string and a non-empty condition.
- String identifiers MUST start with \`$\` followed by a letter or underscore.
- Hex string values MUST contain only 0-9, A-F, spaces, \`??\`, \`[\`, \`]\`, \`(\`, \`)\`, \`|\`, and \`-\`.
- Rule names MUST be valid identifiers: letters, digits, and underscores, starting with a letter or underscore.`;

  // ------- User prompt -------
  const iocSummary = buildIocSummary(iocs);
  const ttpSummary = buildTtpSummary(ttps);

  const user = `Generate YARA detection rules for the following threat intelligence.

## ATT&CK Mapping

- **Technique**: ${mapping.techniqueId} — ${mapping.techniqueName}
- **Tactic**: ${mapping.tactic}
- **Confidence**: ${mapping.confidence}
- **Reasoning**: ${mapping.reasoning}

## Indicators of Compromise

${iocSummary}

## Tactics, Techniques, and Procedures

${ttpSummary}

## Instructions

1. Create one or more YARA rules that detect artifacts described above.
2. Use the "${template.category}" template as a starting point but adapt strings and conditions to the specific threat.
3. Include all relevant meta fields (description, author as "DetectForge", today's date as "${new Date().toISOString().slice(0, 10)}", reference, mitre_attack set to "${mapping.techniqueId}").
4. If file hashes are available, include the first one in the "hash" meta field.
5. Write precise string patterns derived from the IOCs and TTP artifacts — do not invent indicators.
6. Return the result as a JSON object with a "rules" array.`;

  return { system, user };
}

// ---------------------------------------------------------------------------
// Response Parser
// ---------------------------------------------------------------------------

/**
 * Parse the raw AI response text into a validated {@link YaraAIResponse}.
 *
 * Extracts JSON from potential markdown fences, repairs common issues,
 * and validates against the Zod schema.
 *
 * @param raw - The raw string returned by the AI model.
 * @returns The validated response object.
 * @throws If parsing or validation fails.
 */
export function parseYaraAIResponse(raw: string): YaraAIResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return YaraAIResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formatted = error.errors
        .map(err => `  - ${err.path.join('.')}: ${err.message}`)
        .join('\n');
      throw new Error(
        `YARA AI response validation failed:\n${formatted}\n\nRaw response:\n${raw.substring(0, 500)}`,
      );
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a human-readable summary of IOCs for inclusion in the user prompt.
 */
function buildIocSummary(iocs: ExtractedIOC[]): string {
  if (iocs.length === 0) {
    return '_No IOCs provided._';
  }

  const grouped: Record<string, ExtractedIOC[]> = {};
  for (const ioc of iocs) {
    const key = ioc.type;
    if (!grouped[key]) {
      grouped[key] = [];
    }
    grouped[key].push(ioc);
  }

  const lines: string[] = [];
  for (const [type, items] of Object.entries(grouped)) {
    lines.push(`### ${type} (${items.length})`);
    for (const item of items.slice(0, 20)) {
      lines.push(`- \`${item.value}\` — ${item.context} (confidence: ${item.confidence})`);
    }
    if (items.length > 20) {
      lines.push(`- ... and ${items.length - 20} more`);
    }
  }

  return lines.join('\n');
}

/**
 * Build a human-readable summary of TTPs for inclusion in the user prompt.
 */
function buildTtpSummary(ttps: ExtractedTTP[]): string {
  if (ttps.length === 0) {
    return '_No TTPs provided._';
  }

  const lines: string[] = [];
  for (const ttp of ttps) {
    lines.push(`### TTP: ${ttp.description}`);
    if (ttp.tools.length > 0) {
      lines.push(`- **Tools**: ${ttp.tools.join(', ')}`);
    }
    if (ttp.targetPlatforms.length > 0) {
      lines.push(`- **Platforms**: ${ttp.targetPlatforms.join(', ')}`);
    }
    if (ttp.artifacts.length > 0) {
      lines.push('- **Artifacts**:');
      for (const artifact of ttp.artifacts) {
        const val = artifact.value ? ` (\`${artifact.value}\`)` : '';
        lines.push(`  - [${artifact.type}] ${artifact.description}${val}`);
      }
    }
    if (ttp.detectionOpportunities.length > 0) {
      lines.push('- **Detection opportunities**:');
      for (const opp of ttp.detectionOpportunities) {
        lines.push(`  - ${opp}`);
      }
    }
  }

  return lines.join('\n');
}
