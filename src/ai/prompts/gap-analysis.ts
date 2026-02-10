/**
 * AI prompt templates and response parsing for coverage gap analysis.
 *
 * Builds system + user prompts that instruct the AI model to evaluate
 * detection coverage across all generated rules, identify uncovered TTPs,
 * potential evasion vectors, and missing log sources.  The response is
 * validated against a Zod schema before being returned to the caller.
 */

import { z } from 'zod';
import { extractJsonFromResponse } from '@/ai/response-parser.js';
import type { GeneratedRule } from '@/types/detection-rule.js';
import type { ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Zod Schema for the AI response
// ---------------------------------------------------------------------------

/**
 * Schema that the AI model must conform to when producing a gap analysis.
 *
 * The schema covers four major areas:
 * - Uncovered TTPs that were not translated into detection rules
 * - Evasion vectors that could bypass existing rules
 * - Log source gaps that limit detection capability
 * - An overall coverage summary with per-tactic breakdown
 */
export const GapAnalysisAIResponseSchema = z.object({
  uncoveredTTPs: z.array(z.object({
    ttpDescription: z.string(),
    techniqueId: z.string().optional(),
    reason: z.string(),
    alternativeDetection: z.string(),
    requiredLogSources: z.array(z.string()),
  })),
  evasionVectors: z.array(z.object({
    ruleAffected: z.string(),
    evasionTechnique: z.string(),
    mitigationSuggestion: z.string(),
  })),
  logSourceGaps: z.array(z.object({
    logSource: z.string(),
    requiredFor: z.array(z.string()),
    currentlyAvailable: z.boolean(),
    recommendation: z.string(),
  })),
  overallCoverage: z.object({
    coveredTechniqueCount: z.number(),
    totalTechniqueCount: z.number(),
    coveragePercentage: z.number(),
    strongestTactic: z.string(),
    weakestTactic: z.string(),
  }),
  recommendations: z.array(z.string()),
});

/** Inferred TypeScript type from the schema. */
export type GapAnalysisAIResponse = z.infer<typeof GapAnalysisAIResponseSchema>;

// ---------------------------------------------------------------------------
// Response Parser
// ---------------------------------------------------------------------------

/**
 * Parse the raw string returned by the AI model into a validated
 * {@link GapAnalysisAIResponse}.
 *
 * Handles markdown code fences and minor JSON issues via
 * {@link extractJsonFromResponse}.
 *
 * @param raw - The raw AI response text.
 * @returns A validated gap analysis AI response object.
 * @throws When the response cannot be parsed or fails Zod validation.
 */
export function parseGapAnalysisAIResponse(raw: string): GapAnalysisAIResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return GapAnalysisAIResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors
        .map((err) => `  - ${err.path.join('.')}: ${err.message}`)
        .join('\n');
      throw new Error(
        `Gap analysis AI response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`,
      );
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Prompt Builder
// ---------------------------------------------------------------------------

/**
 * Build the system and user prompts for coverage gap analysis.
 *
 * The system prompt establishes the persona of a detection engineering
 * manager evaluating detection coverage.  The user prompt supplies the
 * complete set of generated rules, extracted TTPs, and ATT&CK mappings
 * so the model can identify gaps, evasion vectors, and missing log sources.
 *
 * @param rules    - All rules generated for the threat report.
 * @param ttps     - All TTPs extracted from the threat report.
 * @param mappings - All ATT&CK technique mappings for those TTPs.
 * @returns An object with `system` and `user` prompt strings.
 */
export function buildGapAnalysisPrompt(
  rules: GeneratedRule[],
  ttps: ExtractedTTP[],
  mappings: AttackMappingResult[],
): { system: string; user: string } {
  const system = buildSystemPrompt();
  const user = buildUserPrompt(rules, ttps, mappings);
  return { system, user };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Produce a one-line summary of a generated rule for prompt embedding.
 */
function summarizeRule(rule: GeneratedRule): string {
  const format = rule.format;
  const technique = rule.attackTechniqueId || 'unknown';
  const tactic = rule.attackTactic || 'unknown';
  if (rule.sigma) return `[Sigma] ${rule.sigma.title} (${technique}, ${tactic})`;
  if (rule.yara) return `[YARA] ${rule.yara.name} (${technique}, ${tactic})`;
  if (rule.suricata) {
    const msg = rule.suricata.options.find((o) => o.keyword === 'msg');
    return `[Suricata] ${msg?.value || 'rule'} (${technique}, ${tactic})`;
  }
  return `[${format}] Unknown rule`;
}

/**
 * Build the system prompt establishing the detection engineering manager
 * persona and output requirements.
 */
function buildSystemPrompt(): string {
  return `You are a senior detection engineering manager performing a rigorous review of detection rule coverage against a threat intelligence report. Your job is to be brutally honest about gaps, weaknesses, and blind spots.

## Your Objectives

1. **Identify uncovered TTPs**: Determine which TTPs from the threat report could NOT be translated into detection rules. For each one, explain specifically WHY a rule could not be generated (e.g., the technique operates below the visibility of available log sources, no telemetry exists for that behavior, the technique is inherently difficult to distinguish from legitimate activity).

2. **Identify evasion vectors**: For each generated rule, think like a red teamer. How would a sophisticated adversary evade the detection? Consider techniques such as:
   - Obfuscation (encoding, encryption, string manipulation)
   - Living-off-the-land binaries (LOLBins) and trusted tools
   - Timestomping and log manipulation
   - Process injection and indirect execution
   - Fileless and in-memory techniques
   - Protocol tunneling and encrypted channels
   - Variations in command-line syntax or tooling

3. **Identify log source gaps**: Determine which log sources are required for comprehensive detection but may not be available. Consider:
   - Windows Event Log channels (Sysmon, Security, PowerShell, WMI, etc.)
   - EDR telemetry requirements
   - Network traffic visibility (NetFlow, full packet capture, DNS logs, proxy logs)
   - Cloud audit logs (if applicable)
   - Application-specific logs

4. **Compute overall coverage**: Calculate the percentage of ATT&CK techniques from the report that have at least one detection rule. Identify the strongest and weakest tactical areas.

5. **Provide actionable recommendations**: Suggest specific, prioritized steps to improve detection coverage. Be concrete — reference specific techniques, log sources, and rule types.

## Output Format

Return ONLY a JSON object (no markdown fences, no explanation) matching this schema:

\`\`\`json
{
  "uncoveredTTPs": [
    {
      "ttpDescription": "Description of the TTP from the report",
      "techniqueId": "T1234.001",
      "reason": "Why no rule was generated",
      "alternativeDetection": "How you COULD detect this",
      "requiredLogSources": ["log source 1", "log source 2"]
    }
  ],
  "evasionVectors": [
    {
      "ruleAffected": "Title or identifier of the rule",
      "evasionTechnique": "How an attacker could evade this rule",
      "mitigationSuggestion": "How to address the gap"
    }
  ],
  "logSourceGaps": [
    {
      "logSource": "Name of the log source",
      "requiredFor": ["T1234", "T5678"],
      "currentlyAvailable": false,
      "recommendation": "How to enable or substitute this log source"
    }
  ],
  "overallCoverage": {
    "coveredTechniqueCount": 5,
    "totalTechniqueCount": 10,
    "coveragePercentage": 50.0,
    "strongestTactic": "Execution",
    "weakestTactic": "Defense Evasion"
  },
  "recommendations": [
    "Prioritized recommendation 1",
    "Prioritized recommendation 2"
  ]
}
\`\`\`

Be thorough. Do not sugarcoat coverage — if gaps exist, say so clearly. Every uncovered TTP and every evasion vector is a potential attacker advantage.`;
}

/**
 * Build the user prompt with rule summaries, TTP details, and ATT&CK
 * mappings so the AI can perform a comprehensive gap analysis.
 */
function buildUserPrompt(
  rules: GeneratedRule[],
  ttps: ExtractedTTP[],
  mappings: AttackMappingResult[],
): string {
  // --- Rules summary ---
  const rulesSummary = rules.length > 0
    ? rules.map((r, i) => `${i + 1}. ${summarizeRule(r)}`).join('\n')
    : '_No rules were generated._';

  // --- TTPs summary ---
  const ttpsSummary = ttps.length > 0
    ? ttps.map((ttp, i) => {
      const lines: string[] = [];
      lines.push(`### TTP ${i + 1}: ${ttp.description}`);
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
      lines.push(`- **Confidence**: ${ttp.confidence}`);
      return lines.join('\n');
    }).join('\n\n')
    : '_No TTPs were extracted._';

  // --- ATT&CK mappings summary ---
  const mappingsSummary = mappings.length > 0
    ? mappings.map((m, i) => {
      return `${i + 1}. **${m.techniqueId}** — ${m.techniqueName} (Tactic: ${m.tactic}, Confidence: ${m.confidence})\n   Reasoning: ${m.reasoning}\n   Suggested formats: ${m.suggestedRuleFormats.join(', ')}`;
    }).join('\n')
    : '_No ATT&CK mappings were produced._';

  // --- Coverage quick stats ---
  const uniqueTechniques = new Set(mappings.map((m) => m.techniqueId));
  const coveredTechniques = new Set(
    rules
      .filter((r) => r.attackTechniqueId)
      .map((r) => r.attackTechniqueId),
  );

  return `Analyze the detection coverage for the following threat intelligence report and identify all gaps.

## Generated Detection Rules (${rules.length} total)

${rulesSummary}

## Extracted TTPs (${ttps.length} total)

${ttpsSummary}

## ATT&CK Technique Mappings (${mappings.length} total)

${mappingsSummary}

## Quick Stats

- Unique ATT&CK techniques identified: ${uniqueTechniques.size}
- Techniques with at least one rule: ${coveredTechniques.size}
- Rule formats generated: ${[...new Set(rules.map((r) => r.format))].join(', ') || 'none'}

## Instructions

1. Compare every extracted TTP and ATT&CK mapping against the generated rules. Identify any TTP that does NOT have a corresponding detection rule and explain why.
2. For each generated rule, identify at least one realistic evasion technique an adversary could use to bypass the detection.
3. Identify all log sources that would be needed for comprehensive detection but may be missing or insufficient.
4. Calculate the overall coverage percentage based on unique ATT&CK techniques covered.
5. Provide at least 3 prioritized, actionable recommendations to improve detection coverage.

Respond with ONLY the JSON object.`;
}
