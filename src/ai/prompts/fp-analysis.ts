/**
 * AI prompt templates and response parsing for false positive analysis.
 *
 * Builds carefully structured system + user prompts that instruct the AI
 * model to act as a seasoned SOC analyst, identifying specific false
 * positive scenarios for a given detection rule and providing actionable
 * tuning advice.  The AI response is validated with Zod before being
 * returned as a typed {@link FPAnalysisAIResponse}.
 */

import { z } from 'zod';
import { extractJsonFromResponse } from '@/ai/response-parser.js';
import type { GeneratedRule, RuleFormat } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Zod Schema for the AI response
// ---------------------------------------------------------------------------

/**
 * Schema that the AI model must conform to when analyzing false positives.
 *
 * Requires between 3 and 7 specific false positive scenarios, each with
 * detailed descriptions and actionable tuning advice.
 */
export const FPAnalysisAIResponseSchema = z.object({
  falsePositives: z
    .array(
      z.object({
        scenario: z
          .string()
          .min(20, 'Scenario must be detailed'),
        likelihood: z.enum(['high', 'medium', 'low']),
        tuningAdvice: z
          .string()
          .min(20, 'Tuning advice must be actionable'),
        parentProcess: z.string().optional(),
        environment: z.string().optional(),
      }),
    )
    .min(3, 'At least 3 FP scenarios required')
    .max(7),
  overallFPRisk: z.enum(['high', 'medium', 'low']),
  recommendations: z.array(z.string()),
});

/** Inferred TypeScript type from the schema. */
export type FPAnalysisAIResponse = z.infer<typeof FPAnalysisAIResponseSchema>;

// ---------------------------------------------------------------------------
// Response Parser
// ---------------------------------------------------------------------------

/**
 * Parse the raw string returned by the AI model into a validated
 * {@link FPAnalysisAIResponse}.
 *
 * Handles markdown code fences and minor JSON issues via
 * {@link extractJsonFromResponse}.
 *
 * @param raw - The raw AI response text.
 * @returns A validated FP analysis AI response object.
 * @throws When the response cannot be parsed or fails Zod validation.
 */
export function parseFPAnalysisAIResponse(raw: string): FPAnalysisAIResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return FPAnalysisAIResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors
        .map((err) => `  - ${err.path.join('.')}: ${err.message}`)
        .join('\n');
      throw new Error(
        `FP analysis AI response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`,
      );
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Prompt Builders
// ---------------------------------------------------------------------------

/**
 * Build the system and user prompts for false positive analysis of a
 * generated detection rule.
 *
 * The system prompt establishes the persona of a senior SOC analyst with
 * deep operational experience deploying detection rules at scale.  The
 * user prompt supplies the full rule text, its format, ATT&CK technique,
 * and confidence level.
 *
 * @param rule - The generated detection rule to analyze.
 * @returns An object with `system` and `user` prompt strings.
 */
export function buildFPAnalysisPrompt(
  rule: GeneratedRule,
): { system: string; user: string } {
  const system = buildSystemPrompt();
  const user = buildUserPrompt(rule);
  return { system, user };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the raw rule text from a {@link GeneratedRule}.
 *
 * Checks each format field in priority order and returns the first
 * available raw representation.
 */
function getRuleRaw(rule: GeneratedRule): string {
  if (rule.sigma) return rule.sigma.raw;
  if (rule.yara) return rule.yara.raw;
  if (rule.suricata) return rule.suricata.raw;
  return '';
}

/**
 * Derive a human-readable format label from the {@link RuleFormat}.
 */
function formatLabel(format: RuleFormat): string {
  switch (format) {
    case 'sigma':
      return 'Sigma (SIEM)';
    case 'yara':
      return 'YARA (file/malware)';
    case 'suricata':
      return 'Suricata (network IDS)';
    default:
      return format;
  }
}

/**
 * Build the system prompt establishing the SOC analyst persona and
 * output requirements.
 */
function buildSystemPrompt(): string {
  return `You are a senior SOC analyst and detection engineer who has deployed thousands of detection rules across enterprise environments. You have deep operational experience with Sigma, YARA, and Suricata rules and understand the common false positive patterns that plague production deployments.

## Your Task

Analyze a detection rule and identify specific, realistic false positive scenarios that would occur when this rule is deployed in a production environment. Your analysis must be grounded in real-world operational experience, not theoretical possibilities.

## Requirements for False Positive Scenarios

1. **Be SPECIFIC, not generic.** Each scenario must describe a concrete situation with named tools, services, or processes.
   - GOOD: "Windows Update service (wuauclt.exe) spawning svchost.exe with network connections to Microsoft CDN endpoints (*.download.windowsupdate.com)"
   - BAD: "Legitimate network traffic"
   - GOOD: "SCCM client (CcmExec.exe) executing PowerShell scripts from C:\\Windows\\ccmcache\\ during software deployment cycles"
   - BAD: "Administrative tools running scripts"

2. **Include parent process chains** where applicable. For process-based rules, specify the full parent-child process relationship that would trigger the false positive.

3. **Tuning advice must be actionable.** Provide specific filter/exclusion syntax for the rule's format:
   - For Sigma: Suggest concrete \`filter_*\` selection blocks with field values to exclude.
   - For YARA: Suggest specific conditions, filesize constraints, or imphash/section checks to add.
   - For Suricata: Suggest \`flowbits\`, threshold, or suppress directives with concrete values.

4. **Consider different enterprise environments:**
   - Corporate workstations with standard software stacks
   - Developer machines with build tools and IDEs
   - CI/CD infrastructure and build servers
   - Server infrastructure (web, database, domain controllers)
   - Cloud workloads and containers

5. **Assess likelihood realistically:** "high" means the FP will fire daily in most environments, "medium" means weekly or in specific environments, "low" means rare but documented.

## Output Format

Return a JSON object matching this schema:

\`\`\`json
{
  "falsePositives": [
    {
      "scenario": "Detailed description of the false positive scenario (min 20 chars)",
      "likelihood": "high | medium | low",
      "tuningAdvice": "Actionable advice for tuning the rule to avoid this FP (min 20 chars)",
      "parentProcess": "optional: parent process path for process-based rules",
      "environment": "optional: enterprise environment where this FP is most common"
    }
  ],
  "overallFPRisk": "high | medium | low",
  "recommendations": [
    "General recommendation for improving the rule's signal-to-noise ratio"
  ]
}
\`\`\`

IMPORTANT:
- Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.
- Provide between 3 and 7 false positive scenarios, ordered by likelihood (highest first).
- Each scenario description must be at least 20 characters and highly specific.
- Each tuning advice must be at least 20 characters and directly actionable.
- The \`overallFPRisk\` should reflect the aggregate risk across all scenarios.
- The \`recommendations\` array should contain 1-5 general improvement suggestions.`;
}

/**
 * Build the user prompt with the specific rule details for FP analysis.
 */
function buildUserPrompt(rule: GeneratedRule): string {
  const raw = getRuleRaw(rule);
  const format = formatLabel(rule.format);

  const techniqueInfo = rule.attackTechniqueId
    ? `- **ATT&CK Technique**: ${rule.attackTechniqueId}`
    : '- **ATT&CK Technique**: Not specified';

  const tacticInfo = rule.attackTactic
    ? `- **ATT&CK Tactic**: ${rule.attackTactic}`
    : '- **ATT&CK Tactic**: Not specified';

  const confidenceInfo = `- **Rule Confidence**: ${rule.confidence}`;

  const ttpInfo = rule.sourceTtp
    ? `- **Source TTP**: ${rule.sourceTtp}`
    : '';

  const docSection = rule.documentation
    ? buildDocumentationSection(rule)
    : '';

  return `Analyze the following detection rule for false positive scenarios.

## Rule Format

${format}

## Rule Metadata

${techniqueInfo}
${tacticInfo}
${confidenceInfo}
${ttpInfo ? ttpInfo + '\n' : ''}
## Full Rule

\`\`\`
${raw}
\`\`\`
${docSection}
## Instructions

1. Identify 3-7 specific, realistic false positive scenarios for this rule.
2. Order them by likelihood (highest first).
3. For each scenario, provide actionable tuning advice specific to the ${rule.format} rule format.
4. Assess the overall false positive risk.
5. Provide general recommendations for improving the rule's detection quality.

Respond with ONLY the JSON object.`;
}

/**
 * Build an optional documentation section if the rule has attached
 * documentation metadata.
 */
function buildDocumentationSection(rule: GeneratedRule): string {
  if (!rule.documentation) return '';

  const doc = rule.documentation;
  const lines: string[] = [
    '',
    '## Rule Documentation Context',
    '',
    `- **What it detects**: ${doc.whatItDetects}`,
    `- **How it works**: ${doc.howItWorks}`,
  ];

  if (doc.falsePositives.length > 0) {
    lines.push('- **Known FP hints**:');
    for (const fp of doc.falsePositives) {
      lines.push(`  - ${fp.scenario} (${fp.likelihood})`);
    }
  }

  if (doc.coverageGaps.length > 0) {
    lines.push('- **Coverage gaps**:');
    for (const gap of doc.coverageGaps) {
      lines.push(`  - ${gap}`);
    }
  }

  return lines.join('\n');
}
