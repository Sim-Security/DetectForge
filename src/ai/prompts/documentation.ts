/**
 * AI prompt templates and response parsing for detection rule documentation.
 *
 * Builds structured system + user prompts that instruct the AI model to
 * produce comprehensive rule documentation in JSON format, which is then
 * validated with Zod before being returned as a {@link RuleDocumentation}
 * object suitable for SOC analyst consumption.
 */

import { z } from 'zod';
import { extractJsonFromResponse } from '@/ai/response-parser.js';
import type { GeneratedRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Zod Schema for the AI response
// ---------------------------------------------------------------------------

/**
 * Schema for a single false-positive scenario returned by the AI.
 */
const FalsePositiveScenarioSchema = z.object({
  scenario: z
    .string()
    .min(5, 'Scenario description must be at least 5 characters'),
  likelihood: z.enum(['high', 'medium', 'low']),
  tuningAdvice: z
    .string()
    .min(5, 'Tuning advice must be at least 5 characters'),
});

/**
 * Schema for the ATT&CK mapping block within the documentation response.
 */
const AttackMappingSchema = z.object({
  techniqueId: z
    .string()
    .regex(/^T\d{4}(\.\d{3})?$/, 'Invalid ATT&CK technique ID format'),
  techniqueName: z
    .string()
    .min(1, 'Technique name must not be empty'),
  tactic: z
    .string()
    .min(1, 'Tactic must not be empty'),
  platform: z
    .string()
    .min(1, 'Platform must not be empty'),
});

/**
 * Schema that the AI model must conform to when generating rule documentation.
 * Mirrors the {@link RuleDocumentation} interface from detection-rule types.
 */
export const DocumentationAIResponseSchema = z.object({
  whatItDetects: z
    .string()
    .min(20, 'whatItDetects must be at least 20 characters'),
  howItWorks: z
    .string()
    .min(20, 'howItWorks must be at least 20 characters'),
  attackMapping: AttackMappingSchema,
  falsePositives: z
    .array(FalsePositiveScenarioSchema)
    .min(1, 'At least one false-positive scenario is required'),
  coverageGaps: z
    .array(z.string().min(1))
    .min(1, 'At least one coverage gap must be identified'),
  recommendedLogSources: z
    .array(z.string().min(1))
    .min(1, 'At least one recommended log source is required'),
  tuningRecommendations: z
    .array(z.string().min(1))
    .min(1, 'At least one tuning recommendation is required'),
});

/** Inferred TypeScript type from the schema. */
export type DocumentationAIResponse = z.infer<typeof DocumentationAIResponseSchema>;

// ---------------------------------------------------------------------------
// Response Parser
// ---------------------------------------------------------------------------

/**
 * Parse the raw string returned by the AI model into a validated
 * {@link DocumentationAIResponse}.
 *
 * Handles markdown code fences and minor JSON issues via
 * {@link extractJsonFromResponse}.
 *
 * @param raw - The raw AI response text.
 * @returns A validated documentation AI response object.
 * @throws When the response cannot be parsed or fails Zod validation.
 */
export function parseDocumentationAIResponse(raw: string): DocumentationAIResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return DocumentationAIResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors
        .map((err) => `  - ${err.path.join('.')}: ${err.message}`)
        .join('\n');
      throw new Error(
        `Documentation AI response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`,
      );
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Prompt Builder
// ---------------------------------------------------------------------------

/**
 * Build the system and user prompts for detection rule documentation
 * generation.
 *
 * The system prompt establishes the persona of a detection engineering
 * documentation expert. The user prompt supplies the rule details including
 * its format, raw text, ATT&CK mapping, and confidence level so the AI
 * can produce contextually accurate documentation.
 *
 * @param rule - The generated detection rule to document.
 * @returns An object with `system` and `user` prompt strings.
 */
export function buildDocumentationPrompt(
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
 * Build the system prompt with documentation expert persona and quality
 * guidelines.
 */
function buildSystemPrompt(): string {
  return `You are an expert detection engineering documentation specialist. Your role is to produce clear, comprehensive, and actionable documentation for security detection rules that will be used by SOC analysts in operational environments.

## Documentation Quality Principles

Good rule documentation for SOC analysts must:

1. **Explain the "what" clearly**: Describe the specific threat behavior or attacker technique the rule detects in plain language. Avoid jargon where possible; where technical terms are necessary, provide brief context.
2. **Explain the "how" in detail**: Walk through the detection logic step-by-step so an analyst understands exactly which log fields, values, and conditions trigger the rule. This enables analysts to investigate alerts effectively.
3. **Map to ATT&CK precisely**: Provide the correct MITRE ATT&CK technique ID, name, tactic, and applicable platform. This enables analysts to contextualize the alert within the broader kill chain.
4. **Anticipate false positives**: List realistic scenarios where the rule may fire on benign activity. For each scenario, assess the likelihood (high/medium/low) and provide concrete tuning advice so teams can reduce noise without losing coverage.
5. **Identify coverage gaps**: Honestly state what the rule does NOT detect. This prevents false confidence and helps teams plan complementary detections.
6. **Recommend log sources**: List the specific log sources (products, event IDs, categories) that must be collected for the rule to function correctly.
7. **Provide tuning guidance**: Offer practical recommendations for threshold adjustments, allowlist additions, field value refinements, and environmental customization.

## Output Format

Respond with ONLY a JSON object (no markdown fences, no explanation) matching this structure:

\`\`\`json
{
  "whatItDetects": "A clear, 2-4 sentence explanation of the threat behavior this rule detects.",
  "howItWorks": "A detailed, 3-6 sentence explanation of the detection logic, referencing specific fields and conditions.",
  "attackMapping": {
    "techniqueId": "T1059.001",
    "techniqueName": "PowerShell",
    "tactic": "Execution",
    "platform": "Windows"
  },
  "falsePositives": [
    {
      "scenario": "Description of a realistic false-positive scenario.",
      "likelihood": "medium",
      "tuningAdvice": "Specific advice to mitigate this false positive."
    }
  ],
  "coverageGaps": [
    "Description of a specific detection gap or evasion technique not covered."
  ],
  "recommendedLogSources": [
    "Specific log source required for this rule (e.g., Windows Security Event Log 4688)."
  ],
  "tuningRecommendations": [
    "Specific, actionable tuning recommendation."
  ]
}
\`\`\`

## Important Requirements

- The \`techniqueId\` MUST be a valid ATT&CK technique ID in the format \`TNNNN\` or \`TNNNN.NNN\`.
- Provide at least 1 false-positive scenario, 1 coverage gap, 1 recommended log source, and 1 tuning recommendation.
- Be specific and actionable — avoid vague advice like "tune as needed" or "monitor for anomalies."
- Tailor the documentation to the specific rule format (Sigma, YARA, or Suricata) and its detection context.
- Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.`;
}

/**
 * Build the user prompt with rule-specific details for documentation.
 */
function buildUserPrompt(rule: GeneratedRule): string {
  const ruleText = extractRuleText(rule);
  const ruleTitle = extractRuleTitle(rule);
  const ruleDescription = extractRuleDescription(rule);

  const attackInfo = rule.attackTechniqueId
    ? `- **ATT&CK Technique**: ${rule.attackTechniqueId}`
    : '- **ATT&CK Technique**: Not specified';

  const tacticInfo = rule.attackTactic
    ? `- **ATT&CK Tactic**: ${rule.attackTactic}`
    : '- **ATT&CK Tactic**: Not specified';

  return `Generate comprehensive documentation for the following detection rule.

## Rule Overview

- **Format**: ${rule.format.toUpperCase()}
- **Title**: ${ruleTitle}
- **Description**: ${ruleDescription}
${attackInfo}
${tacticInfo}
- **Confidence**: ${rule.confidence}

## Rule Content

\`\`\`
${ruleText}
\`\`\`

## Instructions

1. Analyze the rule content above and produce documentation following the JSON schema provided in the system prompt.
2. The \`whatItDetects\` field should describe the threat behavior in plain language suitable for a SOC analyst who may not be deeply familiar with the specific technique.
3. The \`howItWorks\` field should walk through the detection logic of this specific rule, referencing the actual fields, values, and conditions used.
4. For \`attackMapping\`, use the ATT&CK technique information provided above. If the technique ID is not specified, infer the most appropriate mapping from the rule content.
5. For \`falsePositives\`, think about realistic operational environments — legitimate admin tools, DevOps pipelines, security scanners, etc. that could trigger this rule.
6. For \`coverageGaps\`, consider evasion techniques, encoding tricks, alternative tools, or environmental variations that would bypass this rule.
7. For \`recommendedLogSources\`, list the specific log sources, event IDs, or data feeds required for this rule to work correctly.
8. For \`tuningRecommendations\`, provide specific field values, thresholds, or allowlists that operators should customize for their environment.

Respond with ONLY the JSON object.`;
}

/**
 * Extract the raw rule text from a {@link GeneratedRule}, falling back
 * to a descriptive placeholder if no raw text is available.
 */
function extractRuleText(rule: GeneratedRule): string {
  if (rule.format === 'sigma' && rule.sigma) {
    return rule.sigma.raw || formatSigmaSummary(rule);
  }
  if (rule.format === 'yara' && rule.yara) {
    return rule.yara.raw || `YARA rule: ${rule.yara.name}`;
  }
  if (rule.format === 'suricata' && rule.suricata) {
    return rule.suricata.raw || `Suricata rule (SID: ${rule.suricata.sid})`;
  }
  return `[No raw rule text available — format: ${rule.format}]`;
}

/**
 * Extract the rule title from a {@link GeneratedRule}.
 */
function extractRuleTitle(rule: GeneratedRule): string {
  if (rule.format === 'sigma' && rule.sigma) {
    return rule.sigma.title;
  }
  if (rule.format === 'yara' && rule.yara) {
    return rule.yara.name;
  }
  if (rule.format === 'suricata' && rule.suricata) {
    const msgOption = rule.suricata.options.find((opt) => opt.keyword === 'msg');
    return msgOption?.value || `Suricata SID ${rule.suricata.sid}`;
  }
  return 'Untitled Rule';
}

/**
 * Extract the rule description from a {@link GeneratedRule}.
 */
function extractRuleDescription(rule: GeneratedRule): string {
  if (rule.format === 'sigma' && rule.sigma) {
    return rule.sigma.description;
  }
  if (rule.format === 'yara' && rule.yara) {
    return rule.yara.meta.description;
  }
  if (rule.format === 'suricata' && rule.suricata) {
    const msgOption = rule.suricata.options.find((opt) => opt.keyword === 'msg');
    return msgOption?.value || 'No description available';
  }
  return 'No description available';
}

/**
 * Build a concise summary of a Sigma rule when the raw YAML is not available.
 */
function formatSigmaSummary(rule: GeneratedRule): string {
  if (!rule.sigma) {
    return '[Sigma rule data missing]';
  }

  const sigma = rule.sigma;
  const lines: string[] = [];

  lines.push(`title: ${sigma.title}`);
  lines.push(`description: ${sigma.description}`);
  lines.push(`level: ${sigma.level}`);
  lines.push(`status: ${sigma.status}`);

  if (sigma.logsource.product) {
    lines.push(`logsource.product: ${sigma.logsource.product}`);
  }
  if (sigma.logsource.category) {
    lines.push(`logsource.category: ${sigma.logsource.category}`);
  }
  if (sigma.logsource.service) {
    lines.push(`logsource.service: ${sigma.logsource.service}`);
  }

  lines.push(`condition: ${sigma.detection.condition}`);
  lines.push(`tags: ${sigma.tags.join(', ')}`);

  if (sigma.falsepositives.length > 0) {
    lines.push(`falsepositives: ${sigma.falsepositives.join('; ')}`);
  }

  return lines.join('\n');
}
