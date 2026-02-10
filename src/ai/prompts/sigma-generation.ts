/**
 * AI prompt templates and response parsing for Sigma rule generation.
 *
 * Builds carefully structured system + user prompts that instruct the AI
 * model to produce Sigma-conformant JSON which is then validated with Zod
 * before being transformed into full {@link SigmaRule} objects.
 */

import { z } from 'zod';
import { extractJsonFromResponse } from '@/ai/response-parser.js';
import type { SigmaTemplate } from '@/generation/sigma/templates.js';
import type { ExtractedTTP, AttackMappingResult, ExtractedIOC } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Zod Schema for the AI response
// ---------------------------------------------------------------------------

/**
 * Schema that the AI model must conform to when generating Sigma rules.
 * The schema intentionally keeps `detection` as a flexible record so that
 * the model can use arbitrary selection names.
 */
export const SigmaAIResponseSchema = z.object({
  title: z
    .string()
    .min(10, 'Title must be at least 10 characters')
    .max(256, 'Title must be at most 256 characters'),
  description: z
    .string()
    .min(20, 'Description must be at least 20 characters'),
  tags: z
    .array(z.string())
    .min(1, 'At least one tag is required'),
  logsource: z.object({
    product: z.string(),
    category: z.string().optional(),
    service: z.string().optional(),
  }),
  detection: z
    .record(z.unknown())
    .refine(
      (det) => typeof det['condition'] === 'string',
      { message: 'detection must contain a "condition" key of type string' },
    ),
  falsepositives: z.array(z.string()).default([]),
  level: z.enum(['informational', 'low', 'medium', 'high', 'critical']),
});

/** Inferred TypeScript type from the schema. */
export type SigmaAIResponse = z.infer<typeof SigmaAIResponseSchema>;

// ---------------------------------------------------------------------------
// Response Parser
// ---------------------------------------------------------------------------

/**
 * Parse the raw string returned by the AI model into a validated
 * {@link SigmaAIResponse}.
 *
 * Handles markdown code fences and minor JSON issues via
 * {@link extractJsonFromResponse}.
 *
 * @param raw - The raw AI response text.
 * @returns A validated Sigma AI response object.
 * @throws When the response cannot be parsed or fails Zod validation.
 */
export function parseSigmaAIResponse(raw: string): SigmaAIResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return SigmaAIResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors
        .map((err) => `  - ${err.path.join('.')}: ${err.message}`)
        .join('\n');
      throw new Error(
        `Sigma AI response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`,
      );
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Prompt Builders
// ---------------------------------------------------------------------------

/**
 * Build the system and user prompts for Sigma rule generation.
 *
 * The system prompt establishes the persona, the Sigma specification context,
 * the target logsource template, and a concrete example.  The user prompt
 * supplies the specific TTP details, ATT&CK mapping, and any IOCs that
 * should be woven into the detection logic.
 *
 * @param ttp      - The extracted TTP from a threat report.
 * @param mapping  - The ATT&CK mapping for this TTP.
 * @param template - The Sigma logsource template to use.
 * @param iocs     - Relevant IOCs that could enrich detection logic.
 * @returns An object with `system` and `user` prompt strings.
 */
export function buildSigmaGenerationPrompt(
  ttp: ExtractedTTP,
  mapping: AttackMappingResult,
  template: SigmaTemplate,
  iocs: ExtractedIOC[],
): { system: string; user: string } {
  const system = buildSystemPrompt(template);
  const user = buildUserPrompt(ttp, mapping, template, iocs);
  return { system, user };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Build the system prompt with Sigma specification context.
 */
function buildSystemPrompt(template: SigmaTemplate): string {
  const logsourceYaml = formatLogsourceBlock(template.logsource);
  const fieldsBlock = template.availableFields
    .map((f) => `  - ${f}`)
    .join('\n');
  const exampleDetectionJson = JSON.stringify(template.exampleDetection, null, 2);

  return `You are an expert detection engineer specializing in Sigma rule creation.
Your task is to generate a single, high-quality Sigma detection rule in JSON format.

## Sigma Rule Specification

A valid Sigma rule requires the following fields:
- **title**: A clear, descriptive title (10-256 characters). Use the format: "<Action> <What> via <How/Where>".
- **description**: A detailed explanation of what the rule detects and why it matters (min 20 chars).
- **tags**: Array of ATT&CK tags in the formats:
  - Tactic: \`attack.tactic_name\` (lowercase, underscores for spaces, e.g. \`attack.defense_evasion\`)
  - Technique: \`attack.tNNNN\` (lowercase t, e.g. \`attack.t1059\`)
  - Sub-technique: \`attack.tNNNN.NNN\` (e.g. \`attack.t1059.001\`)
- **logsource**: The log source this rule applies to (product, category, service).
- **detection**: One or more named selection/filter blocks plus a \`condition\` string that references them.
- **falsepositives**: Array of known false-positive scenarios.
- **level**: One of: informational, low, medium, high, critical.

## Detection Block Rules

- Name selection blocks descriptively: \`selection_process\`, \`selection_commandline\`, \`filter_legitimate\`, etc.
- Use lists for OR logic within a field: \`CommandLine: ["*-enc*", "*-encoded*"]\`
- Use wildcards (\`*\`) for partial matching.
- The \`condition\` field is a boolean expression referencing selection names: \`selection and not filter_legitimate\`
- Prefer specific field values over overly broad wildcards.
- Combine multiple selections with \`and\`/\`or\`/\`not\` in the condition.

## Target Logsource

Your rule MUST use this logsource:
\`\`\`yaml
logsource:
${logsourceYaml}
\`\`\`

## Available Fields for This Logsource

${fieldsBlock}

Only use fields from the list above. Do not invent fields that do not exist in this logsource.

## Example Detection Block

\`\`\`json
${exampleDetectionJson}
\`\`\`

## Example of a High-Quality Sigma Rule (for reference)

\`\`\`json
{
  "title": "Suspicious PowerShell Download Cradle via Invoke-WebRequest",
  "description": "Detects execution of PowerShell with download cradle patterns commonly used by threat actors to fetch and execute remote payloads. These patterns are frequently observed in initial access and execution phases of intrusions.",
  "tags": ["attack.execution", "attack.t1059.001", "attack.command_and_control", "attack.t1105"],
  "logsource": {
    "product": "windows",
    "category": "process_creation"
  },
  "detection": {
    "selection_parent": {
      "ParentImage": ["*\\\\cmd.exe", "*\\\\explorer.exe", "*\\\\mshta.exe"]
    },
    "selection_ps": {
      "Image": ["*\\\\powershell.exe", "*\\\\pwsh.exe"],
      "CommandLine": ["*Invoke-WebRequest*", "*iwr *", "*wget *", "*Net.WebClient*", "*DownloadString*", "*DownloadFile*"]
    },
    "condition": "selection_parent and selection_ps"
  },
  "falsepositives": [
    "Administrative scripts that download updates or configuration files",
    "Developer toolchains that fetch packages"
  ],
  "level": "high"
}
\`\`\`

## Output Format

Respond with ONLY a JSON object (no markdown fences, no explanation) matching the structure above.
Do NOT include fields like id, status, date, author, or raw — those are added programmatically.`;
}

/**
 * Build the user prompt with TTP-specific details.
 */
function buildUserPrompt(
  ttp: ExtractedTTP,
  mapping: AttackMappingResult,
  template: SigmaTemplate,
  iocs: ExtractedIOC[],
): string {
  const toolsList = ttp.tools.length > 0
    ? ttp.tools.join(', ')
    : 'None specified';

  const artifactsList = ttp.artifacts.length > 0
    ? ttp.artifacts
        .map((a) => `  - [${a.type}] ${a.description}${a.value ? ` (value: ${a.value})` : ''}`)
        .join('\n')
    : '  None specified';

  const detectionOpps = ttp.detectionOpportunities.length > 0
    ? ttp.detectionOpportunities.map((d) => `  - ${d}`).join('\n')
    : '  None specified';

  const relevantIocs = filterRelevantIocs(iocs, template.category);
  const iocsBlock = relevantIocs.length > 0
    ? relevantIocs
        .map((ioc) => `  - [${ioc.type}] ${ioc.value} (confidence: ${ioc.confidence})`)
        .join('\n')
    : '  None available';

  const fieldsBlock = template.availableFields
    .map((f) => `  - ${f}`)
    .join('\n');

  return `Generate a Sigma detection rule for the following threat activity.

## Threat Technique

- **ATT&CK Technique**: ${mapping.techniqueId} — ${mapping.techniqueName}
- **Tactic**: ${mapping.tactic}
- **Confidence**: ${mapping.confidence}
- **Mapping Rationale**: ${mapping.reasoning}

## TTP Description

${ttp.description}

## Tools Used

${toolsList}

## Artifacts Observed

${artifactsList}

## Detection Opportunities

${detectionOpps}

## Relevant IOCs

${iocsBlock}

## Target Logsource Category

${template.category}

## Available Fields

${fieldsBlock}

## Requirements

1. The rule MUST detect the specific behavior described above, not generic activity.
2. Include at least one selection block with concrete field values derived from the TTP details.
3. Where possible, incorporate relevant IOCs (file paths, process names, command-line patterns, domains, IPs) into the detection logic.
4. Add a filter block to reduce false positives if appropriate.
5. Use the \`condition\` field to combine selections and filters logically.
6. Set the \`level\` based on the threat severity and detection confidence.
7. Write actionable \`falsepositives\` entries that help analysts tune the rule.
8. The \`tags\` array MUST include the tactic as \`attack.<tactic>\` and the technique as \`attack.t<id>\` (lowercase).

Respond with ONLY the JSON object.`;
}

/**
 * Format a logsource object into indented YAML lines (for prompt embedding).
 */
function formatLogsourceBlock(
  logsource: { product: string; category?: string; service?: string },
): string {
  const lines: string[] = [];
  lines.push(`  product: ${logsource.product}`);
  if (logsource.category) {
    lines.push(`  category: ${logsource.category}`);
  }
  if (logsource.service) {
    lines.push(`  service: ${logsource.service}`);
  }
  return lines.join('\n');
}

/**
 * Filter IOCs to those most relevant for a given logsource category.
 *
 * For example, network-oriented categories benefit from IP/domain IOCs,
 * while process categories benefit from file path and hash IOCs.
 */
function filterRelevantIocs(
  iocs: ExtractedIOC[],
  category: string,
): ExtractedIOC[] {
  const networkCategories = new Set([
    'network_connection',
    'dns_query',
  ]);
  const fileCategories = new Set([
    'process_creation',
    'image_load',
    'file_event',
  ]);
  const registryCategories = new Set([
    'registry_event',
  ]);

  return iocs.filter((ioc) => {
    if (networkCategories.has(category)) {
      return ['ipv4', 'ipv6', 'domain', 'url'].includes(ioc.type);
    }
    if (fileCategories.has(category)) {
      return [
        'filepath_windows',
        'filepath_linux',
        'md5',
        'sha1',
        'sha256',
        'domain',
        'url',
      ].includes(ioc.type);
    }
    if (registryCategories.has(category)) {
      return ['registry_key', 'filepath_windows'].includes(ioc.type);
    }
    // For other categories, include all IOCs
    return true;
  });
}
