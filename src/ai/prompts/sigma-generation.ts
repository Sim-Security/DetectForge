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
import type { SigmaReferenceRule } from '@/knowledge/sigma-reference/loader.js';

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
  referenceRules?: SigmaReferenceRule[],
  behavioralFeedback?: string,
): { system: string; user: string } {
  const system = buildSystemPrompt(template, referenceRules);
  const user = buildUserPrompt(ttp, mapping, template, iocs, behavioralFeedback);
  return { system, user };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Build the system prompt with Sigma specification context.
 */
function buildSystemPrompt(
  template: SigmaTemplate,
  referenceRules?: SigmaReferenceRule[],
): string {
  const logsourceYaml = formatLogsourceBlock(template.logsource);
  const fieldsBlock = template.availableFields
    .map((f) => `  - ${f}`)
    .join('\n');
  const exampleDetectionJson = JSON.stringify(template.exampleDetection, null, 2);
  const referenceBlock = buildReferenceBlock(referenceRules);

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
- **falsepositives**: Array of known false-positive scenarios (MINIMUM 2 entries).
- **level**: One of: informational, low, medium, high, critical.

## Detection Block Rules

- Name selection blocks descriptively: \`selection_process\`, \`selection_commandline\`, \`filter_legitimate\`, etc.
- Use lists for OR logic within a field: \`CommandLine: ["*-enc*", "*-encoded*"]\`
- Use wildcards (\`*\`) for partial matching.
- The \`condition\` field is a boolean expression referencing selection names: \`selection and not filter_legitimate\`
- Prefer specific field values over overly broad wildcards.
- Combine multiple selections with \`and\`/\`or\`/\`not\` in the condition.
- Aggregation syntax is supported: \`selection | count(FieldName) by GroupField > N\`
- **CRITICAL**: The condition MUST ONLY use these operators: \`and\`, \`or\`, \`not\`, \`|\`, \`count()\`, \`by\`, \`near\`, \`>\`, \`<\`, \`>=\`, \`<=\`, \`==\`, and references to detection block key names. NEVER use natural language words like "followed by", "then", "before", "after", "within" in the condition — these are NOT valid Sigma syntax.
- If you need to express temporal correlation (e.g. failures followed by success), use a combined condition like \`(selection_failures or selection_success) and not filter\` — do NOT try to express ordering.

## STRICT Field Constraints

Your rule MUST use this logsource:
\`\`\`yaml
logsource:
${logsourceYaml}
\`\`\`

**ONLY use these fields in your detection blocks** — do NOT invent or use ANY fields not in this list:

${fieldsBlock}

This is a HARD CONSTRAINT. Using fields outside this list will cause the rule to fail validation. For example, do NOT use \`EventID\` in a process_creation logsource — it does not exist there. Do NOT use \`IpAddress\` in a process_creation logsource.

WARNING: OriginalFileName, Company, Product, and Description are PE metadata fields.
They are trivially spoofable by attackers and absent in many log sources.
Use them ONLY as supplementary filters, NEVER as primary selection criteria.

## Detection Quality Requirements

### 1. MANDATORY: Include Filter/Exclusion Block
Every rule MUST include at least one \`filter_*\` or \`exclusion_*\` block to reduce false positives. The condition MUST use \`not\` to exclude legitimate activity. Rules without filters are rejected.

Good: \`"condition": "selection and not filter_legitimate"\`
Bad: \`"condition": "selection"\` (no filter = too many false positives)

### 2. MANDATORY: Behavioral Detection Over Static IOCs
Prefer behavioral patterns (command-line arguments, process relationships, registry paths, API calls) over static IOC matching (specific IP addresses, domains, hashes). IOCs change constantly; behaviors persist across campaigns.

- Good: Detecting \`powershell.exe -encodedcommand *\` (behavioral pattern)
- Bad: Detecting connections to \`198.51.100.42\` (static IOC that changes)

IOCs may be used to ENRICH behavioral detections (e.g. as additional selection criteria) but should NOT be the sole detection logic.

### 3. MANDATORY: Multiple Selection Blocks
Use at least 2 named selection blocks to create layered detection logic. Single-selection rules are too broad.

## BAD vs GOOD Detection Patterns

BAD: Tool-signature detection (attacker renames binary and rule breaks):
  selection: { Image: "*\\\\mimikatz.exe" }

GOOD: OS-behavior detection (works regardless of tool):
  selection_target: { "TargetImage|endswith": "\\\\lsass.exe" }
  selection_access: { GrantedAccess: ["0x1010", "0x1038", "0x1fffff"] }

BAD: Single technique variant
  selection: { CommandLine: "*sekurlsa::logonpasswords*" }

GOOD: Multiple variants ORed together
  selection_comsvcs: { "CommandLine|contains|all": ["comsvcs", "MiniDump"] }
  selection_procdump: { "CommandLine|contains|all": ["procdump", "lsass"] }
  selection_generic: { "CommandLine|contains": "lsass" }
  condition: selection_comsvcs or selection_procdump or selection_generic

BAD: Ignoring ParentCommandLine
  selection: { "CommandLine|contains": "-encodedcommand" }

GOOD: Checking both CommandLine and ParentCommandLine
  selection_direct: { "CommandLine|contains": "-enc" }
  selection_parent: { "ParentCommandLine|contains": "-enc" }
  condition: selection_direct or selection_parent

## Parent-Child Process Relationships
When detecting execution techniques (T1059.*), ALWAYS check BOTH
CommandLine AND ParentCommandLine. Attack frameworks spawn child
processes; the encoded command appears in the PARENT's command line.
A rule checking only CommandLine misses 70%+ of real attack data.

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
    "filter_legitimate": {
      "ParentImage": ["*\\\\svchost.exe", "*\\\\services.exe"],
      "User": ["NT AUTHORITY\\\\SYSTEM", "NT AUTHORITY\\\\LOCAL SERVICE"]
    },
    "condition": "selection_parent and selection_ps and not filter_legitimate"
  },
  "falsepositives": [
    "Administrative scripts that download updates or configuration files via PowerShell from internal repositories",
    "Developer toolchains that fetch packages using Invoke-WebRequest in CI/CD pipelines"
  ],
  "level": "high"
}
\`\`\`
${referenceBlock}
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
  behavioralFeedback?: string,
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

## Tools Used (context only — DO NOT detect by tool filename)

${toolsList}

IMPORTANT: Tool names describe what the attacker used. Your rule must NOT
rely on tool filenames. Attackers rename tools, load in-memory, or use
LOLBins. Detect the TECHNIQUE BEHAVIOR, not the tool binary.

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

1. The rule MUST detect the specific **behavior** described above, not generic activity. Focus on command-line patterns, process relationships, registry modifications, and API calls — NOT static IOCs like IP addresses or domains.
2. Include at least **2 named selection blocks** with concrete field values derived from the TTP details.
3. **MANDATORY**: Include at least one \`filter_*\` or \`exclusion_*\` block to exclude legitimate activity. The condition MUST use \`not\` to reference it.
4. **ONLY use fields from the Available Fields list above.** Using any other field will cause the rule to FAIL validation.
5. Use the \`condition\` field to combine selections and filters logically (e.g. \`selection_process and selection_args and not filter_legitimate\`).
6. Set the \`level\` based on the threat severity and detection confidence.
7. Write at least **2 actionable \`falsepositives\` entries** that help analysts tune the rule.
8. The \`tags\` array MUST include the tactic as \`attack.<tactic>\` and the technique as \`attack.t<id>\` (lowercase).
9. IOCs may ENRICH behavioral selections (e.g. known tool names in CommandLine) but must NOT be the sole detection logic.

Respond with ONLY the JSON object.${behavioralFeedback ? `\n\n---\n\n${behavioralFeedback}` : ''}`;
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
 * Build a reference block from SigmaHQ rules for the same ATT&CK technique.
 * Gives the model concrete examples of production-quality detection logic.
 */
function buildReferenceBlock(referenceRules?: SigmaReferenceRule[]): string {
  if (!referenceRules || referenceRules.length === 0) return '\n';

  // Take at most 2 reference rules to keep prompt concise
  const selected = referenceRules.slice(0, 2);
  const rulesText = selected
    .map((r, i) => {
      const detectionYaml = Object.entries(r.detection)
        .map(([key, value]) => {
          if (typeof value === 'string') return `    ${key}: ${value}`;
          return `    ${key}: ${JSON.stringify(value)}`;
        })
        .join('\n');

      return `### Reference ${i + 1}: ${r.title}
- **Level**: ${r.level}
- **Logsource**: product=${r.logsource.product ?? 'N/A'}, category=${r.logsource.category ?? 'N/A'}
\`\`\`
detection:
${detectionYaml}
\`\`\``;
    })
    .join('\n\n');

  return `
## SigmaHQ Reference Rules (same ATT&CK technique)

Study these production SigmaHQ rules for the same technique. Note the field choices, filter patterns, and condition structure:

${rulesText}

Use these as inspiration for detection patterns, but adapt them to the specific TTP described in the user prompt.

`;
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
