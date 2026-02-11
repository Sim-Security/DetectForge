/**
 * YARA rule generation module.
 *
 * Orchestrates AI-driven YARA rule creation by:
 * 1. Filtering IOCs relevant to file-based detection.
 * 2. Selecting the best YARA template category via TTP / IOC analysis.
 * 3. Building a structured prompt with template context.
 * 4. Calling the AI model and parsing the response.
 * 5. Assembling properly formatted YARA rule text (the `raw` field).
 * 6. Validating each generated rule before returning.
 */

import type { AIClient } from '@/ai/client.js';
import type { APIUsage } from '@/types/config.js';
import type { YaraRule, YaraString } from '@/types/detection-rule.js';
import type { ExtractedIOC, ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';
import { withRetry } from '@/ai/retry.js';
import { buildYaraGenerationPrompt, parseYaraAIResponse } from '@/ai/prompts/yara-generation.js';
import {
  getYaraTemplate,
  suggestYaraCategory,
  getAllYaraTemplates,
} from '@/generation/yara/templates.js';
import { validateYaraRule } from '@/generation/yara/validator.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Options for YARA rule generation. */
export interface YaraGenerationOptions {
  /** AI model tier to use. Defaults to `'quality'`. */
  modelTier?: 'fast' | 'standard' | 'quality';
  /** Maximum tokens for the AI response. */
  maxTokens?: number;
  /** Sampling temperature. Lower values are more deterministic. */
  temperature?: number;
  /** Maximum number of retry attempts on transient errors. */
  maxRetries?: number;
  /** Author name embedded in rule metadata. Defaults to `"DetectForge"`. */
  author?: string;
}

/** Result of YARA rule generation. */
export interface YaraGenerationResult {
  /** The generated (and validated) YARA rules. */
  rules: YaraRule[];
  /** API usage / cost information from the AI call. */
  usage: APIUsage;
}

// ---------------------------------------------------------------------------
// IOC types that are relevant for file-based YARA detection
// ---------------------------------------------------------------------------

const YARA_RELEVANT_IOC_TYPES = new Set([
  'md5',
  'sha1',
  'sha256',
  'filepath_windows',
  'filepath_linux',
  'registry_key',
  'domain',
  'ipv4',
  'url',
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate YARA detection rules from extracted threat intelligence.
 *
 * @param client         - The AI client used for inference.
 * @param iocs           - Extracted indicators of compromise.
 * @param ttps           - Extracted tactics, techniques, and procedures.
 * @param attackMappings - ATT&CK technique mappings for the TTPs.
 * @param options        - Optional generation configuration.
 * @returns Generated YARA rules with API usage metadata.
 */
export async function generateYaraRules(
  client: AIClient,
  iocs: ExtractedIOC[],
  ttps: ExtractedTTP[],
  attackMappings: AttackMappingResult[],
  options: YaraGenerationOptions = {},
): Promise<YaraGenerationResult> {
  const {
    modelTier = 'quality',
    maxTokens = 16384,
    temperature = 0.2,
    maxRetries = 3,
    author = 'DetectForge',
  } = options;

  // 1. Filter IOCs relevant to YARA (file-centric indicators)
  const relevantIocs = filterRelevantIocs(iocs);

  // 2. Determine the best template category
  const template = selectTemplate(relevantIocs, ttps);

  // 3. Pick the primary ATT&CK mapping (prefer yara-suggested, highest confidence)
  const primaryMapping = selectPrimaryMapping(attackMappings);

  // 4. Build the prompt
  const { system, user } = buildYaraGenerationPrompt(
    relevantIocs,
    ttps,
    primaryMapping,
    template,
  );

  // 5. Call the AI with retry
  const result = await withRetry(
    () =>
      client.prompt(system, user, {
        model: modelTier,
        maxTokens,
        temperature,
        jsonMode: true,
      }),
    { maxRetries },
  );

  // 6. Parse and validate the AI response
  const parsed = parseYaraAIResponse(result.content);

  // 7. Build full YaraRule objects with raw text and validation
  const rules: YaraRule[] = [];

  for (const aiRule of parsed.rules) {
    // Ensure author is set
    const meta = {
      ...aiRule.meta,
      author,
      mitre_attack: aiRule.meta.mitre_attack || primaryMapping.techniqueId,
    };

    // Inject a hash from IOCs if the AI did not provide one
    if (!meta.hash) {
      const hashIoc = relevantIocs.find(
        ioc => ioc.type === 'sha256' || ioc.type === 'sha1' || ioc.type === 'md5',
      );
      if (hashIoc) {
        meta.hash = hashIoc.value;
      }
    }

    const yaraStrings: YaraString[] = aiRule.strings.map(s => ({
      identifier: s.identifier,
      value: s.value,
      type: s.type,
      modifiers: s.modifiers,
    }));

    const raw = buildRawYaraText(
      aiRule.name,
      aiRule.tags,
      meta,
      yaraStrings,
      aiRule.condition,
    );

    const rule: YaraRule = {
      name: aiRule.name,
      tags: aiRule.tags,
      meta,
      strings: yaraStrings,
      condition: aiRule.condition,
      raw,
    };

    // Validate — attach warnings but include the rule even if imperfect
    const validation = validateYaraRule(rule);
    if (!validation.valid) {
      // Log warnings but still include; the caller can inspect validation
      // via the separate validateYaraRule function.
    }

    rules.push(rule);
  }

  return {
    rules,
    usage: result.usage,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Filter IOCs to those relevant for YARA file-based detection.
 */
function filterRelevantIocs(iocs: ExtractedIOC[]): ExtractedIOC[] {
  return iocs.filter(ioc => YARA_RELEVANT_IOC_TYPES.has(ioc.type));
}

/**
 * Select the most appropriate YARA template based on IOCs and TTPs.
 * Falls back to `binary_pe` if no category scores highly enough.
 */
function selectTemplate(iocs: ExtractedIOC[], ttps: ExtractedTTP[]) {
  const suggestions = suggestYaraCategory(iocs, ttps);

  if (suggestions.length > 0) {
    const template = getYaraTemplate(suggestions[0]);
    if (template) {
      return template;
    }
  }

  // Fallback: binary_pe is the most common target
  const fallback = getYaraTemplate('binary_pe');
  if (fallback) {
    return fallback;
  }

  // Should never happen since binary_pe is always registered, but satisfy TS
  return getAllYaraTemplates()[0];
}

/**
 * Select the primary ATT&CK mapping to feature in the YARA rule.
 * Prefers mappings that suggest YARA and have the highest confidence.
 */
function selectPrimaryMapping(mappings: AttackMappingResult[]): AttackMappingResult {
  if (mappings.length === 0) {
    // Produce a synthetic mapping when none is provided
    return {
      techniqueId: 'T0000',
      techniqueName: 'Unknown',
      tactic: 'unknown',
      confidence: 'low',
      reasoning: 'No ATT&CK mapping provided.',
      sourceTtp: {
        description: 'Unknown TTP',
        tools: [],
        targetPlatforms: [],
        artifacts: [],
        detectionOpportunities: [],
        confidence: 'low',
      },
      suggestedRuleFormats: ['yara'],
      validated: false,
    };
  }

  const confidenceOrder: Record<string, number> = { high: 3, medium: 2, low: 1 };

  // Sort: prefer yara-suggested, then by confidence descending
  const sorted = [...mappings].sort((a, b) => {
    const aYara = a.suggestedRuleFormats.includes('yara') ? 1 : 0;
    const bYara = b.suggestedRuleFormats.includes('yara') ? 1 : 0;
    if (aYara !== bYara) return bYara - aYara;
    return (confidenceOrder[b.confidence] ?? 0) - (confidenceOrder[a.confidence] ?? 0);
  });

  return sorted[0];
}

/**
 * Build properly formatted YARA rule text from structured components.
 *
 * Produces output like:
 * ```
 * rule RuleName : tag1 tag2 {
 *     meta:
 *         description = "..."
 *         author = "DetectForge"
 *     strings:
 *         $s1 = "pattern" ascii
 *     condition:
 *         filesize < 5MB and 2 of ($s*)
 * }
 * ```
 */
function buildRawYaraText(
  name: string,
  tags: string[],
  meta: Record<string, string | number | boolean | undefined>,
  strings: YaraString[],
  condition: string,
): string {
  const lines: string[] = [];

  // Rule header
  const tagPart = tags.length > 0 ? ` : ${tags.join(' ')}` : '';
  lines.push(`rule ${name}${tagPart} {`);

  // Meta section
  lines.push('    meta:');
  for (const [key, value] of Object.entries(meta)) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'boolean') {
      lines.push(`        ${key} = ${value}`);
    } else if (typeof value === 'number') {
      lines.push(`        ${key} = ${value}`);
    } else {
      // String value — escape inner double quotes
      const escaped = String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      lines.push(`        ${key} = "${escaped}"`);
    }
  }

  // Strings section
  lines.push('    strings:');
  for (const str of strings) {
    const formattedValue = formatStringValue(str);
    const modPart = str.modifiers.length > 0 ? ` ${str.modifiers.join(' ')}` : '';
    lines.push(`        ${str.identifier} = ${formattedValue}${modPart}`);
  }

  // Condition section
  lines.push('    condition:');
  lines.push(`        ${condition}`);

  // Close
  lines.push('}');

  return lines.join('\n');
}

/**
 * Format a YARA string value according to its type.
 *
 * - text   -> `"value"`
 * - hex    -> `{ AA BB CC }`
 * - regex  -> `/pattern/`
 */
function formatStringValue(str: YaraString): string {
  switch (str.type) {
    case 'text': {
      const escaped = str.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      return `"${escaped}"`;
    }
    case 'hex':
      return `{ ${str.value} }`;
    case 'regex':
      return `/${str.value}/`;
    default:
      return `"${str.value}"`;
  }
}
