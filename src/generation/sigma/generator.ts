/**
 * Sigma rule generator.
 *
 * Orchestrates the end-to-end process of converting extracted TTPs and IOCs
 * into validated Sigma detection rules.  For each TTP with an ATT&CK
 * mapping the generator:
 *
 * 1. Determines the best logsource category via {@link getSuggestedCategory}.
 * 2. Retrieves the matching template and builds an AI prompt.
 * 3. Sends the prompt to the AI model, parses the response.
 * 4. Enriches the response with UUID, date, author, and YAML serialization.
 * 5. Validates the resulting rule.
 */

import YAML from 'yaml';
import { v4 as uuidv4 } from 'uuid';

import type { AIClient } from '@/ai/client.js';
import type { APIUsage } from '@/types/config.js';
import type { SigmaRule, SigmaDetection } from '@/types/detection-rule.js';
import type { ExtractedTTP, AttackMappingResult, ExtractedIOC } from '@/types/extraction.js';

import { withRetry } from '@/ai/retry.js';
import { buildSigmaGenerationPrompt, parseSigmaAIResponse } from '@/ai/prompts/sigma-generation.js';
import type { SigmaAIResponse } from '@/ai/prompts/sigma-generation.js';
import { getTemplate, getSuggestedCategory } from './templates.js';
import type { SigmaTemplate } from './templates.js';
import { analyzeToolSignatureDependence } from '@/testing/quality-scorer.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/**
 * Options for the Sigma rule generation pipeline.
 */
export interface SigmaGenerationOptions {
  /** AI model tier to use (default: "quality"). */
  modelTier?: 'fast' | 'standard' | 'quality';
  /** Maximum tokens for the AI response (default: 2048). */
  maxTokens?: number;
  /** Sampling temperature (default: 0.2). */
  temperature?: number;
  /** Maximum retry attempts on transient AI errors (default: 3). */
  maxRetries?: number;
  /** Author name to embed in generated rules (default: "DetectForge"). */
  author?: string;
}

/**
 * Result of a Sigma rule generation run.
 */
export interface SigmaGenerationResult {
  /** Successfully generated rules. */
  rules: SigmaRule[];
  /** Aggregated API usage across all generation calls. */
  usage: APIUsage;
}

// ---------------------------------------------------------------------------
// Default Configuration
// ---------------------------------------------------------------------------

const DEFAULT_OPTIONS: Required<SigmaGenerationOptions> = {
  modelTier: 'quality',
  maxTokens: 16384,
  temperature: 0.2,
  maxRetries: 3,
  author: 'DetectForge',
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate Sigma detection rules from extracted TTPs and their ATT&CK
 * mappings.
 *
 * Each TTP that has a corresponding entry in `attackMappings` (matched by
 * reference equality on `sourceTtp`) produces one or more Sigma rules,
 * one per suggested logsource category.
 *
 * @param client         - The AI client used for inference.
 * @param ttps           - Extracted TTPs from a threat report.
 * @param attackMappings - ATT&CK technique mappings for those TTPs.
 * @param iocs           - Extracted IOCs to enrich detection logic.
 * @param options        - Generation options.
 * @returns Generated rules and aggregated API usage.
 */
export async function generateSigmaRules(
  client: AIClient,
  _ttps: ExtractedTTP[],
  attackMappings: AttackMappingResult[],
  iocs: ExtractedIOC[],
  options?: SigmaGenerationOptions,
): Promise<SigmaGenerationResult> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const rules: SigmaRule[] = [];
  const usageEntries: APIUsage[] = [];

  for (const mapping of attackMappings) {
    // Only generate rules for mappings that suggest sigma format
    if (
      mapping.suggestedRuleFormats.length > 0 &&
      !mapping.suggestedRuleFormats.includes('sigma')
    ) {
      continue;
    }

    const ttp = mapping.sourceTtp;

    // Determine the best logsource category for this TTP
    const suggestedCategories = getSuggestedCategory(ttp, mapping);

    // Generate a rule for the primary (first) suggested category only
    // to avoid flooding with near-duplicate rules.
    const primaryCategory = suggestedCategories[0];
    const template = getTemplate(primaryCategory);
    if (!template) {
      continue;
    }

    try {
      const result = await generateSingleRule(
        client,
        ttp,
        mapping,
        template,
        iocs,
        opts,
      );

      if (result.rule) {
        rules.push(result.rule);
      }
      usageEntries.push(result.usage);
    } catch {
      // Log and continue — a single failed generation should not abort
      // the entire batch.
      continue;
    }
  }

  return {
    rules,
    usage: aggregateUsage(usageEntries),
  };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Maximum number of behavioral quality retries before accepting best attempt.
 */
const MAX_BEHAVIORAL_RETRIES = 2;

/**
 * Generate a single Sigma rule for one TTP + template combination.
 *
 * If the initial rule relies on tool-specific filenames without behavioral
 * fields, the generator retries up to {@link MAX_BEHAVIORAL_RETRIES} times
 * with explicit behavioral feedback appended to the prompt.
 */
async function generateSingleRule(
  client: AIClient,
  ttp: ExtractedTTP,
  mapping: AttackMappingResult,
  template: SigmaTemplate,
  iocs: ExtractedIOC[],
  opts: Required<SigmaGenerationOptions>,
): Promise<{ rule: SigmaRule | null; usage: APIUsage }> {
  let bestRule: SigmaRule | null = null;
  const usageEntries: APIUsage[] = [];

  for (let attempt = 0; attempt <= MAX_BEHAVIORAL_RETRIES; attempt++) {
    const feedback = attempt > 0 && bestRule
      ? buildBehavioralFeedback(bestRule)
      : undefined;

    const { system, user } = buildSigmaGenerationPrompt(
      ttp, mapping, template, iocs, undefined, feedback,
    );

    const result = await withRetry(
      () =>
        client.prompt(system, user, {
          model: opts.modelTier,
          maxTokens: opts.maxTokens,
          temperature: opts.temperature,
        }),
      { maxRetries: opts.maxRetries },
    );

    usageEntries.push(result.usage);

    let aiResponse: SigmaAIResponse;
    try {
      aiResponse = parseSigmaAIResponse(result.content);
    } catch {
      if (bestRule) break; // Return best previous attempt
      return { rule: null, usage: aggregateUsage(usageEntries) };
    }

    const rule = buildSigmaRule(aiResponse, mapping, opts.author);
    bestRule = rule;

    // Check behavioral quality — if acceptable, return immediately
    const quality = assessBehavioralQuality(rule);
    if (quality.acceptable) {
      return { rule, usage: aggregateUsage(usageEntries) };
    }

    // Otherwise continue retry loop with feedback
  }

  // After max retries, return best attempt
  return { rule: bestRule, usage: aggregateUsage(usageEntries) };
}

/**
 * Assess whether a rule's detection logic meets behavioral quality standards.
 *
 * Rejects rules whose primary detection relies solely on tool-specific
 * filenames with no behavioral fields (GrantedAccess, CallTrace, etc.).
 */
export function assessBehavioralQuality(rule: SigmaRule): {
  acceptable: boolean;
  reasons: string[];
} {
  const analysis = analyzeToolSignatureDependence(rule);
  const reasons: string[] = [];

  if (analysis.primaryIsToolSignature && !analysis.hasBehavioralFields) {
    reasons.push(
      `Primary detection relies on tool-specific filename only (${analysis.toolNames.join(', ')})`,
    );
  }

  if (analysis.detectionVariantCount < 2 && !analysis.hasBehavioralFields) {
    reasons.push('Single variant with no behavioral fields');
  }

  return { acceptable: reasons.length === 0, reasons };
}

/**
 * Build behavioral feedback text to append to the user prompt when a
 * previous attempt was rejected for tool-signature dependence.
 */
export function buildBehavioralFeedback(failedRule: SigmaRule): string {
  const analysis = analyzeToolSignatureDependence(failedRule);
  return [
    'BEHAVIORAL FEEDBACK: Your previous rule was rejected.',
    `Reason: Primary detection relies on tool-specific filenames (${analysis.toolNames.join(', ')}).`,
    'Rewrite using behavioral OS indicators:',
    '- GrantedAccess masks for memory access patterns',
    '- ParentImage/ParentCommandLine for process relationships',
    '- CallTrace for injection detection',
    '- TargetObject for registry targeting',
    '- CommandLine argument patterns (not tool filenames)',
    'The rule must detect the TECHNIQUE, not the TOOL.',
  ].join('\n');
}

/**
 * Transform an AI response into a fully populated {@link SigmaRule}.
 */
function buildSigmaRule(
  response: SigmaAIResponse,
  mapping: AttackMappingResult,
  author: string,
): SigmaRule {
  const id = uuidv4();
  const now = new Date();
  const dateStr = formatDate(now);

  // Normalize tags to lowercase
  const tags = normalizeTags(response.tags, mapping);

  // Build the detection object with proper typing
  const detection = response.detection as SigmaDetection;

  // Determine level based on AI response and mapping confidence
  const level = response.level;

  const rule: SigmaRule = {
    id,
    title: response.title,
    status: 'experimental',
    description: response.description,
    references: [],
    author,
    date: dateStr,
    modified: dateStr,
    tags,
    logsource: {
      product: response.logsource.product,
      category: response.logsource.category,
      service: response.logsource.service,
    },
    detection,
    falsepositives: response.falsepositives,
    level,
    raw: '',
  };

  // Generate the YAML representation
  rule.raw = generateSigmaYaml(rule);

  return rule;
}

/**
 * Serialize a {@link SigmaRule} into a Sigma-conformant YAML string.
 *
 * Field ordering follows the conventional Sigma rule layout:
 * title, id, status, description, references, author, date, modified,
 * tags, logsource, detection, falsepositives, level, fields.
 */
function generateSigmaYaml(rule: SigmaRule): string {
  // Build an ordered object for YAML serialization
  const ordered: Record<string, unknown> = {
    title: rule.title,
    id: rule.id,
    status: rule.status,
    description: rule.description,
  };

  if (rule.references.length > 0) {
    ordered['references'] = rule.references;
  }

  ordered['author'] = rule.author;
  ordered['date'] = rule.date;
  ordered['modified'] = rule.modified;
  ordered['tags'] = rule.tags;
  ordered['logsource'] = buildLogsourceObject(rule.logsource);
  ordered['detection'] = rule.detection;
  ordered['falsepositives'] = rule.falsepositives;
  ordered['level'] = rule.level;

  if (rule.fields && rule.fields.length > 0) {
    ordered['fields'] = rule.fields;
  }

  return YAML.stringify(ordered, {
    lineWidth: 0,
    defaultStringType: 'PLAIN',
    defaultKeyType: 'PLAIN',
  });
}

/**
 * Build a clean logsource object without undefined values.
 */
function buildLogsourceObject(
  logsource: SigmaRule['logsource'],
): Record<string, string> {
  const result: Record<string, string> = {};
  if (logsource.product) result['product'] = logsource.product;
  if (logsource.category) result['category'] = logsource.category;
  if (logsource.service) result['service'] = logsource.service;
  return result;
}

/**
 * Normalize ATT&CK tags to the Sigma convention.
 *
 * Ensures:
 * - All tags are lowercase
 * - Tactic tags use underscores: `attack.defense_evasion`
 * - Technique tags use lowercase: `attack.t1059.001`
 * - The mapping's tactic and technique are always present
 */
function normalizeTags(
  aiTags: string[],
  mapping: AttackMappingResult,
): string[] {
  const tagSet = new Set<string>();

  // Add tags from AI response (normalized)
  for (const tag of aiTags) {
    tagSet.add(tag.toLowerCase().trim());
  }

  // Ensure the mapped tactic is present
  const tacticTag = `attack.${mapping.tactic.toLowerCase().replace(/[\s-]+/g, '_')}`;
  tagSet.add(tacticTag);

  // Ensure the mapped technique is present
  const techniqueTag = `attack.${mapping.techniqueId.toLowerCase()}`;
  tagSet.add(techniqueTag);

  return [...tagSet];
}

/**
 * Format a Date as YYYY/MM/DD (Sigma convention).
 */
function formatDate(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}/${month}/${day}`;
}

/**
 * Aggregate multiple {@link APIUsage} entries into a single summary.
 */
function aggregateUsage(entries: APIUsage[]): APIUsage {
  if (entries.length === 0) {
    return {
      operation: 'sigma_generation',
      model: '',
      inputTokens: 0,
      outputTokens: 0,
      costUsd: 0,
      durationMs: 0,
      timestamp: new Date().toISOString(),
    };
  }

  let totalInput = 0;
  let totalOutput = 0;
  let totalCost = 0;
  let totalDuration = 0;

  for (const entry of entries) {
    totalInput += entry.inputTokens;
    totalOutput += entry.outputTokens;
    totalCost += entry.costUsd;
    totalDuration += entry.durationMs;
  }

  return {
    operation: 'sigma_generation',
    model: entries[0].model,
    inputTokens: totalInput,
    outputTokens: totalOutput,
    costUsd: Math.round(totalCost * 10000) / 10000,
    durationMs: totalDuration,
    timestamp: new Date().toISOString(),
  };
}
