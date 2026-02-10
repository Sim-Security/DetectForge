/**
 * ATT&CK Mapper — maps extracted TTPs to MITRE ATT&CK technique IDs.
 *
 * Two-pass approach:
 * 1. AI mapping: use AI to identify ATT&CK techniques from TTP descriptions
 * 2. Validation: cross-reference against local ATT&CK knowledge base
 *
 * Targets subtechnique specificity (T1059.001 preferred over T1059).
 */

import type { AIClient } from '../ai/client.js';
import type { ExtractedTTP, AttackMappingResult } from '../types/extraction.js';
import type { APIUsage } from '../types/config.js';
import { buildAttackMappingPrompt } from '../ai/prompts/ttp-extraction.js';
import { parseAttackMappingResponse } from '../ai/response-parser.js';
import { withRetry } from '../ai/retry.js';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface AttackMapperOptions {
  /** AI model tier. Default: 'standard' */
  modelTier?: 'fast' | 'standard' | 'quality';
  /** Max tokens for AI response. Default: 4096 */
  maxTokens?: number;
  /** Temperature. Default: 0.1 */
  temperature?: number;
  /** Max retries. Default: 3 */
  maxRetries?: number;
  /**
   * Optional: local ATT&CK knowledge base for validation.
   * If provided, technique IDs are validated against it.
   * Pass a function that checks if a technique ID exists.
   */
  validateTechniqueId?: (id: string) => boolean;
}

// ---------------------------------------------------------------------------
// Main mapping function
// ---------------------------------------------------------------------------

export interface AttackMappingOutput {
  mappings: AttackMappingResult[];
  totalUsage: APIUsage;
}

/**
 * Map extracted TTPs to MITRE ATT&CK techniques using AI.
 *
 * For each TTP, the AI identifies the most specific technique/subtechnique ID,
 * provides reasoning, and suggests detection rule formats.
 */
export async function mapToAttack(
  client: AIClient,
  ttps: ExtractedTTP[],
  options: AttackMapperOptions = {},
): Promise<AttackMappingOutput> {
  const {
    modelTier = 'standard',
    maxTokens = 4096,
    temperature = 0.1,
    maxRetries = 3,
    validateTechniqueId,
  } = options;

  if (ttps.length === 0) {
    return {
      mappings: [],
      totalUsage: {
        operation: 'attack-mapping',
        model: '',
        inputTokens: 0,
        outputTokens: 0,
        costUsd: 0,
        durationMs: 0,
        timestamp: new Date().toISOString(),
      },
    };
  }

  // Prepare TTP summaries for the prompt
  const ttpSummaries = ttps.map(ttp => ({
    description: ttp.description,
    tools: ttp.tools,
    artifacts: ttp.artifacts.map(a => a.description),
  }));

  const { system, user } = buildAttackMappingPrompt(ttpSummaries);

  const result = await withRetry(
    () => client.prompt(system, user, {
      model: modelTier,
      maxTokens,
      temperature,
      jsonMode: true,
    }),
    { maxRetries },
  );

  const parsed = parseAttackMappingResponse(result.content);

  // Map parsed response to AttackMappingResult, linking back to source TTPs
  const mappings: AttackMappingResult[] = parsed.mappings.map((mapping, index) => {
    // Find the best matching source TTP (by index if available, otherwise by heuristic)
    const sourceTtp = ttps[index] ?? ttps[ttps.length - 1];

    // Validate technique ID against local knowledge base if available
    const validated = validateTechniqueId
      ? validateTechniqueId(mapping.techniqueId)
      : false;

    return {
      techniqueId: mapping.techniqueId,
      techniqueName: mapping.techniqueName,
      tactic: mapping.tactic,
      confidence: mapping.confidence,
      reasoning: mapping.reasoning,
      sourceTtp,
      suggestedRuleFormats: mapping.suggestedRuleFormats,
      validated,
    };
  });

  // Deduplicate by technique ID (keep highest confidence)
  const CONFIDENCE_ORDER = { high: 3, medium: 2, low: 1 };
  const deduped = new Map<string, AttackMappingResult>();

  for (const mapping of mappings) {
    const existing = deduped.get(mapping.techniqueId);
    if (!existing || CONFIDENCE_ORDER[mapping.confidence] > CONFIDENCE_ORDER[existing.confidence]) {
      deduped.set(mapping.techniqueId, mapping);
    }
  }

  return {
    mappings: [...deduped.values()],
    totalUsage: result.usage,
  };
}
