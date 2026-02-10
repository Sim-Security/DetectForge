/**
 * Documentation generator for detection rules.
 *
 * Takes a {@link GeneratedRule} and produces a comprehensive
 * {@link RuleDocumentation} object by leveraging AI to analyze the rule
 * content and generate SOC-analyst-friendly documentation including
 * ATT&CK mappings, false-positive analysis, coverage gaps, and tuning
 * recommendations.
 */

import type { AIClient, ModelTier } from '@/ai/client.js';
import type { APIUsage } from '@/types/config.js';
import type { GeneratedRule, RuleDocumentation } from '@/types/detection-rule.js';
import { withRetry } from '@/ai/retry.js';
import {
  buildDocumentationPrompt,
  parseDocumentationAIResponse,
} from '@/ai/prompts/documentation.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/**
 * Options for the documentation generation function.
 */
export interface DocumentationOptions {
  /** The AI client used for inference. */
  client: AIClient;
  /** Model tier to use for generation (default: "standard"). */
  modelTier?: ModelTier;
}

/**
 * Result of a documentation generation call.
 */
export interface DocumentationResult {
  /** The generated rule documentation. */
  documentation: RuleDocumentation;
  /** API usage statistics for the generation call. */
  usage: APIUsage;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate comprehensive documentation for a detection rule.
 *
 * The function builds an AI prompt from the rule details, sends it to the
 * configured model, parses and validates the response, and returns
 * structured documentation along with usage statistics.
 *
 * Uses {@link withRetry} for resilience against transient API failures.
 *
 * @param rule    - The generated detection rule to document.
 * @param options - Generation options including the AI client and model tier.
 * @returns The generated documentation and API usage statistics.
 * @throws When the AI response cannot be parsed or validated after retries.
 */
export async function generateDocumentation(
  rule: GeneratedRule,
  options: DocumentationOptions,
): Promise<DocumentationResult> {
  const { client, modelTier = 'standard' } = options;
  const { system, user } = buildDocumentationPrompt(rule);

  const result = await withRetry(
    () =>
      client.prompt(system, user, {
        model: modelTier,
      }),
  );

  const documentation = parseDocumentationAIResponse(result.content);

  return {
    documentation,
    usage: result.usage,
  };
}
