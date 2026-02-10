/**
 * False positive analyzer for generated detection rules.
 *
 * Takes a {@link GeneratedRule} and uses AI to produce a detailed analysis
 * of potential false positive scenarios, overall FP risk assessment, and
 * actionable tuning recommendations.  The analyzer leverages the SOC
 * analyst persona prompt from {@link buildFPAnalysisPrompt} and validates
 * the AI response with Zod before returning typed results.
 *
 * @example
 * ```ts
 * import { analyzeFalsePositives } from '@/generation/false-positive-analyzer.js';
 *
 * const result = await analyzeFalsePositives(rule, {
 *   client: aiClient,
 *   modelTier: 'standard',
 * });
 *
 * for (const fp of result.falsePositives) {
 *   console.log(`[${fp.likelihood}] ${fp.scenario}`);
 *   console.log(`  Tuning: ${fp.tuningAdvice}`);
 * }
 * ```
 */

import type { GeneratedRule, FalsePositiveScenario } from '@/types/detection-rule.js';
import type { AIClient, ModelTier } from '@/ai/client.js';
import type { APIUsage } from '@/types/config.js';
import { withRetry } from '@/ai/retry.js';
import {
  buildFPAnalysisPrompt,
  parseFPAnalysisAIResponse,
} from '@/ai/prompts/fp-analysis.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/**
 * Options for the false positive analysis pipeline.
 */
export interface FPAnalysisOptions {
  /** The AI client used for inference. */
  client: AIClient;
  /** AI model tier to use (default: "standard"). */
  modelTier?: ModelTier;
  /** Maximum retry attempts on transient AI errors (default: 3). */
  maxRetries?: number;
  /** Maximum tokens for the AI response (default: 2048). */
  maxTokens?: number;
  /** Sampling temperature (default: 0.3). */
  temperature?: number;
}

/**
 * Result of a false positive analysis run.
 */
export interface FPAnalysisResult {
  /** Identified false positive scenarios with likelihood and tuning advice. */
  falsePositives: FalsePositiveScenario[];
  /** Overall false positive risk assessment for the rule. */
  overallFPRisk: 'high' | 'medium' | 'low';
  /** General recommendations for improving the rule's signal-to-noise ratio. */
  recommendations: string[];
  /** API usage statistics for this analysis call. */
  usage: APIUsage;
}

// ---------------------------------------------------------------------------
// Default Configuration
// ---------------------------------------------------------------------------

const DEFAULT_MODEL_TIER: ModelTier = 'standard';
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_MAX_TOKENS = 2048;
const DEFAULT_TEMPERATURE = 0.3;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Analyze a generated detection rule for false positive scenarios.
 *
 * Builds an AI prompt using the SOC analyst persona, calls the AI model
 * with retry logic, parses and validates the response, and maps the
 * results back to {@link FalsePositiveScenario} objects.
 *
 * @param rule    - The generated detection rule to analyze.
 * @param options - Analysis options including the AI client and model tier.
 * @returns The FP analysis result with scenarios, risk assessment, recommendations, and usage.
 * @throws When the AI response cannot be parsed or validation fails after retries.
 */
export async function analyzeFalsePositives(
  rule: GeneratedRule,
  options: FPAnalysisOptions,
): Promise<FPAnalysisResult> {
  const modelTier = options.modelTier ?? DEFAULT_MODEL_TIER;
  const maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
  const maxTokens = options.maxTokens ?? DEFAULT_MAX_TOKENS;
  const temperature = options.temperature ?? DEFAULT_TEMPERATURE;

  // 1. Build the prompt
  const { system, user } = buildFPAnalysisPrompt(rule);

  // 2. Call the AI model with retry logic
  const result = await withRetry(
    () =>
      options.client.prompt(system, user, {
        model: modelTier,
        maxTokens,
        temperature,
      }),
    { maxRetries },
  );

  // 3. Parse and validate the AI response
  const parsed = parseFPAnalysisAIResponse(result.content);

  // 4. Map the parsed response to FalsePositiveScenario[] from detection-rule types
  const falsePositives: FalsePositiveScenario[] = parsed.falsePositives.map(
    (fp) => ({
      scenario: fp.scenario,
      likelihood: fp.likelihood,
      tuningAdvice: fp.tuningAdvice,
    }),
  );

  // 5. Return the analysis and usage stats
  return {
    falsePositives,
    overallFPRisk: parsed.overallFPRisk,
    recommendations: parsed.recommendations,
    usage: result.usage,
  };
}
