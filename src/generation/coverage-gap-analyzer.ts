/**
 * Coverage gap analyzer for DetectForge.
 *
 * Takes all generated detection rules alongside extraction results (TTPs
 * and ATT&CK mappings) and produces a comprehensive gap analysis by
 * leveraging an AI model.  The analysis identifies:
 *
 * - TTPs from the report that could not be translated into rules
 * - Evasion vectors that would bypass the generated rules
 * - Missing log sources that limit detection capability
 * - Overall detection coverage statistics
 * - Prioritized recommendations for improving coverage
 */

import type { AIClient, ModelTier } from '@/ai/client.js';
import type { APIUsage } from '@/types/config.js';
import type { GeneratedRule } from '@/types/detection-rule.js';
import type { ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';

import { withRetry } from '@/ai/retry.js';
import {
  buildGapAnalysisPrompt,
  parseGapAnalysisAIResponse,
} from '@/ai/prompts/gap-analysis.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/**
 * Options for running the coverage gap analyzer.
 */
export interface CoverageGapOptions {
  /** The AI client used for inference. */
  client: AIClient;
  /** Model tier to use (default: "quality" for deeper reasoning). */
  modelTier?: ModelTier;
}

/**
 * Complete result of a coverage gap analysis.
 */
export interface CoverageGapResult {
  /** TTPs that were not covered by any generated rule. */
  uncoveredTTPs: UncoveredTTP[];
  /** Evasion techniques that could bypass existing rules. */
  evasionVectors: EvasionVector[];
  /** Log sources required but potentially missing. */
  logSourceGaps: LogSourceGap[];
  /** High-level coverage statistics. */
  overallCoverage: OverallCoverage;
  /** Prioritized recommendations to improve detection. */
  recommendations: string[];
  /** API usage for the analysis call. */
  usage: APIUsage;
}

/**
 * A TTP from the report that was not translated into a detection rule.
 */
export interface UncoveredTTP {
  /** Description of the TTP. */
  ttpDescription: string;
  /** ATT&CK technique ID, if known. */
  techniqueId?: string;
  /** Reason why no rule was generated. */
  reason: string;
  /** How this TTP could alternatively be detected. */
  alternativeDetection: string;
  /** Log sources that would be needed to detect this TTP. */
  requiredLogSources: string[];
}

/**
 * An evasion technique that could bypass an existing rule.
 */
export interface EvasionVector {
  /** Title or identifier of the affected rule. */
  ruleAffected: string;
  /** Description of the evasion technique. */
  evasionTechnique: string;
  /** Suggestion for mitigating the evasion vector. */
  mitigationSuggestion: string;
}

/**
 * A log source that is required for detection but may be unavailable.
 */
export interface LogSourceGap {
  /** Name of the log source. */
  logSource: string;
  /** ATT&CK technique IDs that depend on this log source. */
  requiredFor: string[];
  /** Whether the log source is believed to be currently available. */
  currentlyAvailable: boolean;
  /** Recommendation for enabling or substituting this log source. */
  recommendation: string;
}

/**
 * High-level detection coverage statistics.
 */
export interface OverallCoverage {
  /** Number of ATT&CK techniques covered by at least one rule. */
  coveredTechniqueCount: number;
  /** Total number of ATT&CK techniques identified in the report. */
  totalTechniqueCount: number;
  /** Coverage as a percentage (0-100). */
  coveragePercentage: number;
  /** Tactic with the best detection coverage. */
  strongestTactic: string;
  /** Tactic with the weakest detection coverage. */
  weakestTactic: string;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Analyze detection coverage gaps across all generated rules and extracted
 * threat intelligence.
 *
 * Sends the full set of rules, TTPs, and ATT&CK mappings to an AI model
 * that identifies uncovered TTPs, evasion vectors, log source gaps, and
 * provides prioritized recommendations.
 *
 * @param rules    - All detection rules generated for the report.
 * @param ttps     - All TTPs extracted from the threat report.
 * @param mappings - All ATT&CK technique mappings for those TTPs.
 * @param options  - Configuration options including the AI client.
 * @returns A comprehensive coverage gap analysis with usage statistics.
 */
export async function analyzeCoverageGaps(
  rules: GeneratedRule[],
  ttps: ExtractedTTP[],
  mappings: AttackMappingResult[],
  options: CoverageGapOptions,
): Promise<CoverageGapResult> {
  const { client, modelTier = 'quality' } = options;
  const { system, user } = buildGapAnalysisPrompt(rules, ttps, mappings);

  const result = await withRetry(
    () =>
      client.prompt(system, user, {
        model: modelTier,
      }),
    { maxRetries: 3 },
  );

  const parsed = parseGapAnalysisAIResponse(result.content);

  return {
    uncoveredTTPs: parsed.uncoveredTTPs,
    evasionVectors: parsed.evasionVectors,
    logSourceGaps: parsed.logSourceGaps,
    overallCoverage: parsed.overallCoverage,
    recommendations: parsed.recommendations,
    usage: result.usage,
  };
}
