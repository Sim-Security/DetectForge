/**
 * TTP Extractor — AI-powered behavioral pattern extraction.
 *
 * Extracts tactics, techniques, and procedures from threat report text
 * using AI inference. Each TTP includes:
 * - Behavioral description
 * - Tools/software used
 * - Target platforms
 * - Forensic artifacts
 * - Detection opportunities
 * - Confidence scoring
 */

import type { AIClient } from '../ai/client.js';
import type { ExtractedTTP, TTTArtifact } from '../types/extraction.js';
import type { APIUsage } from '../types/config.js';
import { buildTtpExtractionPrompt } from '../ai/prompts/ttp-extraction.js';
import { parseTtpResponse } from '../ai/response-parser.js';
import { withRetry } from '../ai/retry.js';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface TtpExtractionOptions {
  /** AI model tier to use. Default: 'standard' */
  modelTier?: 'fast' | 'standard' | 'quality';
  /** Maximum tokens for AI response. Default: 4096 */
  maxTokens?: number;
  /** Temperature for AI inference. Default: 0.1 */
  temperature?: number;
  /** Maximum retries for AI calls. Default: 3 */
  maxRetries?: number;
}

// ---------------------------------------------------------------------------
// Main extraction function
// ---------------------------------------------------------------------------

export interface TtpExtractionResult {
  ttps: ExtractedTTP[];
  usage: APIUsage;
}

/**
 * Extract TTPs from report text using AI.
 *
 * Sends the report text to the AI with a structured extraction prompt,
 * parses the response into ExtractedTTP objects with validation.
 */
export async function extractTtps(
  client: AIClient,
  reportText: string,
  options: TtpExtractionOptions = {},
): Promise<TtpExtractionResult> {
  const {
    modelTier = 'standard',
    maxTokens = 4096,
    temperature = 0.1,
    maxRetries = 3,
  } = options;

  // Truncate very long reports to stay within token limits
  const maxChars = 30_000;
  const truncatedText = reportText.length > maxChars
    ? reportText.substring(0, maxChars) + '\n\n[... report truncated for processing ...]'
    : reportText;

  const { system, user } = buildTtpExtractionPrompt(truncatedText);

  const result = await withRetry(
    () => client.prompt(system, user, {
      model: modelTier,
      maxTokens,
      temperature,
      jsonMode: true,
    }),
    { maxRetries },
  );

  const parsed = parseTtpResponse(result.content);

  // Map parsed response to ExtractedTTP objects
  const ttps: ExtractedTTP[] = parsed.ttps.map(ttp => ({
    description: ttp.description,
    tools: ttp.tools,
    targetPlatforms: ttp.targetPlatforms,
    artifacts: ttp.artifacts.map((a): TTTArtifact => ({
      type: a.type,
      description: a.description,
      value: a.value,
    })),
    detectionOpportunities: ttp.detectionOpportunities,
    confidence: ttp.confidence,
  }));

  return { ttps, usage: result.usage };
}
