/**
 * Robust AI response parser with Zod validation.
 *
 * Handles:
 * - JSON extraction from markdown code blocks
 * - Partial/truncated JSON repair
 * - Zod schema validation
 * - Type-safe return values
 */

import { z } from 'zod';

// --- Zod Schemas ---

export const IocResponseSchema = z.object({
  iocs: z.array(
    z.object({
      value: z.string(),
      type: z.enum([
        'ipv4',
        'ipv6',
        'domain',
        'url',
        'md5',
        'sha1',
        'sha256',
        'email',
        'filepath_windows',
        'filepath_linux',
        'registry_key',
        'cve',
        'attack_technique',
      ]),
      context: z.string(),
      confidence: z.enum(['high', 'medium', 'low']),
      defanged: z.boolean(),
      originalValue: z.string(),
      relationships: z
        .array(
          z.object({
            relatedIOC: z.string(),
            relationship: z.string(),
          })
        )
        .default([]),
    })
  ),
});

export const TtpResponseSchema = z.object({
  ttps: z.array(
    z.object({
      description: z.string(),
      tools: z.array(z.string()).default([]),
      targetPlatforms: z.array(z.string()).default([]),
      artifacts: z
        .array(
          z.object({
            type: z.enum(['file', 'registry', 'event_log', 'network', 'process', 'other']),
            description: z.string(),
            value: z.string().optional(),
          })
        )
        .default([]),
      detectionOpportunities: z.array(z.string()).default([]),
      confidence: z.enum(['high', 'medium', 'low']),
    })
  ),
});

export const AttackMappingResponseSchema = z.object({
  mappings: z.array(
    z.object({
      techniqueId: z.string().regex(/^T\d{4}(\.\d{3})?$/, 'Invalid ATT&CK technique ID format'),
      techniqueName: z.string(),
      tactic: z.string(),
      confidence: z.enum(['high', 'medium', 'low']),
      reasoning: z.string(),
      suggestedRuleFormats: z.array(z.enum(['sigma', 'yara', 'suricata'])).default(['sigma']),
    })
  ),
});

// Disambiguation response schema (used with buildIocDisambiguationPrompt)
export const IocDisambiguationResponseSchema = z.object({
  results: z.array(
    z.object({
      value: z.string(),
      type: z.string(),
      isMalicious: z.boolean(),
      confidence: z.enum(['high', 'medium', 'low']).nullable(),
      reasoning: z.string(),
      relationships: z
        .array(
          z.object({
            relatedIOC: z.string(),
            relationship: z.string(),
          })
        )
        .default([]),
    })
  ),
});

// --- Type Inference ---

export type IocResponse = z.infer<typeof IocResponseSchema>;
export type TtpResponse = z.infer<typeof TtpResponseSchema>;
export type AttackMappingResponse = z.infer<typeof AttackMappingResponseSchema>;
export type IocDisambiguationResponse = z.infer<typeof IocDisambiguationResponseSchema>;

// --- Parser Functions ---

/**
 * Extract JSON from various response formats.
 * Handles:
 * - Raw JSON
 * - JSON wrapped in markdown code blocks (```json ... ```)
 * - JSON with extra text before/after
 */
export function extractJsonFromResponse(raw: string): unknown {
  let cleaned = raw.trim();

  // Remove markdown code blocks
  const codeBlockMatch = cleaned.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (codeBlockMatch) {
    cleaned = codeBlockMatch[1].trim();
  }

  // Try to find JSON object boundaries if there's extra text
  const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
  if (jsonMatch) {
    cleaned = jsonMatch[0];
  }

  // Attempt to parse
  try {
    return JSON.parse(cleaned);
  } catch {
    // Try to repair common JSON errors
    const repaired = attemptJsonRepair(cleaned);
    try {
      return JSON.parse(repaired);
    } catch {
      // Last resort: try inserting missing closers before trailing braces
      const aggressive = aggressiveJsonRepair(cleaned);
      return JSON.parse(aggressive);
    }
  }
}

/**
 * Attempt to repair common JSON errors.
 * - Unclosed brackets/braces
 * - Trailing commas
 * - Unescaped quotes in strings
 */
function attemptJsonRepair(json: string): string {
  let repaired = json;

  // Remove trailing commas before closing brackets/braces
  repaired = repaired.replace(/,(\s*[}\]])/g, '$1');

  // Track the nesting stack to determine correct closing order
  const stack: string[] = [];
  let inString = false;
  let escaped = false;

  for (const ch of repaired) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inString = !inString;
      continue;
    }
    if (inString) continue;

    if (ch === '{') stack.push('}');
    else if (ch === '[') stack.push(']');
    else if (ch === '}' || ch === ']') {
      if (stack.length > 0 && stack[stack.length - 1] === ch) {
        stack.pop();
      }
    }
  }

  // Close any unclosed structures in reverse order
  while (stack.length > 0) {
    repaired += stack.pop();
  }

  return repaired;
}

/**
 * Aggressive JSON repair for cases where brackets are mismatched.
 * Tries inserting missing closers before trailing braces/brackets.
 */
function aggressiveJsonRepair(json: string): string {
  let repaired = json.replace(/,(\s*[}\]])/g, '$1');

  // Count unmatched openers
  const openBraces = (repaired.match(/\{/g) || []).length;
  const closeBraces = (repaired.match(/\}/g) || []).length;
  const openBrackets = (repaired.match(/\[/g) || []).length;
  const closeBrackets = (repaired.match(/\]/g) || []).length;

  const missingBrackets = openBrackets - closeBrackets;
  const missingBraces = openBraces - closeBraces;

  if (missingBrackets > 0) {
    // Insert missing ] before the last } (common: array not closed before object end)
    const lastBrace = repaired.lastIndexOf('}');
    if (lastBrace >= 0) {
      const insert = ']'.repeat(missingBrackets);
      repaired = repaired.substring(0, lastBrace) + insert + repaired.substring(lastBrace);
    } else {
      repaired += ']'.repeat(missingBrackets);
    }
  }

  if (missingBraces > 0) {
    repaired += '}'.repeat(missingBraces);
  }

  return repaired;
}

/**
 * Parse and validate IOC extraction response.
 */
export function parseIocResponse(raw: string): IocResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return IocResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors.map(err =>
        `  - ${err.path.join('.')}: ${err.message}`
      ).join('\n');
      throw new Error(
        `IOC response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`
      );
    }
    throw error;
  }
}

/**
 * Parse and validate TTP extraction response.
 */
export function parseTtpResponse(raw: string): TtpResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return TtpResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors.map(err =>
        `  - ${err.path.join('.')}: ${err.message}`
      ).join('\n');
      throw new Error(
        `TTP response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`
      );
    }
    throw error;
  }
}

/**
 * Parse and validate ATT&CK mapping response.
 */
export function parseAttackMappingResponse(raw: string): AttackMappingResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return AttackMappingResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors.map(err =>
        `  - ${err.path.join('.')}: ${err.message}`
      ).join('\n');
      throw new Error(
        `ATT&CK mapping response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`
      );
    }
    throw error;
  }
}

/**
 * Parse and validate IOC disambiguation response.
 */
export function parseIocDisambiguationResponse(raw: string): IocDisambiguationResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return IocDisambiguationResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors.map(err =>
        `  - ${err.path.join('.')}: ${err.message}`
      ).join('\n');
      throw new Error(
        `IOC disambiguation response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`
      );
    }
    throw error;
  }
}
