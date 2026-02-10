/**
 * YAML parsing and serialization utilities.
 * Wraps the 'yaml' package with error handling.
 */

import { parse, stringify } from 'yaml';

export function parseYaml<T = unknown>(input: string): T {
  return parse(input) as T;
}

export function serializeYaml(data: unknown): string {
  return stringify(data, {
    lineWidth: 0,
    defaultStringType: 'QUOTE_SINGLE',
    defaultKeyType: 'PLAIN',
  });
}

/**
 * Validate that a string is valid YAML. Returns the parsed object or throws.
 */
export function validateYaml(input: string): { valid: boolean; data?: unknown; error?: string } {
  try {
    const data = parse(input);
    return { valid: true, data };
  } catch (e) {
    return { valid: false, error: (e as Error).message };
  }
}
