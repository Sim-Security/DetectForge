/**
 * YARA rule validation utilities.
 *
 * Provides structural and syntactic validation for:
 * - Parsed {@link YaraRule} objects (schema-level checks)
 * - Raw YARA rule text (syntax-level plausibility checks)
 *
 * These validators run locally without invoking an external YARA compiler,
 * so they verify plausible correctness rather than full compilation.
 */

import type { YaraRule, ValidationResult } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Pattern for a valid YARA rule name or string identifier (without the `$` prefix). */
const IDENTIFIER_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/** Pattern for a valid YARA string identifier (with `$` prefix). */
const STRING_ID_RE = /^\$[a-zA-Z_][a-zA-Z0-9_]*$/;

/** Allowed characters inside a hex string body (pairs, wildcards, jumps, alternatives). */
const HEX_BODY_RE = /^[\s0-9A-Fa-f?|\[\]\-()]+$/;

/** Required meta fields. */
const REQUIRED_META_FIELDS: (keyof Pick<YaraRule['meta'], 'description' | 'author' | 'date'>)[] = [
  'description',
  'author',
  'date',
];

/** Valid modifiers for text strings. */
const VALID_TEXT_MODIFIERS = new Set([
  'ascii',
  'wide',
  'nocase',
  'fullword',
  'xor',
  'base64',
  'base64wide',
  'private',
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate a parsed {@link YaraRule} object.
 *
 * Checks:
 * - Rule name is a valid identifier.
 * - Required meta fields (`description`, `author`, `date`) are present and non-empty.
 * - Each string has a valid identifier (`$name`), a non-empty value, and a valid type.
 * - Hex strings use only valid hex characters, wildcards, jumps, and alternatives.
 * - No duplicate string identifiers.
 * - Condition is non-empty.
 * - Condition references at least one string identifier that exists (when using `$`-prefixed refs).
 *
 * @param rule - The YARA rule to validate.
 * @returns A {@link ValidationResult} with errors and warnings.
 */
export function validateYaraRule(rule: YaraRule): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // --- Rule name ---
  if (!rule.name || !IDENTIFIER_RE.test(rule.name)) {
    errors.push(
      `Invalid rule name "${rule.name}". Must start with a letter or underscore and contain only alphanumeric characters and underscores.`,
    );
  }

  // --- Meta fields ---
  for (const field of REQUIRED_META_FIELDS) {
    const value = rule.meta[field];
    if (value === undefined || value === null || String(value).trim() === '') {
      errors.push(`Required meta field "${field}" is missing or empty.`);
    }
  }

  if (rule.meta.date && !/^\d{4}-\d{2}-\d{2}$/.test(rule.meta.date)) {
    warnings.push(
      `Meta field "date" should use YYYY-MM-DD format. Got "${rule.meta.date}".`,
    );
  }

  // --- Strings ---
  if (!rule.strings || rule.strings.length === 0) {
    errors.push('Rule must contain at least one string definition.');
  }

  const seenIds = new Set<string>();

  for (const str of rule.strings) {
    // Identifier
    if (!str.identifier || !STRING_ID_RE.test(str.identifier)) {
      errors.push(
        `Invalid string identifier "${str.identifier}". Must start with "$" followed by a letter/underscore and alphanumeric characters.`,
      );
    }

    // Duplicate check
    if (seenIds.has(str.identifier)) {
      errors.push(`Duplicate string identifier "${str.identifier}".`);
    }
    seenIds.add(str.identifier);

    // Value
    if (!str.value || str.value.trim() === '') {
      errors.push(`String "${str.identifier}" has an empty value.`);
    }

    // Type
    if (!['text', 'hex', 'regex'].includes(str.type)) {
      errors.push(
        `String "${str.identifier}" has invalid type "${str.type}". Must be "text", "hex", or "regex".`,
      );
    }

    // Hex-specific validation
    if (str.type === 'hex' && str.value) {
      if (!HEX_BODY_RE.test(str.value)) {
        errors.push(
          `Hex string "${str.identifier}" contains invalid characters. Only 0-9, A-F, spaces, "??", "[", "]", "-", "(", ")", and "|" are allowed.`,
        );
      }
    }

    // Modifier validation for text strings
    if (str.type === 'text' && str.modifiers) {
      for (const mod of str.modifiers) {
        if (!VALID_TEXT_MODIFIERS.has(mod)) {
          warnings.push(
            `String "${str.identifier}" has unknown modifier "${mod}".`,
          );
        }
      }
    }
  }

  // --- Condition ---
  if (!rule.condition || rule.condition.trim() === '') {
    errors.push('Condition must not be empty.');
  }

  // Check that condition references at least one existing string when it
  // contains explicit $-prefixed identifiers (not counting wildcards like $s*).
  if (rule.condition && rule.strings && rule.strings.length > 0) {
    const conditionRefs = rule.condition.match(/\$[a-zA-Z_][a-zA-Z0-9_]*/g) || [];
    const definedIds = new Set(rule.strings.map(s => s.identifier));

    for (const ref of conditionRefs) {
      if (!definedIds.has(ref)) {
        warnings.push(
          `Condition references "${ref}" which is not defined in the strings section.`,
        );
      }
    }
  }

  // --- Tags ---
  if (rule.tags) {
    for (const tag of rule.tags) {
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(tag)) {
        warnings.push(`Tag "${tag}" contains invalid characters. Tags should be simple identifiers.`);
      }
    }
  }

  const syntaxValid = errors.length === 0;
  const schemaValid = errors.length === 0;

  return {
    valid: syntaxValid && schemaValid,
    syntaxValid,
    schemaValid,
    errors,
    warnings,
  };
}

/**
 * Validate raw YARA rule text for syntactic plausibility.
 *
 * This is a lightweight check — it does NOT compile the rule. It verifies:
 * - Presence of `rule` keyword, `meta:`, `strings:`, and `condition:` sections.
 * - Balanced curly braces.
 * - Rule name follows the keyword `rule`.
 * - At least one string definition in the strings section.
 * - Condition section is non-empty.
 *
 * @param raw - The raw YARA rule text.
 * @returns A {@link ValidationResult}.
 */
export function validateYaraRaw(raw: string): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const trimmed = raw.trim();

  // --- Must start with "rule" keyword ---
  if (!/^rule\s+/m.test(trimmed)) {
    errors.push('Raw YARA text must begin with the "rule" keyword.');
  }

  // --- Required sections ---
  if (!/\bmeta\s*:/m.test(trimmed)) {
    errors.push('Missing "meta:" section in raw YARA text.');
  }
  if (!/\bstrings\s*:/m.test(trimmed)) {
    errors.push('Missing "strings:" section in raw YARA text.');
  }
  if (!/\bcondition\s*:/m.test(trimmed)) {
    errors.push('Missing "condition:" section in raw YARA text.');
  }

  // --- Balanced braces ---
  let braceDepth = 0;
  for (const ch of trimmed) {
    if (ch === '{') braceDepth++;
    if (ch === '}') braceDepth--;
    if (braceDepth < 0) {
      errors.push('Unbalanced curly braces: unexpected closing brace.');
      break;
    }
  }
  if (braceDepth > 0) {
    errors.push(`Unbalanced curly braces: ${braceDepth} unclosed opening brace(s).`);
  }

  // --- Rule name extraction and validation ---
  const ruleNameMatch = trimmed.match(/^rule\s+([^\s:{]+)/m);
  if (ruleNameMatch) {
    const name = ruleNameMatch[1];
    if (!IDENTIFIER_RE.test(name)) {
      errors.push(
        `Invalid rule name "${name}". Must start with a letter or underscore and contain only alphanumeric characters and underscores.`,
      );
    }
  }

  // --- Strings section should contain at least one $identifier ---
  const stringsSection = extractSection(trimmed, 'strings');
  if (stringsSection !== null) {
    if (!/\$[a-zA-Z_]/m.test(stringsSection)) {
      errors.push('Strings section does not contain any string definitions ($identifier).');
    }
  }

  // --- Condition section should be non-empty ---
  const conditionSection = extractSection(trimmed, 'condition');
  if (conditionSection !== null) {
    if (conditionSection.trim() === '') {
      errors.push('Condition section is empty.');
    }
  }

  // --- Warnings for common issues ---
  if (!/\bauthor\s*=/.test(trimmed)) {
    warnings.push('Meta section is missing an "author" field.');
  }
  if (!/\bdescription\s*=/.test(trimmed)) {
    warnings.push('Meta section is missing a "description" field.');
  }
  if (!/\bdate\s*=/.test(trimmed)) {
    warnings.push('Meta section is missing a "date" field.');
  }

  const syntaxValid = errors.length === 0;
  const schemaValid = errors.length === 0;

  return {
    valid: syntaxValid && schemaValid,
    syntaxValid,
    schemaValid,
    errors,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the content of a named section from raw YARA text.
 *
 * Looks for `sectionName:` and returns everything up to the next
 * section keyword or closing brace. Returns `null` if the section is
 * not found.
 */
function extractSection(raw: string, sectionName: string): string | null {
  const sectionRegex = new RegExp(
    `\\b${sectionName}\\s*:\\s*([\\s\\S]*?)(?=\\b(?:meta|strings|condition)\\s*:|\\}\\s*$)`,
    'm',
  );
  const match = raw.match(sectionRegex);
  return match ? match[1] : null;
}
