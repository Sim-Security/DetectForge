/**
 * Sigma rule validation.
 *
 * Provides both structured-object validation ({@link validateSigmaRule}) and
 * raw-YAML validation ({@link validateSigmaYaml}).  Checks cover required
 * fields, UUID format, logsource validity, detection condition references,
 * ATT&CK tag formatting, and parseable YAML.
 */

import YAML from 'yaml';
import { validateSigmaLogsource } from '@/knowledge/logsource-catalog/index.js';
import type { SigmaRule, ValidationResult } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** RFC 4122 UUID v4 pattern. */
const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** ATT&CK tag patterns accepted in Sigma rules. */
const ATTACK_TAG_REGEX = /^attack\.(t\d{4}(\.\d{3})?|[a-z_]+)$/;

/** Valid Sigma severity levels. */
const VALID_LEVELS = new Set([
  'informational',
  'low',
  'medium',
  'high',
  'critical',
]);

/** Valid Sigma rule statuses. */
const VALID_STATUSES = new Set([
  'experimental',
  'test',
  'stable',
  'deprecated',
  'unsupported',
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate a structured {@link SigmaRule} object.
 *
 * Checks:
 * - Required fields: title, id, status, description, logsource, detection, level
 * - `id` is a valid UUID v4
 * - `status` is one of: experimental, test, stable, deprecated, unsupported
 * - `level` is one of: informational, low, medium, high, critical
 * - `logsource` has at least product or category
 * - `logsource` product/category/service combination is recognised by the catalog
 * - `detection` contains a `condition` field
 * - `condition` references existing selection/filter names
 * - ATT&CK `tags` match the expected patterns
 *
 * @param rule - The Sigma rule to validate.
 * @returns A {@link ValidationResult} with errors and warnings.
 */
export function validateSigmaRule(rule: SigmaRule): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // --- Required fields ---

  if (!rule.title || rule.title.trim().length === 0) {
    errors.push('Missing required field: title');
  }

  if (!rule.id || rule.id.trim().length === 0) {
    errors.push('Missing required field: id');
  } else if (!UUID_V4_REGEX.test(rule.id)) {
    errors.push(`Invalid UUID v4 format for id: "${rule.id}"`);
  }

  if (!rule.status) {
    errors.push('Missing required field: status');
  } else if (!VALID_STATUSES.has(rule.status)) {
    errors.push(
      `Invalid status "${rule.status}". Must be one of: ${[...VALID_STATUSES].join(', ')}`,
    );
  }

  if (!rule.description || rule.description.trim().length === 0) {
    errors.push('Missing required field: description');
  }

  if (!rule.level) {
    errors.push('Missing required field: level');
  } else if (!VALID_LEVELS.has(rule.level)) {
    errors.push(
      `Invalid level "${rule.level}". Must be one of: ${[...VALID_LEVELS].join(', ')}`,
    );
  }

  // --- Logsource ---

  if (!rule.logsource) {
    errors.push('Missing required field: logsource');
  } else {
    const hasProductOrCategory = rule.logsource.product || rule.logsource.category;
    if (!hasProductOrCategory) {
      errors.push('Logsource must have at least "product" or "category"');
    }

    // Validate against the catalog when product is present
    if (rule.logsource.product) {
      const isKnown = validateSigmaLogsource(
        rule.logsource.product,
        rule.logsource.category,
        rule.logsource.service,
      );
      if (!isKnown) {
        warnings.push(
          `Logsource combination not found in catalog: product="${rule.logsource.product}"` +
            `${rule.logsource.category ? `, category="${rule.logsource.category}"` : ''}` +
            `${rule.logsource.service ? `, service="${rule.logsource.service}"` : ''}`,
        );
      }
    }
  }

  // --- Detection ---

  if (!rule.detection) {
    errors.push('Missing required field: detection');
  } else {
    if (typeof rule.detection.condition !== 'string') {
      errors.push('Detection must contain a "condition" field of type string');
    } else {
      validateConditionReferences(rule.detection, errors, warnings);
    }
  }

  // --- Tags ---

  if (rule.tags && rule.tags.length > 0) {
    for (const tag of rule.tags) {
      if (tag.startsWith('attack.') && !ATTACK_TAG_REGEX.test(tag)) {
        warnings.push(
          `ATT&CK tag "${tag}" does not match expected pattern "attack.tXXXX" or "attack.tactic_name"`,
        );
      }
    }
  } else {
    warnings.push('Rule has no tags. Consider adding ATT&CK technique tags.');
  }

  // --- Additional warnings ---

  if (!rule.date) {
    warnings.push('Rule is missing a "date" field');
  }

  if (!rule.author || rule.author.trim().length === 0) {
    warnings.push('Rule is missing an "author" field');
  }

  if (!rule.falsepositives || rule.falsepositives.length === 0) {
    warnings.push('Rule has no false-positive entries. Consider documenting known FPs.');
  }

  return {
    valid: errors.length === 0,
    syntaxValid: errors.length === 0,
    schemaValid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Validate a raw Sigma YAML string.
 *
 * First checks that the string is parseable YAML, then delegates to
 * {@link validateSigmaRule} for structural validation.
 *
 * @param yamlString - The raw YAML text.
 * @returns A {@link ValidationResult} with errors and warnings.
 */
export function validateSigmaYaml(yamlString: string): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // --- YAML Parsing ---

  let parsed: unknown;
  try {
    parsed = YAML.parse(yamlString);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      syntaxValid: false,
      schemaValid: false,
      errors: [`YAML parsing failed: ${message}`],
      warnings: [],
    };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return {
      valid: false,
      syntaxValid: true,
      schemaValid: false,
      errors: ['YAML content is not a valid Sigma rule object'],
      warnings: [],
    };
  }

  const obj = parsed as Record<string, unknown>;

  // Build a SigmaRule-shaped object for structural validation
  const rule: SigmaRule = {
    id: asString(obj['id']),
    title: asString(obj['title']),
    status: asString(obj['status']) as SigmaRule['status'],
    description: asString(obj['description']),
    references: asStringArray(obj['references']),
    author: asString(obj['author']),
    date: asString(obj['date']),
    modified: asString(obj['modified']),
    tags: asStringArray(obj['tags']),
    logsource: asLogsource(obj['logsource']),
    detection: asDetection(obj['detection']),
    falsepositives: asStringArray(obj['falsepositives']),
    level: asString(obj['level']) as SigmaRule['level'],
    raw: yamlString,
  };

  const structuralResult = validateSigmaRule(rule);
  errors.push(...structuralResult.errors);
  warnings.push(...structuralResult.warnings);

  return {
    valid: errors.length === 0,
    syntaxValid: true,
    schemaValid: errors.length === 0,
    errors,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Check that every name referenced in the `condition` string corresponds
 * to a key in the detection block.
 */
function validateConditionReferences(
  detection: Record<string, unknown>,
  errors: string[],
  _warnings: string[],
): void {
  const condition = detection.condition as string;

  // Extract all potential selection/filter identifiers from the condition.
  // We strip boolean operators and parentheses, then grab word tokens.
  const tokens = condition
    .replace(/\(|\)/g, ' ')
    .split(/\s+/)
    .filter((token) => {
      const lower = token.toLowerCase();
      return (
        token.length > 0 &&
        lower !== 'and' &&
        lower !== 'or' &&
        lower !== 'not' &&
        lower !== '1' &&
        lower !== 'of' &&
        lower !== 'them' &&
        lower !== 'all'
      );
    });

  const detectionKeys = new Set(
    Object.keys(detection).filter((k) => k !== 'condition'),
  );

  for (const token of tokens) {
    // Handle wildcard patterns like "selection_*" or "filter*" used with
    // the "1 of selection_*" Sigma syntax.  Also skip pure numeric tokens
    // (used in "1 of ..." syntax) and the special keyword "them".
    if (token.includes('*')) {
      const prefix = token.replace(/\*/g, '');
      const matched = [...detectionKeys].some((key) => key.startsWith(prefix));
      if (!matched && prefix.length > 0) {
        errors.push(
          `Condition references pattern "${token}" but no matching keys found in detection block`,
        );
      }
      continue;
    }

    // Skip pure numeric tokens ("1 of selection*")
    if (/^\d+$/.test(token)) {
      continue;
    }

    if (!detectionKeys.has(token)) {
      errors.push(
        `Condition references "${token}" which does not exist in the detection block. ` +
          `Available keys: ${[...detectionKeys].join(', ')}`,
      );
    }
  }
}

/** Safely coerce a value to string. */
function asString(val: unknown): string {
  if (typeof val === 'string') return val;
  if (val === undefined || val === null) return '';
  return String(val);
}

/** Safely coerce a value to string array. */
function asStringArray(val: unknown): string[] {
  if (Array.isArray(val)) {
    return val.map((v) => (typeof v === 'string' ? v : String(v)));
  }
  return [];
}

/** Safely coerce a value to a SigmaLogsource. */
function asLogsource(val: unknown): SigmaRule['logsource'] {
  if (typeof val === 'object' && val !== null) {
    const obj = val as Record<string, unknown>;
    return {
      product: asString(obj['product']) || undefined,
      category: asString(obj['category']) || undefined,
      service: asString(obj['service']) || undefined,
    };
  }
  return {};
}

/** Safely coerce a value to a SigmaDetection. */
function asDetection(val: unknown): SigmaRule['detection'] {
  if (typeof val === 'object' && val !== null) {
    const obj = val as Record<string, unknown>;
    return {
      ...obj,
      condition: asString(obj['condition']),
    };
  }
  return { condition: '' };
}
