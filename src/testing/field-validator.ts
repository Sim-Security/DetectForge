/**
 * Field validator for Sigma rules.
 *
 * Checks that detection fields actually exist in the target logsource.
 * Catches mistakes like using "IpAddress" in a process_creation rule
 * (which only has fields like Image, CommandLine, etc.).
 */

import { getFieldsForLogsource } from '@/knowledge/logsource-catalog/index.js';
import type { SigmaRule, SigmaLogsource } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface FieldValidationResult {
  /** Fields used in detection that exist in the logsource catalog. */
  validFields: string[];
  /** Fields used in detection that do NOT exist in the logsource catalog. */
  invalidFields: string[];
  /** Ratio of valid fields to total fields (0-1). */
  fieldValidityRate: number;
  /** True when the logsource isn't in our catalog (cloud, custom). */
  unknownLogsource: boolean;
  /** All fields extracted from the detection block. */
  allDetectionFields: string[];
}

// ---------------------------------------------------------------------------
// Known products in our catalog
// ---------------------------------------------------------------------------

const KNOWN_PRODUCTS = new Set(['windows', 'linux']);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate that a Sigma rule's detection fields exist in the target logsource.
 *
 * Extracts every field name from the detection block (stripping Sigma
 * modifiers like `|contains`, `|endswith`), then checks each against the
 * fields registered for the rule's logsource in the catalog.
 *
 * If the logsource product is not in our catalog (e.g. cloud providers),
 * returns `unknownLogsource: true` with all fields marked valid to avoid
 * false failures.
 */
export function validateRuleFields(rule: SigmaRule): FieldValidationResult {
  const logsource = rule.logsource;

  // Check if this logsource is in our catalog
  if (!isKnownLogsource(logsource)) {
    const allFields = extractDetectionFields(rule.detection);
    return {
      validFields: allFields,
      invalidFields: [],
      fieldValidityRate: 1,
      unknownLogsource: true,
      allDetectionFields: allFields,
    };
  }

  // Get the fields available for this logsource
  const catalogFields = getFieldsForLogsource(
    logsource.product ?? '',
    logsource.category,
    logsource.service,
  );

  // If catalog returned no fields, treat as unknown to avoid false failures
  if (catalogFields.length === 0) {
    const allFields = extractDetectionFields(rule.detection);
    return {
      validFields: allFields,
      invalidFields: [],
      fieldValidityRate: 1,
      unknownLogsource: true,
      allDetectionFields: allFields,
    };
  }

  // Build case-insensitive lookup set
  const knownFieldsLower = new Set(catalogFields.map((f) => f.toLowerCase()));

  const allFields = extractDetectionFields(rule.detection);
  const validFields: string[] = [];
  const invalidFields: string[] = [];

  for (const field of allFields) {
    if (knownFieldsLower.has(field.toLowerCase())) {
      validFields.push(field);
    } else {
      invalidFields.push(field);
    }
  }

  const total = allFields.length;
  const fieldValidityRate = total === 0 ? 1 : validFields.length / total;

  return {
    validFields,
    invalidFields,
    fieldValidityRate,
    unknownLogsource: false,
    allDetectionFields: allFields,
  };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Check whether a logsource product is known to our catalog.
 */
function isKnownLogsource(logsource: SigmaLogsource): boolean {
  if (!logsource.product) return false;
  return KNOWN_PRODUCTS.has(logsource.product.toLowerCase());
}

/**
 * Extract all unique field names from a Sigma detection block.
 *
 * Strips Sigma modifiers (e.g. `CommandLine|contains` → `CommandLine`).
 * Skips the `condition` key.
 */
export function extractDetectionFields(
  detection: Record<string, unknown>,
): string[] {
  const fields = new Set<string>();

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;
    collectFieldNames(value, fields);
  }

  return [...fields];
}

/**
 * Recursively collect field names from a selection block value.
 *
 * Handles:
 * - Plain objects (map of field → values)
 * - Array-of-maps (Sigma list selection)
 */
function collectFieldNames(value: unknown, fields: Set<string>): void {
  if (typeof value !== 'object' || value === null) return;

  if (Array.isArray(value)) {
    for (const item of value) {
      collectFieldNames(item, fields);
    }
    return;
  }

  const obj = value as Record<string, unknown>;
  for (const rawKey of Object.keys(obj)) {
    // Strip modifiers: "CommandLine|contains|all" → "CommandLine"
    const fieldName = rawKey.split('|')[0];
    if (fieldName.length > 0) {
      fields.add(fieldName);
    }
  }
}
