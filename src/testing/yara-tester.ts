/**
 * YARA rule testing and quality assessment.
 *
 * Validates YARA rules structurally and generates quality metrics
 * without requiring an external YARA compiler.  Evaluates:
 *
 * - Syntax validity via {@link validateYaraRule}
 * - String coverage: percentage of defined strings referenced in condition
 * - Condition complexity: count of logical operators
 * - Specificity estimation: high / medium / low based on heuristics
 * - Quality issues: overly broad patterns, short hex strings, etc.
 */

import type { YaraRule } from '@/types/detection-rule.js';
import { validateYaraRule } from '@/generation/yara/validator.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface YaraTestResult {
  ruleName: string;
  syntaxValid: boolean;
  structureValid: boolean;
  hasFileTypeConstraint: boolean;
  stringCoverage: number;
  conditionComplexity: number;
  estimatedSpecificity: 'high' | 'medium' | 'low';
  issues: string[];
  warnings: string[];
}

export interface YaraTestSuiteResult {
  totalRules: number;
  syntaxPassRate: number;
  structurePassRate: number;
  averageSpecificity: string;
  perRuleResults: YaraTestResult[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Logical operators counted for condition complexity. */
const CONDITION_OPERATORS = /\b(and|or|not|any\s+of|all\s+of|for\s+any|for\s+all)\b/gi;

/** Magic byte / file type indicators in conditions. */
const FILE_TYPE_INDICATORS = [
  'uint16(0)',
  'uint32(0)',
  'uint16be(0)',
  'uint32be(0)',
  'magic',
  'MZ',
  'PE',
  '4D5A',
  '7F454C46',  // ELF
  '504B0304',  // ZIP / OOXML
  '25504446',  // PDF
  'D0CF11E0',  // OLE
];

/** Minimum meaningful hex string length (bytes, not char pairs). */
const MIN_HEX_BYTES = 4;

/** Wildcard patterns considered overly broad. */
const BROAD_WILDCARD_RE = /\?\s*\?\s*\?\s*\?\s*\?\s*\?/;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Evaluate a single YARA rule's quality.
 *
 * Checks syntax validity, string coverage, condition complexity,
 * specificity estimation, and common quality issues.
 */
export function evaluateYaraRule(rule: YaraRule): YaraTestResult {
  const issues: string[] = [];
  const warnings: string[] = [];

  // 1. Syntax validity via the existing validator
  const validation = validateYaraRule(rule);
  const syntaxValid = validation.syntaxValid;
  const structureValid = validation.schemaValid;

  // Merge validator warnings
  for (const w of validation.warnings) {
    warnings.push(w);
  }
  for (const e of validation.errors) {
    issues.push(e);
  }

  // 2. String coverage: what % of defined strings appear in the condition
  const stringCoverage = calculateStringCoverage(rule);

  if (stringCoverage < 50 && rule.strings.length > 0) {
    warnings.push(
      `Only ${Math.round(stringCoverage)}% of defined strings are referenced in the condition.`,
    );
  }

  // 3. Condition complexity
  const conditionComplexity = calculateConditionComplexity(rule.condition);

  // 4. File type constraint detection
  const hasFileTypeConstraint = detectFileTypeConstraint(rule);

  // 5. Specificity estimation
  const estimatedSpecificity = estimateSpecificity(rule, hasFileTypeConstraint);

  // 6. Quality issue checks
  detectQualityIssues(rule, issues, warnings);

  return {
    ruleName: rule.name,
    syntaxValid,
    structureValid,
    hasFileTypeConstraint,
    stringCoverage,
    conditionComplexity,
    estimatedSpecificity,
    issues,
    warnings,
  };
}

/**
 * Evaluate a set of YARA rules and produce aggregate metrics.
 */
export function evaluateYaraRuleSuite(rules: YaraRule[]): YaraTestSuiteResult {
  const perRuleResults = rules.map(evaluateYaraRule);

  const totalRules = perRuleResults.length;

  const syntaxPassCount = perRuleResults.filter(r => r.syntaxValid).length;
  const syntaxPassRate = totalRules > 0 ? syntaxPassCount / totalRules : 0;

  const structurePassCount = perRuleResults.filter(r => r.structureValid).length;
  const structurePassRate = totalRules > 0 ? structurePassCount / totalRules : 0;

  const averageSpecificity = computeAverageSpecificity(perRuleResults);

  return {
    totalRules,
    syntaxPassRate,
    structurePassRate,
    averageSpecificity,
    perRuleResults,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Calculate the percentage of defined strings that are referenced
 * in the condition (by their `$identifier`).
 */
function calculateStringCoverage(rule: YaraRule): number {
  if (!rule.strings || rule.strings.length === 0) return 0;
  if (!rule.condition) return 0;

  const condition = rule.condition;

  // Check for wildcards like "any of them", "all of them", "$s*", etc.
  if (/\b(them)\b/.test(condition)) {
    return 100;
  }

  // Check for wildcard prefix references like ($s*)
  const wildcardRefs = condition.match(/\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\*\s*\)/g) || [];
  const referencedByWildcard = new Set<string>();

  for (const wRef of wildcardRefs) {
    const prefix = wRef.replace(/[()$*\s]/g, '');
    for (const str of rule.strings) {
      const bareId = str.identifier.replace(/^\$/, '');
      if (bareId.startsWith(prefix)) {
        referencedByWildcard.add(str.identifier);
      }
    }
  }

  // Check for explicit references
  const explicitRefs = condition.match(/\$[a-zA-Z_][a-zA-Z0-9_]*/g) || [];
  const referencedExplicitly = new Set(explicitRefs);

  let referencedCount = 0;
  for (const str of rule.strings) {
    if (referencedExplicitly.has(str.identifier) || referencedByWildcard.has(str.identifier)) {
      referencedCount++;
    }
  }

  return (referencedCount / rule.strings.length) * 100;
}

/**
 * Count logical operators in a YARA condition to gauge complexity.
 */
function calculateConditionComplexity(condition: string): number {
  if (!condition) return 0;
  const matches = condition.match(CONDITION_OPERATORS);
  return matches ? matches.length : 0;
}

/**
 * Detect whether the rule constrains file type via magic bytes,
 * uint16/uint32 checks, or filesize constraints.
 */
function detectFileTypeConstraint(rule: YaraRule): boolean {
  const condition = rule.condition || '';
  const raw = rule.raw || '';
  const combined = `${condition} ${raw}`;

  // Check for filesize constraint
  if (/\bfilesize\b/.test(combined)) return true;

  // Check for magic byte indicators
  for (const indicator of FILE_TYPE_INDICATORS) {
    if (combined.includes(indicator)) return true;
  }

  // Check hex strings for common magic bytes
  for (const str of rule.strings) {
    if (str.type === 'hex') {
      for (const magic of ['4D5A', '7F454C46', '504B0304', '25504446', 'D0CF11E0']) {
        if (str.value.replace(/\s/g, '').toUpperCase().startsWith(magic)) return true;
      }
    }
  }

  return false;
}

/**
 * Estimate specificity of the rule based on heuristics:
 * - high: filesize/magic bytes + 3+ strings
 * - medium: 2+ strings
 * - low: single string or very broad
 */
function estimateSpecificity(
  rule: YaraRule,
  hasFileTypeConstraint: boolean,
): 'high' | 'medium' | 'low' {
  const stringCount = rule.strings ? rule.strings.length : 0;

  if (hasFileTypeConstraint && stringCount >= 3) return 'high';
  if (stringCount >= 2) return 'medium';
  return 'low';
}

/**
 * Detect common quality issues in YARA rules.
 */
function detectQualityIssues(
  rule: YaraRule,
  issues: string[],
  warnings: string[],
): void {
  // Single-string conditions
  if (rule.strings && rule.strings.length === 1) {
    warnings.push(
      'Rule has only one string definition. Consider adding more strings for better specificity.',
    );
  }

  for (const str of rule.strings || []) {
    // Very short hex strings (less than MIN_HEX_BYTES)
    if (str.type === 'hex') {
      const hexChars = str.value.replace(/[\s?|\[\]\-()]/g, '');
      const byteCount = Math.floor(hexChars.length / 2);
      if (byteCount < MIN_HEX_BYTES && byteCount > 0) {
        warnings.push(
          `Hex string "${str.identifier}" is only ${byteCount} byte(s). Short hex strings increase false positive risk.`,
        );
      }
    }

    // Overly broad wildcards in hex strings
    if (str.type === 'hex' && BROAD_WILDCARD_RE.test(str.value)) {
      warnings.push(
        `Hex string "${str.identifier}" contains a broad wildcard sequence (6+ consecutive "??"). This may match too liberally.`,
      );
    }

    // Very short text strings
    if (str.type === 'text' && str.value.length < 4) {
      warnings.push(
        `Text string "${str.identifier}" is very short (${str.value.length} chars). Short text strings increase false positive risk.`,
      );
    }
  }

  // Condition that is just "any of them" with no other constraints
  if (rule.condition && /^\s*any\s+of\s+them\s*$/.test(rule.condition)) {
    issues.push(
      'Condition is "any of them" with no additional constraints. This is overly broad for most use cases.',
    );
  }

  // Missing filesize constraint for rules with many strings
  if (rule.strings && rule.strings.length > 5 && !detectFileTypeConstraint(rule)) {
    warnings.push(
      'Rule has many strings but no filesize or file type constraint. Consider adding filesize limits to improve performance.',
    );
  }
}

/**
 * Compute the modal (most common) specificity across rule results.
 */
function computeAverageSpecificity(results: YaraTestResult[]): string {
  if (results.length === 0) return 'low';

  const counts: Record<string, number> = { high: 0, medium: 0, low: 0 };
  for (const r of results) {
    counts[r.estimatedSpecificity]++;
  }

  if (counts.high >= counts.medium && counts.high >= counts.low) return 'high';
  if (counts.medium >= counts.low) return 'medium';
  return 'low';
}
