/**
 * Suricata rule testing and quality assessment.
 *
 * Validates Suricata rules structurally and generates quality metrics.
 * Evaluates:
 *
 * - Syntax validity via {@link validateSuricataRule}
 * - Content match presence and count
 * - Flow constraint detection
 * - Specificity estimation: high / medium / low
 * - Quality issues: missing flow, overly broad patterns, etc.
 * - Duplicate SID detection across rule sets
 */

import type { SuricataRule } from '@/types/detection-rule.js';
import { validateSuricataRule } from '@/generation/suricata/validator.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface SuricataTestResult {
  sid: number;
  msg: string;
  syntaxValid: boolean;
  structureValid: boolean;
  hasContentMatch: boolean;
  contentMatchCount: number;
  hasFlowConstraint: boolean;
  estimatedSpecificity: 'high' | 'medium' | 'low';
  issues: string[];
  warnings: string[];
}

export interface SuricataTestSuiteResult {
  totalRules: number;
  syntaxPassRate: number;
  structurePassRate: number;
  averageSpecificity: string;
  duplicateSIDs: number[];
  perRuleResults: SuricataTestResult[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Keywords that represent content-matching options. */
const CONTENT_KEYWORDS = new Set([
  'content',
  'pcre',
  'byte_test',
  'byte_jump',
  'isdataat',
  'urilen',
  'dsize',
]);

/** Keywords that constrain flow direction or state. */
const FLOW_KEYWORDS = new Set([
  'flow',
  'flowbits',
  'stream_size',
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Evaluate a single Suricata rule's quality.
 *
 * Checks syntax validity, content match presence and count,
 * flow constraints, specificity estimation, and common quality issues.
 */
export function evaluateSuricataRule(rule: SuricataRule): SuricataTestResult {
  const issues: string[] = [];
  const warnings: string[] = [];

  // 1. Syntax validity via the existing validator
  const validation = validateSuricataRule(rule);
  const syntaxValid = validation.syntaxValid;
  const structureValid = validation.schemaValid;

  // Merge validator findings
  for (const w of validation.warnings) {
    warnings.push(w);
  }
  for (const e of validation.errors) {
    issues.push(e);
  }

  // 2. Extract the msg option value
  const msgOption = rule.options.find(o => o.keyword === 'msg');
  const msg = msgOption?.value?.replace(/^"|"$/g, '') ?? '';

  // 3. Content match analysis
  const contentMatchCount = countContentMatches(rule);
  const hasContentMatch = contentMatchCount > 0;

  // 4. Flow constraint detection
  const hasFlowConstraint = detectFlowConstraint(rule);

  // 5. Specificity estimation
  const estimatedSpecificity = estimateSpecificity(rule, contentMatchCount, hasFlowConstraint);

  // 6. Quality issue checks
  detectQualityIssues(rule, contentMatchCount, hasFlowConstraint, issues, warnings);

  return {
    sid: rule.sid,
    msg,
    syntaxValid,
    structureValid,
    hasContentMatch,
    contentMatchCount,
    hasFlowConstraint,
    estimatedSpecificity,
    issues,
    warnings,
  };
}

/**
 * Evaluate a set of Suricata rules and produce aggregate metrics.
 */
export function evaluateSuricataRuleSuite(rules: SuricataRule[]): SuricataTestSuiteResult {
  const perRuleResults = rules.map(evaluateSuricataRule);

  const totalRules = perRuleResults.length;

  const syntaxPassCount = perRuleResults.filter(r => r.syntaxValid).length;
  const syntaxPassRate = totalRules > 0 ? syntaxPassCount / totalRules : 0;

  const structurePassCount = perRuleResults.filter(r => r.structureValid).length;
  const structurePassRate = totalRules > 0 ? structurePassCount / totalRules : 0;

  const averageSpecificity = computeAverageSpecificity(perRuleResults);

  // Detect duplicate SIDs
  const duplicateSIDs = detectDuplicateSIDs(rules);

  return {
    totalRules,
    syntaxPassRate,
    structurePassRate,
    averageSpecificity,
    duplicateSIDs,
    perRuleResults,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Count the number of content-matching keywords in a rule's options.
 */
function countContentMatches(rule: SuricataRule): number {
  let count = 0;
  for (const opt of rule.options) {
    if (CONTENT_KEYWORDS.has(opt.keyword)) {
      count++;
    }
  }
  return count;
}

/**
 * Detect whether the rule has a flow constraint.
 */
function detectFlowConstraint(rule: SuricataRule): boolean {
  for (const opt of rule.options) {
    if (FLOW_KEYWORDS.has(opt.keyword)) {
      return true;
    }
  }
  return false;
}

/**
 * Estimate specificity based on content match count and flow constraint:
 * - high: 3+ content matches + flow constraint
 * - medium: 2+ content matches or (1 content + flow)
 * - low: 0-1 content matches without flow
 */
function estimateSpecificity(
  _rule: SuricataRule,
  contentMatchCount: number,
  hasFlowConstraint: boolean,
): 'high' | 'medium' | 'low' {
  if (contentMatchCount >= 3 && hasFlowConstraint) return 'high';
  if (contentMatchCount >= 2 || (contentMatchCount >= 1 && hasFlowConstraint)) return 'medium';
  return 'low';
}

/**
 * Detect common quality issues in Suricata rules.
 */
function detectQualityIssues(
  rule: SuricataRule,
  contentMatchCount: number,
  hasFlowConstraint: boolean,
  issues: string[],
  warnings: string[],
): void {
  // No content match at all
  if (contentMatchCount === 0) {
    issues.push(
      'Rule has no content-matching keywords (content, pcre, byte_test, etc.). ' +
      'This may result in matching all traffic on the specified protocol/port.',
    );
  }

  // No flow constraint
  if (!hasFlowConstraint) {
    warnings.push(
      'Rule has no flow constraint. Consider adding "flow:established,to_server;" ' +
      'or similar to reduce false positives.',
    );
  }

  // Content matches with very short patterns
  for (const opt of rule.options) {
    if (opt.keyword === 'content' && opt.value) {
      const cleaned = opt.value.replace(/^"|"$/g, '').replace(/\|[^|]*\|/g, '');
      if (cleaned.length > 0 && cleaned.length < 4) {
        warnings.push(
          `Content match "${opt.value}" is very short (${cleaned.length} printable chars). ` +
          'Short content matches increase false positive risk.',
        );
      }
    }
  }

  // Check for classtype option
  const hasClasstype = rule.options.some(o => o.keyword === 'classtype');
  if (!hasClasstype) {
    warnings.push(
      'Rule has no "classtype" option. Adding a classtype helps with rule categorization.',
    );
  }

  // Check for reference option
  const hasReference = rule.options.some(o => o.keyword === 'reference');
  if (!hasReference) {
    warnings.push(
      'Rule has no "reference" option. Adding references improves traceability.',
    );
  }

  // Alert on any protocol with destination port "any" and no flow constraint
  if (rule.destPort === 'any' && rule.sourcePort === 'any' && !hasFlowConstraint) {
    warnings.push(
      'Both source and destination ports are "any" without a flow constraint. ' +
      'This is very broad and may generate excessive alerts.',
    );
  }
}

/**
 * Detect duplicate SIDs across a set of Suricata rules.
 * Returns an array of SID numbers that appear more than once.
 */
function detectDuplicateSIDs(rules: SuricataRule[]): number[] {
  const sidCounts = new Map<number, number>();
  for (const rule of rules) {
    sidCounts.set(rule.sid, (sidCounts.get(rule.sid) ?? 0) + 1);
  }

  const duplicates: number[] = [];
  for (const [sid, count] of sidCounts) {
    if (count > 1) {
      duplicates.push(sid);
    }
  }
  return duplicates.sort((a, b) => a - b);
}

/**
 * Compute the modal (most common) specificity across rule results.
 */
function computeAverageSpecificity(results: SuricataTestResult[]): string {
  if (results.length === 0) return 'low';

  const counts: Record<string, number> = { high: 0, medium: 0, low: 0 };
  for (const r of results) {
    counts[r.estimatedSpecificity]++;
  }

  if (counts.high >= counts.medium && counts.high >= counts.low) return 'high';
  if (counts.medium >= counts.low) return 'medium';
  return 'low';
}
