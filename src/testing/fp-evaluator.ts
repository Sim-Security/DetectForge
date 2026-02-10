/**
 * False-positive rate evaluator.
 *
 * Evaluates a set of Sigma rules against synthetically generated benign
 * logs to estimate false-positive rates.  Provides per-rule and aggregate
 * metrics and identifies the highest-FP rules with explanations.
 */

import type { SigmaRule } from '@/types/detection-rule.js';
import { evaluateSigmaRule } from './sigma-tester.js';
import type { LogEntry, SigmaTestSuiteResult } from './sigma-tester.js';
import { generateTestLogs } from './log-generator.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface FPEvaluationResult {
  totalRulesEvaluated: number;
  aggregateFPRate: number;
  perRuleResults: SigmaTestSuiteResult[];
  highestFPRules: Array<{
    ruleId: string;
    ruleTitle: string;
    fpRate: number;
    explanation: string;
  }>;
  passesThreshold: boolean;
}

export interface FPEvaluationOptions {
  fpRateThreshold?: number;
  benignLogsPerRule?: number;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Evaluate false-positive rates across a set of Sigma rules.
 *
 * For each rule:
 * 1. Generate benign logs using the log generator.
 * 2. Run the rule against every benign log.
 * 3. Compute the per-rule FP rate.
 *
 * Aggregate metrics and identify the highest-FP rules.
 */
export function evaluateFalsePositiveRates(
  rules: SigmaRule[],
  options?: FPEvaluationOptions,
): FPEvaluationResult {
  const threshold = options?.fpRateThreshold ?? 0.05;
  const benignCount = options?.benignLogsPerRule ?? 20;

  const perRuleResults: SigmaTestSuiteResult[] = [];
  let totalFP = 0;
  let totalTN = 0;

  for (const rule of rules) {
    const logSet = generateTestLogs(rule, {
      attackLogCount: 0,
      benignLogCount: benignCount,
    });

    const benignLogs: LogEntry[] = logSet.benignLogs;

    let fp = 0;
    let tn = 0;

    for (const log of benignLogs) {
      const result = evaluateSigmaRule(rule, log);
      if (result.matched) {
        fp++;
      } else {
        tn++;
      }
    }

    const fpRate = fp + tn === 0 ? 0 : fp / (fp + tn);

    const suiteResult: SigmaTestSuiteResult = {
      ruleId: rule.id,
      ruleTitle: rule.title,
      truePositives: 0,
      falseNegatives: 0,
      trueNegatives: tn,
      falsePositives: fp,
      tpRate: 0,
      fpRate,
    };

    perRuleResults.push(suiteResult);
    totalFP += fp;
    totalTN += tn;
  }

  const aggregateFPRate =
    totalFP + totalTN === 0 ? 0 : totalFP / (totalFP + totalTN);

  // Identify highest-FP rules (any with fpRate > 0, sorted descending)
  const highestFPRules = perRuleResults
    .filter((r) => r.fpRate > 0)
    .sort((a, b) => b.fpRate - a.fpRate)
    .map((r) => ({
      ruleId: r.ruleId,
      ruleTitle: r.ruleTitle,
      fpRate: r.fpRate,
      explanation: buildFPExplanation(r, rules),
    }));

  return {
    totalRulesEvaluated: rules.length,
    aggregateFPRate,
    perRuleResults,
    highestFPRules,
    passesThreshold: aggregateFPRate < threshold,
  };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Build a human-readable explanation of why a rule has a high FP rate.
 */
function buildFPExplanation(
  result: SigmaTestSuiteResult,
  rules: SigmaRule[],
): string {
  const rule = rules.find((r) => r.id === result.ruleId);
  if (!rule) {
    return `Rule ${result.ruleId} had an FP rate of ${formatPercent(result.fpRate)}.`;
  }

  const parts: string[] = [];

  parts.push(
    `Rule "${result.ruleTitle}" triggered on ${result.falsePositives} out of ` +
      `${result.falsePositives + result.trueNegatives} benign logs ` +
      `(${formatPercent(result.fpRate)} FP rate).`,
  );

  // Analyse why — look at the rule's detection logic
  const detection = rule.detection;
  const condition = detection.condition;

  // Count selections in the condition
  const selectionCount = Object.keys(detection).filter(
    (k) => k !== 'condition',
  ).length;

  if (selectionCount === 1) {
    parts.push(
      'The rule uses a single selection block, which may be too broad.',
    );
  }

  // Check if condition has filters
  const hasFilter =
    condition.toLowerCase().includes('not') ||
    condition.toLowerCase().includes('filter');

  if (!hasFilter) {
    parts.push(
      'The rule has no filter/exclusion conditions. Consider adding exclusions ' +
        'for known legitimate activity.',
    );
  }

  // Check for overly generic wildcards
  const allValues = extractAllDetectionValues(detection);
  const broadWildcards = allValues.filter(
    (v) => v === '*' || v === '*\\*' || v === '**',
  );
  if (broadWildcards.length > 0) {
    parts.push(
      `The rule contains ${broadWildcards.length} overly broad wildcard pattern(s) ` +
        'that may match too many log entries.',
    );
  }

  // Check documented false positives
  if (rule.falsepositives && rule.falsepositives.length > 0) {
    parts.push(
      `Known FP scenarios: ${rule.falsepositives.join('; ')}.`,
    );
  }

  return parts.join(' ');
}

/**
 * Extract all string values from a detection block.
 */
function extractAllDetectionValues(
  detection: Record<string, unknown>,
): string[] {
  const values: string[] = [];

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;
    collectValues(value, values);
  }

  return values;
}

function collectValues(value: unknown, accumulator: string[]): void {
  if (typeof value === 'string') {
    accumulator.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectValues(item, accumulator);
    }
    return;
  }
  if (typeof value === 'object' && value !== null) {
    for (const v of Object.values(value)) {
      collectValues(v, accumulator);
    }
  }
}

/**
 * Format a rate as a percentage string.
 */
function formatPercent(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}
