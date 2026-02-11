/**
 * Rule effectiveness tester.
 *
 * Evaluates each Sigma rule's true-positive and false-positive rates by:
 * 1. Generating synthetic attack and benign logs via log-generator.ts
 * 2. Running the rule against both log sets via sigma-tester.ts
 * 3. Computing TP/FP/TN/FN rates and a pass/fail verdict
 *
 * All evaluation is in-memory with zero API calls.
 */

import type { SigmaRule } from '@/types/detection-rule.js';
import { generateTestLogs } from './log-generator.js';
import type { GeneratedLogSet } from './log-generator.js';
import { evaluateSigmaRuleSuite } from './sigma-tester.js';
import type { SigmaTestSuiteResult } from './sigma-tester.js';
import { validateRuleFields } from './field-validator.js';
import type { FieldValidationResult } from './field-validator.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface EffectivenessResult {
  ruleId: string;
  ruleTitle: string;
  /** Raw suite metrics from sigma-tester. */
  suite: SigmaTestSuiteResult;
  /** Field validation result. */
  fieldValidation: FieldValidationResult;
  /** Whether the rule passes all quality gate thresholds. */
  pass: boolean;
  /** Reasons for failure (empty if pass). */
  failures: string[];
}

export interface EffectivenessThresholds {
  /** Minimum TP rate (0-1). Default: 0.8 */
  minTpRate?: number;
  /** Maximum FP rate (0-1). Default: 0.1 */
  maxFpRate?: number;
  /** Minimum field validity rate (0-1). Default: 0.7 */
  minFieldValidity?: number;
}

export interface EffectivenessSummary {
  totalRules: number;
  passedRules: number;
  failedRules: number;
  avgTpRate: number;
  avgFpRate: number;
  avgFieldValidity: number;
  results: EffectivenessResult[];
}

export interface EffectivenessOptions {
  /** Number of attack logs to generate per rule. Default: 10 */
  attackLogCount?: number;
  /** Number of benign logs to generate per rule. Default: 20 */
  benignLogCount?: number;
  /** Pass/fail thresholds. */
  thresholds?: EffectivenessThresholds;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_THRESHOLDS: Required<EffectivenessThresholds> = {
  minTpRate: 0.8,
  maxFpRate: 0.1,
  minFieldValidity: 0.7,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Test a single Sigma rule's effectiveness.
 *
 * Generates synthetic logs, evaluates the rule against them, and checks
 * the results against configurable thresholds.
 */
export function testRuleEffectiveness(
  rule: SigmaRule,
  options?: EffectivenessOptions,
): EffectivenessResult {
  const attackCount = options?.attackLogCount ?? 10;
  const benignCount = options?.benignLogCount ?? 20;
  const thresholds = {
    ...DEFAULT_THRESHOLDS,
    ...options?.thresholds,
  };

  // Generate test logs
  const logSet: GeneratedLogSet = generateTestLogs(rule, {
    attackLogCount: attackCount,
    benignLogCount: benignCount,
  });

  // Evaluate rule against logs
  const suite: SigmaTestSuiteResult = evaluateSigmaRuleSuite(
    rule,
    logSet.attackLogs,
    logSet.benignLogs,
  );

  // Validate fields
  const fieldValidation: FieldValidationResult = validateRuleFields(rule);

  // Check thresholds
  const failures: string[] = [];

  if (suite.tpRate < thresholds.minTpRate) {
    failures.push(
      `TP rate ${pct(suite.tpRate)} < minimum ${pct(thresholds.minTpRate)}`,
    );
  }

  if (suite.fpRate > thresholds.maxFpRate) {
    failures.push(
      `FP rate ${pct(suite.fpRate)} > maximum ${pct(thresholds.maxFpRate)}`,
    );
  }

  if (
    !fieldValidation.unknownLogsource &&
    fieldValidation.fieldValidityRate < thresholds.minFieldValidity
  ) {
    failures.push(
      `Field validity ${pct(fieldValidation.fieldValidityRate)} < minimum ${pct(thresholds.minFieldValidity)}` +
        ` (invalid: ${fieldValidation.invalidFields.join(', ')})`,
    );
  }

  return {
    ruleId: rule.id,
    ruleTitle: rule.title,
    suite,
    fieldValidation,
    pass: failures.length === 0,
    failures,
  };
}

/**
 * Test multiple rules and return an aggregate summary.
 */
export function testRulesEffectiveness(
  rules: SigmaRule[],
  options?: EffectivenessOptions,
): EffectivenessSummary {
  const results = rules.map((rule) => testRuleEffectiveness(rule, options));

  const totalRules = results.length;
  const passedRules = results.filter((r) => r.pass).length;
  const failedRules = totalRules - passedRules;

  const avgTpRate =
    totalRules === 0
      ? 0
      : results.reduce((sum, r) => sum + r.suite.tpRate, 0) / totalRules;

  const avgFpRate =
    totalRules === 0
      ? 0
      : results.reduce((sum, r) => sum + r.suite.fpRate, 0) / totalRules;

  const avgFieldValidity =
    totalRules === 0
      ? 0
      : results.reduce((sum, r) => sum + r.fieldValidation.fieldValidityRate, 0) /
        totalRules;

  return {
    totalRules,
    passedRules,
    failedRules,
    avgTpRate,
    avgFpRate,
    avgFieldValidity,
    results,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pct(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}
