/**
 * Quality gate for Sigma rules.
 *
 * Combines all validators (quality scorer, effectiveness tester, field
 * validator, condition checks) into a single pass/fail verdict per rule.
 *
 * Three tiered profiles control strictness:
 * - **dev**: Lenient thresholds for rapid iteration
 * - **standard**: Production-ready baseline
 * - **production**: Strict thresholds for high-confidence deployment
 */

import type { SigmaRule, GeneratedRule, ValidationResult } from '@/types/detection-rule.js';
import { scoreRuleQuality } from './quality-scorer.js';
import type { RuleQualityScore } from './quality-scorer.js';
import { testRuleEffectiveness } from './effectiveness-tester.js';
import type { EffectivenessResult } from './effectiveness-tester.js';
import { validateRuleFields } from './field-validator.js';
import type { FieldValidationResult } from './field-validator.js';
import { validateSigmaRule } from '@/generation/sigma/validator.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export type QualityProfile = 'dev' | 'standard' | 'production';

export interface QualityGateThresholds {
  /** Minimum quality score (1-10). */
  minQualityScore: number;
  /** Minimum TP rate (0-1). */
  minTpRate: number;
  /** Maximum FP rate (0-1). */
  maxFpRate: number;
  /** Minimum field validity rate (0-1). */
  minFieldValidity: number;
  /** Whether rule must have filter/exclusion blocks. */
  requiresFilters: boolean;
  /** Minimum falsepositives[] entries. */
  minFalsePositiveEntries: number;
}

export interface QualityGateResult {
  ruleId: string;
  ruleTitle: string;
  profile: QualityProfile;
  pass: boolean;
  checks: QualityGateCheck[];
  qualityScore: RuleQualityScore;
  effectiveness: EffectivenessResult;
  fieldValidation: FieldValidationResult;
  validation: ValidationResult;
}

export interface QualityGateCheck {
  name: string;
  pass: boolean;
  actual: string;
  threshold: string;
}

export interface QualityGateSummary {
  profile: QualityProfile;
  totalRules: number;
  passedRules: number;
  failedRules: number;
  results: QualityGateResult[];
}

// ---------------------------------------------------------------------------
// Profile Definitions
// ---------------------------------------------------------------------------

const PROFILES: Record<QualityProfile, QualityGateThresholds> = {
  dev: {
    minQualityScore: 3.0,
    minTpRate: 0.5,
    maxFpRate: 0.3,
    minFieldValidity: 0.5,
    requiresFilters: false,
    minFalsePositiveEntries: 0,
  },
  standard: {
    minQualityScore: 5.0,
    minTpRate: 0.8,
    maxFpRate: 0.1,
    minFieldValidity: 0.7,
    requiresFilters: false,
    minFalsePositiveEntries: 1,
  },
  production: {
    minQualityScore: 7.0,
    minTpRate: 0.9,
    maxFpRate: 0.05,
    minFieldValidity: 0.9,
    requiresFilters: true,
    minFalsePositiveEntries: 2,
  },
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Get the thresholds for a given quality profile.
 */
export function getProfileThresholds(profile: QualityProfile): QualityGateThresholds {
  return { ...PROFILES[profile] };
}

/**
 * Run the quality gate on a single Sigma rule.
 *
 * Performs all checks and returns a detailed result with per-check pass/fail.
 */
export function runQualityGate(
  rule: SigmaRule,
  profile: QualityProfile = 'standard',
): QualityGateResult {
  const thresholds = PROFILES[profile];
  const checks: QualityGateCheck[] = [];

  // 1. Validation
  const validation = validateSigmaRule(rule);

  // 2. Quality score
  const generatedRule: GeneratedRule = {
    format: 'sigma',
    sigma: rule,
    sourceReportId: '',
    attackTechniqueId: extractTechniqueId(rule.tags),
    attackTactic: extractTactic(rule.tags),
    confidence: 'medium',
    validation,
  };
  const qualityScore = scoreRuleQuality(generatedRule);

  checks.push({
    name: 'Quality Score',
    pass: qualityScore.overallScore >= thresholds.minQualityScore,
    actual: qualityScore.overallScore.toFixed(1),
    threshold: `>= ${thresholds.minQualityScore}`,
  });

  // 3. Effectiveness (TP/FP rates)
  const effectiveness = testRuleEffectiveness(rule, {
    attackLogCount: 10,
    benignLogCount: 20,
    thresholds: {
      minTpRate: thresholds.minTpRate,
      maxFpRate: thresholds.maxFpRate,
      minFieldValidity: thresholds.minFieldValidity,
    },
  });

  checks.push({
    name: 'TP Rate',
    pass: effectiveness.suite.tpRate >= thresholds.minTpRate,
    actual: pct(effectiveness.suite.tpRate),
    threshold: `>= ${pct(thresholds.minTpRate)}`,
  });

  checks.push({
    name: 'FP Rate',
    pass: effectiveness.suite.fpRate <= thresholds.maxFpRate,
    actual: pct(effectiveness.suite.fpRate),
    threshold: `<= ${pct(thresholds.maxFpRate)}`,
  });

  // 4. Field validation
  const fieldValidation = validateRuleFields(rule);

  if (!fieldValidation.unknownLogsource) {
    checks.push({
      name: 'Field Validity',
      pass: fieldValidation.fieldValidityRate >= thresholds.minFieldValidity,
      actual: pct(fieldValidation.fieldValidityRate),
      threshold: `>= ${pct(thresholds.minFieldValidity)}`,
    });
  }

  // 5. Filter requirement
  if (thresholds.requiresFilters) {
    const hasFilters = hasFilterBlocks(rule);
    checks.push({
      name: 'Has Filters',
      pass: hasFilters,
      actual: hasFilters ? 'yes' : 'no',
      threshold: 'required',
    });
  }

  // 6. False positive documentation
  const fpCount = rule.falsepositives?.length ?? 0;
  checks.push({
    name: 'FP Entries',
    pass: fpCount >= thresholds.minFalsePositiveEntries,
    actual: String(fpCount),
    threshold: `>= ${thresholds.minFalsePositiveEntries}`,
  });

  const pass = checks.every((c) => c.pass);

  return {
    ruleId: rule.id,
    ruleTitle: rule.title,
    profile,
    pass,
    checks,
    qualityScore,
    effectiveness,
    fieldValidation,
    validation,
  };
}

/**
 * Run the quality gate on multiple rules and return a summary.
 */
export function runQualityGateBatch(
  rules: SigmaRule[],
  profile: QualityProfile = 'standard',
): QualityGateSummary {
  const results = rules.map((rule) => runQualityGate(rule, profile));
  const passedRules = results.filter((r) => r.pass).length;

  return {
    profile,
    totalRules: results.length,
    passedRules,
    failedRules: results.length - passedRules,
    results,
  };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

function hasFilterBlocks(rule: SigmaRule): boolean {
  const condition = rule.detection.condition.toLowerCase();
  const detKeys = Object.keys(rule.detection).filter((k) => k !== 'condition');

  // Check if any detection keys are filter/exclusion blocks
  const hasFilterKey = detKeys.some(
    (k) => k.startsWith('filter') || k.startsWith('exclusion'),
  );

  // Also check if condition uses NOT
  const hasNot = condition.includes('not ');

  return hasFilterKey || hasNot;
}

function extractTechniqueId(tags: string[]): string | undefined {
  const match = tags.find((t) => /^attack\.t\d{4}/i.test(t));
  if (!match) return undefined;
  return match.replace(/^attack\./i, '').toUpperCase();
}

function extractTactic(tags: string[]): string | undefined {
  return tags.find(
    (t) => t.startsWith('attack.') && !/^attack\.t\d{4}/i.test(t),
  )?.replace(/^attack\./, '');
}

function pct(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}
