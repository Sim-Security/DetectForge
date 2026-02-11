/**
 * Unit tests for the effectiveness tester.
 */

import { describe, it, expect } from 'vitest';
import {
  testRuleEffectiveness,
  testRulesEffectiveness,
} from '@/testing/effectiveness-tester.js';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(
  detection: Record<string, unknown> & { condition: string },
  overrides: Partial<SigmaRule> = {},
): SigmaRule {
  return {
    id: 'eff-test-0001-0000-000000000001',
    title: 'Effectiveness Test Rule',
    status: 'experimental',
    description: 'A test rule for effectiveness testing.',
    references: [],
    author: 'DetectForge',
    date: '2026/02/10',
    modified: '2026/02/10',
    tags: ['attack.execution'],
    logsource: { product: 'windows', category: 'process_creation' },
    detection,
    falsepositives: [],
    level: 'high',
    raw: '',
    ...overrides,
  };
}

// ===========================================================================
// testRuleEffectiveness
// ===========================================================================

describe('testRuleEffectiveness', () => {
  it('returns a result with expected structure', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    const result = testRuleEffectiveness(rule);

    expect(result.ruleId).toBe(rule.id);
    expect(result.ruleTitle).toBe(rule.title);
    expect(result.suite).toBeDefined();
    expect(result.fieldValidation).toBeDefined();
    expect(typeof result.pass).toBe('boolean');
    expect(Array.isArray(result.failures)).toBe(true);
  });

  it('reports TP and FP rates', () => {
    const rule = makeRule({
      selection: {
        Image: '*\\cmd.exe',
        CommandLine: '*whoami*',
      },
      condition: 'selection',
    });

    const result = testRuleEffectiveness(rule);

    expect(result.suite.tpRate).toBeGreaterThanOrEqual(0);
    expect(result.suite.tpRate).toBeLessThanOrEqual(1);
    expect(result.suite.fpRate).toBeGreaterThanOrEqual(0);
    expect(result.suite.fpRate).toBeLessThanOrEqual(1);
  });

  it('passes a well-constructed rule with valid fields', () => {
    const rule = makeRule({
      selection: {
        Image: ['*\\cmd.exe', '*\\powershell.exe'],
        CommandLine: '*whoami*',
      },
      filter_system: { User: 'SYSTEM' },
      condition: 'selection and not filter_system',
    });

    const result = testRuleEffectiveness(rule);

    // Attack logs should trigger (high TP rate)
    expect(result.suite.tpRate).toBeGreaterThan(0);
    // Field validation should succeed
    expect(result.fieldValidation.invalidFields).toHaveLength(0);
  });

  it('flags rules with invalid fields', () => {
    const rule = makeRule({
      selection: {
        Image: '*\\cmd.exe',
        NonExistentField: 'value',
        AnotherFakeField: 'value2',
      },
      condition: 'selection',
    });

    const result = testRuleEffectiveness(rule, {
      thresholds: { minFieldValidity: 0.7 },
    });

    expect(result.fieldValidation.invalidFields.length).toBeGreaterThan(0);
  });

  it('respects custom thresholds', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    // Very strict thresholds
    const strict = testRuleEffectiveness(rule, {
      thresholds: { minTpRate: 0.99, maxFpRate: 0.0, minFieldValidity: 1.0 },
    });

    // Very lenient thresholds
    const lenient = testRuleEffectiveness(rule, {
      thresholds: { minTpRate: 0.0, maxFpRate: 1.0, minFieldValidity: 0.0 },
    });

    // Lenient should always pass
    expect(lenient.pass).toBe(true);
    expect(lenient.failures).toHaveLength(0);
  });

  it('respects custom log counts', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    const result = testRuleEffectiveness(rule, {
      attackLogCount: 3,
      benignLogCount: 5,
    });

    const total =
      result.suite.truePositives +
      result.suite.falseNegatives +
      result.suite.trueNegatives +
      result.suite.falsePositives;
    expect(total).toBe(8); // 3 attack + 5 benign
  });
});

// ===========================================================================
// testRulesEffectiveness
// ===========================================================================

describe('testRulesEffectiveness', () => {
  it('returns aggregate metrics for multiple rules', () => {
    const rules = [
      makeRule(
        {
          selection: { Image: '*\\cmd.exe' },
          condition: 'selection',
        },
        { id: 'rule-001a-0000-0000-000000000001', title: 'Rule 1' },
      ),
      makeRule(
        {
          selection: {
            Image: '*\\powershell.exe',
            CommandLine: '*Invoke-*',
          },
          condition: 'selection',
        },
        { id: 'rule-002a-0000-0000-000000000002', title: 'Rule 2' },
      ),
    ];

    const summary = testRulesEffectiveness(rules, {
      attackLogCount: 5,
      benignLogCount: 10,
    });

    expect(summary.totalRules).toBe(2);
    expect(summary.passedRules + summary.failedRules).toBe(2);
    expect(summary.results).toHaveLength(2);
    expect(summary.avgTpRate).toBeGreaterThanOrEqual(0);
    expect(summary.avgFpRate).toBeGreaterThanOrEqual(0);
    expect(summary.avgFieldValidity).toBeGreaterThanOrEqual(0);
  });

  it('handles empty rule set', () => {
    const summary = testRulesEffectiveness([]);

    expect(summary.totalRules).toBe(0);
    expect(summary.passedRules).toBe(0);
    expect(summary.failedRules).toBe(0);
    expect(summary.avgTpRate).toBe(0);
    expect(summary.avgFpRate).toBe(0);
  });
});
