/**
 * Unit tests for the false-positive rate evaluator.
 *
 * Covers: per-rule FP evaluation, aggregate metrics, threshold checking,
 * highest-FP identification, and edge cases.
 */

import { describe, it, expect } from 'vitest';
import { evaluateFalsePositiveRates } from '@/testing/fp-evaluator.js';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(
  detection: Record<string, unknown> & { condition: string },
  overrides: Partial<SigmaRule> = {},
): SigmaRule {
  return {
    id: 'fp-eval-0001-0000-000000000001',
    title: 'FP Evaluator Test Rule',
    status: 'experimental',
    description: 'A test rule for FP evaluation.',
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
// Basic FP Evaluation
// ===========================================================================

describe('evaluateFalsePositiveRates', () => {
  describe('output structure', () => {
    it('returns correct totalRulesEvaluated', () => {
      const rules = [
        makeRule({
          selection: { Image: '*\\cmd.exe' },
          condition: 'selection',
        }),
        makeRule(
          {
            selection: { Image: '*\\powershell.exe' },
            condition: 'selection',
          },
          { id: 'fp-eval-0002-0000-000000000002', title: 'Rule 2' },
        ),
      ];

      const result = evaluateFalsePositiveRates(rules);
      expect(result.totalRulesEvaluated).toBe(2);
    });

    it('returns perRuleResults for each rule', () => {
      const rules = [
        makeRule({
          selection: { Image: '*\\cmd.exe' },
          condition: 'selection',
        }),
      ];

      const result = evaluateFalsePositiveRates(rules);
      expect(result.perRuleResults).toHaveLength(1);
      expect(result.perRuleResults[0].ruleId).toBe(rules[0].id);
    });

    it('returns aggregateFPRate as a number', () => {
      const rules = [
        makeRule({
          selection: { Image: '*\\cmd.exe' },
          condition: 'selection',
        }),
      ];

      const result = evaluateFalsePositiveRates(rules);
      expect(typeof result.aggregateFPRate).toBe('number');
      expect(result.aggregateFPRate).toBeGreaterThanOrEqual(0);
      expect(result.aggregateFPRate).toBeLessThanOrEqual(1);
    });
  });

  // =========================================================================
  // Threshold Checking
  // =========================================================================

  describe('threshold checking', () => {
    it('passes threshold for a specific rule (default 5%)', () => {
      // A very specific rule is unlikely to trigger on benign logs
      const rule = makeRule({
        selection: {
          Image: '*\\cmd.exe',
          CommandLine: '*-encodedcommand*',
          User: 'evil_hacker',
        },
        condition: 'selection',
      });

      const result = evaluateFalsePositiveRates([rule], {
        benignLogsPerRule: 20,
      });

      expect(result.passesThreshold).toBe(true);
    });

    it('uses custom threshold', () => {
      const rule = makeRule({
        selection: {
          Image: '*\\cmd.exe',
          CommandLine: '*-encodedcommand*',
        },
        condition: 'selection',
      });

      const result = evaluateFalsePositiveRates([rule], {
        fpRateThreshold: 1.0, // 100% — should always pass
        benignLogsPerRule: 10,
      });

      expect(result.passesThreshold).toBe(true);
    });

    it('strict zero threshold fails if any FP exists', () => {
      // A broad rule that might match benign logs
      const rule = makeRule({
        selection: { Image: '*' },
        condition: 'selection',
      });

      const result = evaluateFalsePositiveRates([rule], {
        fpRateThreshold: 0,
        benignLogsPerRule: 10,
      });

      // "*" matches everything so FP rate should be 1.0
      expect(result.aggregateFPRate).toBe(1);
      expect(result.passesThreshold).toBe(false);
    });
  });

  // =========================================================================
  // Broad vs Specific Rules
  // =========================================================================

  describe('broad vs specific rules', () => {
    it('a very broad rule has a high FP rate', () => {
      const broadRule = makeRule({
        selection: { Image: '*' },
        condition: 'selection',
      });

      const result = evaluateFalsePositiveRates([broadRule], {
        benignLogsPerRule: 20,
      });

      expect(result.perRuleResults[0].fpRate).toBe(1);
      expect(result.highestFPRules.length).toBeGreaterThan(0);
      expect(result.highestFPRules[0].fpRate).toBe(1);
    });

    it('a specific rule with many conditions has a low FP rate', () => {
      const specificRule = makeRule({
        selection: {
          Image: '*\\cmd.exe',
          CommandLine: '*-encodedcommand*',
          User: 'attacker_user_xyz',
        },
        condition: 'selection',
      });

      const result = evaluateFalsePositiveRates([specificRule], {
        benignLogsPerRule: 20,
      });

      expect(result.perRuleResults[0].fpRate).toBeLessThan(0.5);
    });
  });

  // =========================================================================
  // Highest-FP Rules
  // =========================================================================

  describe('highest FP rules identification', () => {
    it('identifies rules with FP rate > 0', () => {
      const broadRule = makeRule(
        {
          selection: { Image: '*' },
          condition: 'selection',
        },
        { id: 'broad-rule-id', title: 'Very Broad Rule' },
      );

      const specificRule = makeRule(
        {
          selection: {
            Image: '*\\cmd.exe',
            CommandLine: '*-encodedcommand*',
            User: 'nobody_matches_this_user_12345',
          },
          condition: 'selection',
        },
        { id: 'specific-rule-id', title: 'Very Specific Rule' },
      );

      const result = evaluateFalsePositiveRates(
        [broadRule, specificRule],
        { benignLogsPerRule: 10 },
      );

      // The broad rule should appear in highestFPRules
      const broadFP = result.highestFPRules.find(
        (r) => r.ruleId === 'broad-rule-id',
      );
      expect(broadFP).toBeDefined();
      expect(broadFP!.fpRate).toBeGreaterThan(0);
    });

    it('provides explanations for high-FP rules', () => {
      const broadRule = makeRule(
        {
          selection: { Image: '*' },
          condition: 'selection',
        },
        { id: 'broad-rule-id', title: 'Very Broad Rule' },
      );

      const result = evaluateFalsePositiveRates([broadRule], {
        benignLogsPerRule: 10,
      });

      expect(result.highestFPRules.length).toBeGreaterThan(0);
      expect(result.highestFPRules[0].explanation).toBeTruthy();
      expect(typeof result.highestFPRules[0].explanation).toBe('string');
      expect(result.highestFPRules[0].explanation.length).toBeGreaterThan(0);
    });

    it('sorts highest-FP rules by fpRate descending', () => {
      const rules = [
        makeRule(
          {
            selection: { Image: '*' },
            condition: 'selection',
          },
          { id: 'rule-a', title: 'Broad Rule A' },
        ),
        makeRule(
          {
            selection: {
              Image: '*\\cmd.exe',
              CommandLine: '*whoami*',
              User: 'nobody_matches_this_user_67890',
            },
            condition: 'selection',
          },
          { id: 'rule-b', title: 'Specific Rule B' },
        ),
      ];

      const result = evaluateFalsePositiveRates(rules, {
        benignLogsPerRule: 10,
      });

      if (result.highestFPRules.length > 1) {
        for (let i = 1; i < result.highestFPRules.length; i++) {
          expect(result.highestFPRules[i - 1].fpRate).toBeGreaterThanOrEqual(
            result.highestFPRules[i].fpRate,
          );
        }
      }
    });
  });

  // =========================================================================
  // Aggregate FP Rate
  // =========================================================================

  describe('aggregate FP rate', () => {
    it('computes aggregate across multiple rules', () => {
      const rules = [
        makeRule(
          {
            selection: { Image: '*' },
            condition: 'selection',
          },
          { id: 'agg-rule-1', title: 'Broad Rule' },
        ),
        makeRule(
          {
            selection: {
              Image: '*\\cmd.exe',
              CommandLine: '*-encodedcommand*',
              User: 'nobody_matches_this_67890',
            },
            condition: 'selection',
          },
          { id: 'agg-rule-2', title: 'Specific Rule' },
        ),
      ];

      const result = evaluateFalsePositiveRates(rules, {
        benignLogsPerRule: 10,
      });

      // Aggregate should be between the two individual rates
      expect(result.aggregateFPRate).toBeGreaterThan(0);
      expect(result.aggregateFPRate).toBeLessThanOrEqual(1);
    });
  });

  // =========================================================================
  // Edge Cases
  // =========================================================================

  describe('edge cases', () => {
    it('handles empty rules array', () => {
      const result = evaluateFalsePositiveRates([]);

      expect(result.totalRulesEvaluated).toBe(0);
      expect(result.aggregateFPRate).toBe(0);
      expect(result.perRuleResults).toHaveLength(0);
      expect(result.highestFPRules).toHaveLength(0);
      expect(result.passesThreshold).toBe(true);
    });

    it('handles rule with empty detection selections', () => {
      const rule = makeRule({
        condition: 'selection',
      });

      const result = evaluateFalsePositiveRates([rule], {
        benignLogsPerRule: 5,
      });

      expect(result.totalRulesEvaluated).toBe(1);
      expect(result.perRuleResults).toHaveLength(1);
    });

    it('respects benignLogsPerRule option', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      const result5 = evaluateFalsePositiveRates([rule], {
        benignLogsPerRule: 5,
      });
      const result15 = evaluateFalsePositiveRates([rule], {
        benignLogsPerRule: 15,
      });

      const total5 =
        result5.perRuleResults[0].falsePositives +
        result5.perRuleResults[0].trueNegatives;
      const total15 =
        result15.perRuleResults[0].falsePositives +
        result15.perRuleResults[0].trueNegatives;

      expect(total5).toBe(5);
      expect(total15).toBe(15);
    });
  });

  // =========================================================================
  // Per-Rule Result Fields
  // =========================================================================

  describe('per-rule result fields', () => {
    it('sets truePositives and falseNegatives to 0 (benign-only evaluation)', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      const result = evaluateFalsePositiveRates([rule], {
        benignLogsPerRule: 10,
      });

      expect(result.perRuleResults[0].truePositives).toBe(0);
      expect(result.perRuleResults[0].falseNegatives).toBe(0);
      expect(result.perRuleResults[0].tpRate).toBe(0);
    });

    it('sets correct falsePositives and trueNegatives counts', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      const result = evaluateFalsePositiveRates([rule], {
        benignLogsPerRule: 10,
      });

      const fp = result.perRuleResults[0].falsePositives;
      const tn = result.perRuleResults[0].trueNegatives;
      expect(fp + tn).toBe(10);
    });
  });

  // =========================================================================
  // FP Explanation Content
  // =========================================================================

  describe('FP explanation content', () => {
    it('mentions no filter when rule has no NOT condition', () => {
      const rule = makeRule(
        {
          selection: { Image: '*' },
          condition: 'selection',
        },
        { id: 'no-filter-rule', title: 'No Filter Rule' },
      );

      const result = evaluateFalsePositiveRates([rule], {
        benignLogsPerRule: 5,
      });

      const fpRule = result.highestFPRules.find(
        (r) => r.ruleId === 'no-filter-rule',
      );
      expect(fpRule).toBeDefined();
      expect(fpRule!.explanation).toContain('filter');
    });

    it('mentions single selection when rule has only one', () => {
      const rule = makeRule(
        {
          selection: { Image: '*' },
          condition: 'selection',
        },
        { id: 'single-sel-rule', title: 'Single Selection Rule' },
      );

      const result = evaluateFalsePositiveRates([rule], {
        benignLogsPerRule: 5,
      });

      const fpRule = result.highestFPRules.find(
        (r) => r.ruleId === 'single-sel-rule',
      );
      expect(fpRule).toBeDefined();
      expect(fpRule!.explanation).toContain('single selection');
    });

    it('mentions documented false positives when present', () => {
      const rule = makeRule(
        {
          selection: { Image: '*' },
          condition: 'selection',
        },
        {
          id: 'doc-fp-rule',
          title: 'Documented FP Rule',
          falsepositives: ['Legitimate admin scripts'],
        },
      );

      const result = evaluateFalsePositiveRates([rule], {
        benignLogsPerRule: 5,
      });

      const fpRule = result.highestFPRules.find(
        (r) => r.ruleId === 'doc-fp-rule',
      );
      expect(fpRule).toBeDefined();
      expect(fpRule!.explanation).toContain('Legitimate admin scripts');
    });
  });
});
