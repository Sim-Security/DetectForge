/**
 * Unit tests for the quality gate.
 */

import { describe, it, expect } from 'vitest';
import {
  runQualityGate,
  runQualityGateBatch,
  getProfileThresholds,
} from '@/testing/quality-gate.js';
import type { QualityProfile } from '@/testing/quality-gate.js';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(
  detection: Record<string, unknown> & { condition: string },
  overrides: Partial<SigmaRule> = {},
): SigmaRule {
  return {
    id: 'qg-test-0001-0000-000000000001',
    title: 'Quality Gate Test Rule',
    status: 'experimental',
    description: 'A test rule for quality gate testing with enough detail.',
    references: ['https://example.com/report'],
    author: 'DetectForge',
    date: '2026/02/10',
    modified: '2026/02/10',
    tags: ['attack.execution', 'attack.t1059.001'],
    logsource: { product: 'windows', category: 'process_creation' },
    detection,
    falsepositives: ['Legitimate admin scripts', 'Software installers'],
    level: 'high',
    raw: '',
    ...overrides,
  };
}

// ===========================================================================
// getProfileThresholds
// ===========================================================================

describe('getProfileThresholds', () => {
  it('returns thresholds for dev profile', () => {
    const t = getProfileThresholds('dev');
    expect(t.minQualityScore).toBe(3.0);
    expect(t.minTpRate).toBe(0.5);
    expect(t.maxFpRate).toBe(0.3);
    expect(t.requiresFilters).toBe(false);
  });

  it('returns thresholds for standard profile', () => {
    const t = getProfileThresholds('standard');
    expect(t.minQualityScore).toBe(5.0);
    expect(t.minTpRate).toBe(0.8);
    expect(t.maxFpRate).toBe(0.1);
    expect(t.minFalsePositiveEntries).toBe(1);
  });

  it('returns thresholds for production profile', () => {
    const t = getProfileThresholds('production');
    expect(t.minQualityScore).toBe(7.0);
    expect(t.minTpRate).toBe(0.9);
    expect(t.maxFpRate).toBe(0.05);
    expect(t.requiresFilters).toBe(true);
    expect(t.minFalsePositiveEntries).toBe(2);
  });

  it('returns independent copies (not references)', () => {
    const t1 = getProfileThresholds('dev');
    const t2 = getProfileThresholds('dev');
    t1.minQualityScore = 999;
    expect(t2.minQualityScore).toBe(3.0);
  });
});

// ===========================================================================
// runQualityGate
// ===========================================================================

describe('runQualityGate', () => {
  it('returns expected structure', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    const result = runQualityGate(rule, 'dev');

    expect(result.ruleId).toBe(rule.id);
    expect(result.ruleTitle).toBe(rule.title);
    expect(result.profile).toBe('dev');
    expect(typeof result.pass).toBe('boolean');
    expect(Array.isArray(result.checks)).toBe(true);
    expect(result.qualityScore).toBeDefined();
    expect(result.effectiveness).toBeDefined();
    expect(result.fieldValidation).toBeDefined();
    expect(result.validation).toBeDefined();
  });

  it('includes quality score, TP rate, FP rate, and FP entries checks', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    const result = runQualityGate(rule, 'standard');
    const checkNames = result.checks.map((c) => c.name);

    expect(checkNames).toContain('Quality Score');
    expect(checkNames).toContain('TP Rate');
    expect(checkNames).toContain('FP Rate');
    expect(checkNames).toContain('FP Entries');
  });

  it('includes filter check only for production profile', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    const devResult = runQualityGate(rule, 'dev');
    const prodResult = runQualityGate(rule, 'production');

    const devCheckNames = devResult.checks.map((c) => c.name);
    const prodCheckNames = prodResult.checks.map((c) => c.name);

    expect(devCheckNames).not.toContain('Has Filters');
    expect(prodCheckNames).toContain('Has Filters');
  });

  it('passes a well-crafted rule under dev profile', () => {
    const rule = makeRule({
      selection: {
        Image: ['*\\cmd.exe', '*\\powershell.exe'],
        CommandLine: '*whoami*',
      },
      filter_system: { User: 'SYSTEM' },
      condition: 'selection and not filter_system',
    });

    const result = runQualityGate(rule, 'dev');
    expect(result.pass).toBe(true);
  });

  it('detects missing filter blocks for production profile', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    const result = runQualityGate(rule, 'production');
    const filterCheck = result.checks.find((c) => c.name === 'Has Filters');

    expect(filterCheck).toBeDefined();
    expect(filterCheck!.pass).toBe(false);
  });

  it('checks false positive entry count', () => {
    const ruleNoFPs = makeRule(
      {
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      },
      { falsepositives: [] },
    );

    const result = runQualityGate(ruleNoFPs, 'standard');
    const fpCheck = result.checks.find((c) => c.name === 'FP Entries');

    expect(fpCheck).toBeDefined();
    expect(fpCheck!.pass).toBe(false);
    expect(fpCheck!.actual).toBe('0');
  });

  it('all three profiles produce valid results', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    const profiles: QualityProfile[] = ['dev', 'standard', 'production'];

    for (const profile of profiles) {
      const result = runQualityGate(rule, profile);
      expect(result.profile).toBe(profile);
      expect(result.checks.length).toBeGreaterThan(0);
    }
  });
});

// ===========================================================================
// runQualityGateBatch
// ===========================================================================

describe('runQualityGateBatch', () => {
  it('processes multiple rules', () => {
    const rules = [
      makeRule(
        {
          selection: { Image: '*\\cmd.exe' },
          condition: 'selection',
        },
        { id: 'batch-001a-0000-0000-000000000001', title: 'Rule 1' },
      ),
      makeRule(
        {
          selection: {
            Image: '*\\powershell.exe',
            CommandLine: '*Invoke-*',
          },
          filter_system: { User: 'SYSTEM' },
          condition: 'selection and not filter_system',
        },
        { id: 'batch-002a-0000-0000-000000000002', title: 'Rule 2' },
      ),
    ];

    const summary = runQualityGateBatch(rules, 'dev');

    expect(summary.totalRules).toBe(2);
    expect(summary.passedRules + summary.failedRules).toBe(2);
    expect(summary.results).toHaveLength(2);
    expect(summary.profile).toBe('dev');
  });

  it('handles empty rule set', () => {
    const summary = runQualityGateBatch([], 'standard');

    expect(summary.totalRules).toBe(0);
    expect(summary.passedRules).toBe(0);
    expect(summary.failedRules).toBe(0);
  });
});
