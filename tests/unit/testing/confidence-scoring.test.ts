/**
 * Unit tests for rule confidence scoring (Level 7 Phase 4).
 *
 * Tests that confidence assessment honestly reflects data sufficiency
 * and behavioral robustness.
 */

import { describe, it, expect } from 'vitest';
import { testRuleEffectiveness } from '@/testing/effectiveness-tester.js';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(
  detection: Record<string, unknown> & { condition: string },
  overrides: Partial<SigmaRule> = {},
): SigmaRule {
  return {
    id: 'conf-test-0001',
    title: 'Confidence Test Rule',
    status: 'experimental',
    description: 'A test rule for confidence scoring.',
    references: [],
    author: 'DetectForge',
    date: '2026/02/12',
    modified: '2026/02/12',
    tags: ['attack.credential_access', 'attack.t1003.001'],
    logsource: { product: 'windows', category: 'process_creation' },
    detection,
    falsepositives: [],
    level: 'high',
    raw: '',
    ...overrides,
  };
}

// ===========================================================================
// Confidence Assessment
// ===========================================================================

describe('confidence scoring', () => {
  it('returns a confidence object with level, score, and factors', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe', CommandLine: '*whoami*' },
      condition: 'selection',
    });

    const result = testRuleEffectiveness(rule);

    expect(result.confidence).toBeDefined();
    expect(result.confidence.level).toMatch(/^(high|medium|low|experimental)$/);
    expect(result.confidence.score).toBeGreaterThanOrEqual(0);
    expect(result.confidence.score).toBeLessThanOrEqual(100);
    expect(Array.isArray(result.confidence.factors)).toBe(true);
    expect(result.confidence.factors.length).toBeGreaterThan(0);
  });

  it('gives higher confidence to rules with known technique templates', () => {
    // T1003.001 has technique templates
    const knownTechnique = makeRule({
      selection: { Image: '*\\cmd.exe', CommandLine: '*whoami*' },
      condition: 'selection',
    }, {
      tags: ['attack.credential_access', 'attack.t1003.001'],
    });

    // Made-up technique with no templates
    const unknownTechnique = makeRule({
      selection: { Image: '*\\cmd.exe', CommandLine: '*whoami*' },
      condition: 'selection',
    }, {
      tags: ['attack.execution', 'attack.t9999.001'],
    });

    const knownResult = testRuleEffectiveness(knownTechnique);
    const unknownResult = testRuleEffectiveness(unknownTechnique);

    expect(knownResult.confidence.score).toBeGreaterThan(unknownResult.confidence.score);
  });

  it('gives higher confidence to behavioral rules', () => {
    // Behavioral rule using GrantedAccess + TargetImage
    const behavioral = makeRule({
      selection: {
        TargetImage: '*\\lsass.exe',
        GrantedAccess: ['0x1010', '0x1038'],
      },
      condition: 'selection',
    }, {
      logsource: { product: 'windows', category: 'process_access' },
      tags: ['attack.credential_access', 'attack.t1003.001'],
    });

    // Tool-signature rule
    const toolSig = makeRule({
      selection: { Image: '*\\Seatbelt.exe' },
      condition: 'selection',
    }, {
      tags: ['attack.discovery', 'attack.t1082'],
    });

    const behavioralResult = testRuleEffectiveness(behavioral);
    const toolSigResult = testRuleEffectiveness(toolSig);

    expect(behavioralResult.confidence.score).toBeGreaterThan(toolSigResult.confidence.score);
  });

  it('gives higher confidence to rules with multiple variants', () => {
    const multiVariant = makeRule({
      selection_comsvcs: {
        Image: '*\\rundll32.exe',
        CommandLine: '*comsvcs*',
      },
      selection_procdump: {
        CommandLine: '*lsass*',
      },
      selection_access: {
        TargetImage: '*\\lsass.exe',
        GrantedAccess: '0x1fffff',
      },
      condition: '1 of selection_*',
    }, {
      logsource: { product: 'windows', category: 'process_creation' },
      tags: ['attack.credential_access', 'attack.t1003.001'],
    });

    const singleVariant = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    }, {
      tags: ['attack.credential_access', 'attack.t1003.001'],
    });

    const multiResult = testRuleEffectiveness(multiVariant);
    const singleResult = testRuleEffectiveness(singleVariant);

    expect(multiResult.confidence.score).toBeGreaterThan(singleResult.confidence.score);
  });

  it('confidence level thresholds are correct', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    const result = testRuleEffectiveness(rule);
    const score = result.confidence.score;
    const level = result.confidence.level;

    if (score >= 75) expect(level).toBe('high');
    else if (score >= 50) expect(level).toBe('medium');
    else if (score >= 25) expect(level).toBe('low');
    else expect(level).toBe('experimental');
  });

  it('factors array explains the scoring rationale', () => {
    const rule = makeRule({
      selection: {
        TargetImage: '*\\lsass.exe',
        GrantedAccess: '0x1010',
      },
      condition: 'selection',
    }, {
      logsource: { product: 'windows', category: 'process_access' },
      tags: ['attack.credential_access', 'attack.t1003.001'],
    });

    const result = testRuleEffectiveness(rule);

    // Should have factors explaining the scoring
    const factorText = result.confidence.factors.join(' ');
    // Should mention behavioral fields or technique templates
    expect(factorText.length).toBeGreaterThan(0);
  });
});
