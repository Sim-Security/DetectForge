/**
 * Unit tests for the YARA rule tester module.
 */

import { describe, it, expect } from 'vitest';
import { evaluateYaraRule, evaluateYaraRuleSuite } from '@/testing/yara-tester.js';
import type { YaraRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers — test fixture factories
// ---------------------------------------------------------------------------

function makeValidYaraRule(overrides: Partial<YaraRule> = {}): YaraRule {
  return {
    name: 'APT_Backdoor_Loader',
    tags: ['apt', 'backdoor'],
    meta: {
      description: 'Detects APT backdoor loader',
      author: 'DetectForge',
      date: '2025-01-15',
      reference: 'https://example.com/report',
      mitre_attack: 'T1059.001',
    },
    strings: [
      { identifier: '$s1', value: 'LoadLibraryA', type: 'text', modifiers: ['ascii'] },
      { identifier: '$s2', value: 'VirtualAlloc', type: 'text', modifiers: ['ascii'] },
      { identifier: '$hex1', value: '4D 5A 90 00 03 00 00 00', type: 'hex', modifiers: [] },
    ],
    condition: 'uint16(0) == 0x5A4D and ($s1 and $s2) and $hex1',
    raw: 'rule APT_Backdoor_Loader { meta: description = "Detects APT backdoor loader" author = "DetectForge" date = "2025-01-15" strings: $s1 = "LoadLibraryA" ascii $s2 = "VirtualAlloc" ascii $hex1 = { 4D 5A 90 00 03 00 00 00 } condition: uint16(0) == 0x5A4D and ($s1 and $s2) and $hex1 }',
    ...overrides,
  };
}

function makeMinimalYaraRule(overrides: Partial<YaraRule> = {}): YaraRule {
  return {
    name: 'Simple_Rule',
    tags: [],
    meta: {
      description: 'Simple rule',
      author: 'Test',
      date: '2025-01-01',
      reference: '',
      mitre_attack: '',
    },
    strings: [
      { identifier: '$a', value: 'malware', type: 'text', modifiers: [] },
    ],
    condition: '$a',
    raw: 'rule Simple_Rule { meta: description = "Simple rule" author = "Test" date = "2025-01-01" strings: $a = "malware" condition: $a }',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// evaluateYaraRule
// ---------------------------------------------------------------------------

describe('evaluateYaraRule', () => {
  it('returns syntaxValid true for a well-formed rule', () => {
    const result = evaluateYaraRule(makeValidYaraRule());
    expect(result.syntaxValid).toBe(true);
    expect(result.structureValid).toBe(true);
    expect(result.ruleName).toBe('APT_Backdoor_Loader');
  });

  it('returns syntaxValid false when the rule name is invalid', () => {
    const rule = makeValidYaraRule({ name: '123_bad_name' });
    const result = evaluateYaraRule(rule);
    expect(result.syntaxValid).toBe(false);
    expect(result.issues.length).toBeGreaterThan(0);
  });

  it('returns syntaxValid false when required meta fields are missing', () => {
    const rule = makeValidYaraRule();
    rule.meta.description = '';
    const result = evaluateYaraRule(rule);
    expect(result.syntaxValid).toBe(false);
    expect(result.issues.some(i => i.includes('description'))).toBe(true);
  });

  it('calculates 100% string coverage when all strings are in condition', () => {
    const result = evaluateYaraRule(makeValidYaraRule());
    expect(result.stringCoverage).toBe(100);
  });

  it('calculates partial string coverage for unreferenced strings', () => {
    const rule = makeValidYaraRule({
      strings: [
        { identifier: '$s1', value: 'LoadLibraryA', type: 'text', modifiers: [] },
        { identifier: '$s2', value: 'VirtualAlloc', type: 'text', modifiers: [] },
        { identifier: '$unused', value: 'NeverReferenced', type: 'text', modifiers: [] },
      ],
      condition: '$s1 and $s2',
    });
    const result = evaluateYaraRule(rule);
    // 2 out of 3 strings referenced
    expect(result.stringCoverage).toBeCloseTo(66.67, 0);
  });

  it('returns 100% string coverage when condition uses "any of them"', () => {
    const rule = makeValidYaraRule({ condition: 'any of them' });
    const result = evaluateYaraRule(rule);
    expect(result.stringCoverage).toBe(100);
  });

  it('counts logical operators for condition complexity', () => {
    const rule = makeValidYaraRule({
      condition: '$s1 and $s2 or not $hex1',
    });
    const result = evaluateYaraRule(rule);
    expect(result.conditionComplexity).toBe(3); // and, or, not
  });

  it('returns conditionComplexity 0 for a trivial condition', () => {
    const rule = makeMinimalYaraRule({ condition: '$a' });
    const result = evaluateYaraRule(rule);
    expect(result.conditionComplexity).toBe(0);
  });

  it('detects file type constraints (uint16/magic bytes)', () => {
    const result = evaluateYaraRule(makeValidYaraRule());
    expect(result.hasFileTypeConstraint).toBe(true);
  });

  it('returns false for hasFileTypeConstraint when absent', () => {
    const rule = makeValidYaraRule({
      condition: '$s1 and $s2 and $hex1',
      raw: 'rule Test { strings: $s1 = "A" condition: $s1 }',
      strings: [
        { identifier: '$s1', value: 'A', type: 'text', modifiers: [] },
        { identifier: '$s2', value: 'B', type: 'text', modifiers: [] },
        { identifier: '$hex1', value: 'AA BB CC', type: 'hex', modifiers: [] },
      ],
    });
    const result = evaluateYaraRule(rule);
    expect(result.hasFileTypeConstraint).toBe(false);
  });

  it('estimates high specificity for file-type constrained + 3+ strings', () => {
    const result = evaluateYaraRule(makeValidYaraRule());
    expect(result.estimatedSpecificity).toBe('high');
  });

  it('estimates medium specificity for 2+ strings without file-type constraint', () => {
    const rule = makeValidYaraRule({
      condition: '$s1 and $s2',
      raw: '',
      strings: [
        { identifier: '$s1', value: 'LoadLibraryA', type: 'text', modifiers: [] },
        { identifier: '$s2', value: 'VirtualAlloc', type: 'text', modifiers: [] },
      ],
    });
    const result = evaluateYaraRule(rule);
    expect(result.estimatedSpecificity).toBe('medium');
  });

  it('estimates low specificity for single-string rules', () => {
    const result = evaluateYaraRule(makeMinimalYaraRule());
    expect(result.estimatedSpecificity).toBe('low');
  });

  it('warns about single-string conditions', () => {
    const result = evaluateYaraRule(makeMinimalYaraRule());
    expect(result.warnings.some(w => w.includes('only one string'))).toBe(true);
  });

  it('warns about very short hex strings', () => {
    const rule = makeMinimalYaraRule({
      strings: [
        { identifier: '$h1', value: 'AA BB', type: 'hex', modifiers: [] },
      ],
      condition: '$h1',
    });
    const result = evaluateYaraRule(rule);
    expect(result.warnings.some(w => w.includes('short') || w.includes('byte'))).toBe(true);
  });

  it('warns about very short text strings', () => {
    const rule = makeMinimalYaraRule({
      strings: [
        { identifier: '$t1', value: 'ab', type: 'text', modifiers: [] },
      ],
      condition: '$t1',
    });
    const result = evaluateYaraRule(rule);
    expect(result.warnings.some(w => w.includes('short') || w.includes('chars'))).toBe(true);
  });

  it('flags overly broad "any of them" as an issue', () => {
    const rule = makeMinimalYaraRule({ condition: 'any of them' });
    const result = evaluateYaraRule(rule);
    expect(result.issues.some(i => i.includes('any of them'))).toBe(true);
  });

  it('warns about broad wildcard sequences in hex strings', () => {
    const rule = makeMinimalYaraRule({
      strings: [
        { identifier: '$h1', value: 'AA ?? ?? ?? ?? ?? ?? BB CC DD EE FF', type: 'hex', modifiers: [] },
      ],
      condition: '$h1',
    });
    const result = evaluateYaraRule(rule);
    expect(result.warnings.some(w => w.includes('broad wildcard'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// evaluateYaraRuleSuite
// ---------------------------------------------------------------------------

describe('evaluateYaraRuleSuite', () => {
  it('returns correct totalRules count', () => {
    const rules = [makeValidYaraRule(), makeMinimalYaraRule()];
    const result = evaluateYaraRuleSuite(rules);
    expect(result.totalRules).toBe(2);
  });

  it('calculates syntaxPassRate correctly', () => {
    const validRule = makeValidYaraRule();
    const invalidRule = makeValidYaraRule({ name: '' });
    const result = evaluateYaraRuleSuite([validRule, invalidRule]);
    expect(result.syntaxPassRate).toBe(0.5);
  });

  it('returns 1.0 syntaxPassRate when all rules are valid', () => {
    const rules = [makeValidYaraRule(), makeValidYaraRule()];
    const result = evaluateYaraRuleSuite(rules);
    expect(result.syntaxPassRate).toBe(1);
  });

  it('returns 0 syntaxPassRate for empty suite', () => {
    const result = evaluateYaraRuleSuite([]);
    expect(result.totalRules).toBe(0);
    expect(result.syntaxPassRate).toBe(0);
  });

  it('computes averageSpecificity from the modal value', () => {
    const highRule = makeValidYaraRule(); // high specificity
    const lowRule1 = makeMinimalYaraRule();
    const lowRule2 = makeMinimalYaraRule();
    const result = evaluateYaraRuleSuite([highRule, lowRule1, lowRule2]);
    expect(result.averageSpecificity).toBe('low');
  });

  it('includes perRuleResults for each rule', () => {
    const rules = [makeValidYaraRule(), makeMinimalYaraRule()];
    const result = evaluateYaraRuleSuite(rules);
    expect(result.perRuleResults).toHaveLength(2);
    expect(result.perRuleResults[0].ruleName).toBe('APT_Backdoor_Loader');
    expect(result.perRuleResults[1].ruleName).toBe('Simple_Rule');
  });
});
