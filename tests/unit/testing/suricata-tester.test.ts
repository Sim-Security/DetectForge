/**
 * Unit tests for the Suricata rule tester module.
 */

import { describe, it, expect } from 'vitest';
import {
  evaluateSuricataRule,
  evaluateSuricataRuleSuite,
} from '@/testing/suricata-tester.js';
import type { SuricataRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers — test fixture factories
// ---------------------------------------------------------------------------

function makeValidSuricataRule(overrides: Partial<SuricataRule> = {}): SuricataRule {
  return {
    action: 'alert',
    protocol: 'http',
    sourceIp: '$HOME_NET',
    sourcePort: 'any',
    direction: '->',
    destIp: '$EXTERNAL_NET',
    destPort: '$HTTP_PORTS',
    options: [
      { keyword: 'msg', value: '"ET MALWARE Possible C2 Beacon"' },
      { keyword: 'flow', value: 'established,to_server' },
      { keyword: 'content', value: '"/api/beacon"' },
      { keyword: 'content', value: '"User-Agent: Mozilla/5.0"' },
      { keyword: 'content', value: '"|de ad be ef|"' },
      { keyword: 'classtype', value: 'trojan-activity' },
      { keyword: 'reference', value: 'url,example.com/report' },
      { keyword: 'sid', value: '1000001' },
      { keyword: 'rev', value: '1' },
    ],
    sid: 1000001,
    rev: 1,
    raw: 'alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET MALWARE Possible C2 Beacon"; flow:established,to_server; content:"/api/beacon"; content:"User-Agent: Mozilla/5.0"; content:"|de ad be ef|"; classtype:trojan-activity; reference:url,example.com/report; sid:1000001; rev:1;)',
    ...overrides,
  };
}

function makeMinimalSuricataRule(overrides: Partial<SuricataRule> = {}): SuricataRule {
  return {
    action: 'alert',
    protocol: 'tcp',
    sourceIp: 'any',
    sourcePort: 'any',
    direction: '->',
    destIp: 'any',
    destPort: 'any',
    options: [
      { keyword: 'msg', value: '"Minimal Rule"' },
      { keyword: 'sid', value: '2000001' },
      { keyword: 'rev', value: '1' },
    ],
    sid: 2000001,
    rev: 1,
    raw: 'alert tcp any any -> any any (msg:"Minimal Rule"; sid:2000001; rev:1;)',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// evaluateSuricataRule
// ---------------------------------------------------------------------------

describe('evaluateSuricataRule', () => {
  it('returns syntaxValid true for a well-formed rule', () => {
    const result = evaluateSuricataRule(makeValidSuricataRule());
    expect(result.syntaxValid).toBe(true);
    expect(result.structureValid).toBe(true);
    expect(result.sid).toBe(1000001);
  });

  it('extracts the msg value correctly', () => {
    const result = evaluateSuricataRule(makeValidSuricataRule());
    expect(result.msg).toBe('ET MALWARE Possible C2 Beacon');
  });

  it('returns syntaxValid false for an invalid action', () => {
    const rule = makeValidSuricataRule({ action: 'invalid' as never });
    const result = evaluateSuricataRule(rule);
    expect(result.syntaxValid).toBe(false);
    expect(result.issues.some(i => i.includes('action'))).toBe(true);
  });

  it('counts content matches correctly', () => {
    const result = evaluateSuricataRule(makeValidSuricataRule());
    expect(result.contentMatchCount).toBe(3);
    expect(result.hasContentMatch).toBe(true);
  });

  it('returns hasContentMatch false when no content keywords exist', () => {
    const result = evaluateSuricataRule(makeMinimalSuricataRule());
    expect(result.hasContentMatch).toBe(false);
    expect(result.contentMatchCount).toBe(0);
  });

  it('detects flow constraint when present', () => {
    const result = evaluateSuricataRule(makeValidSuricataRule());
    expect(result.hasFlowConstraint).toBe(true);
  });

  it('returns hasFlowConstraint false when no flow keyword', () => {
    const result = evaluateSuricataRule(makeMinimalSuricataRule());
    expect(result.hasFlowConstraint).toBe(false);
  });

  it('estimates high specificity for 3+ content matches + flow', () => {
    const result = evaluateSuricataRule(makeValidSuricataRule());
    expect(result.estimatedSpecificity).toBe('high');
  });

  it('estimates medium specificity for 2 content matches', () => {
    const rule = makeValidSuricataRule({
      options: [
        { keyword: 'msg', value: '"Test"' },
        { keyword: 'content', value: '"/test1"' },
        { keyword: 'content', value: '"/test2"' },
        { keyword: 'sid', value: '1000002' },
        { keyword: 'rev', value: '1' },
      ],
    });
    const result = evaluateSuricataRule(rule);
    expect(result.estimatedSpecificity).toBe('medium');
  });

  it('estimates low specificity for no content matches', () => {
    const result = evaluateSuricataRule(makeMinimalSuricataRule());
    expect(result.estimatedSpecificity).toBe('low');
  });

  it('flags rules with no content-matching keywords', () => {
    const result = evaluateSuricataRule(makeMinimalSuricataRule());
    expect(result.issues.some(i => i.includes('no content-matching'))).toBe(true);
  });

  it('warns about missing flow constraint', () => {
    const rule = makeMinimalSuricataRule({
      options: [
        { keyword: 'msg', value: '"Test"' },
        { keyword: 'content', value: '"/test"' },
        { keyword: 'sid', value: '2000002' },
        { keyword: 'rev', value: '1' },
      ],
    });
    const result = evaluateSuricataRule(rule);
    expect(result.warnings.some(w => w.includes('flow constraint'))).toBe(true);
  });

  it('warns about missing classtype', () => {
    const result = evaluateSuricataRule(makeMinimalSuricataRule());
    expect(result.warnings.some(w => w.includes('classtype'))).toBe(true);
  });

  it('warns about missing reference', () => {
    const result = evaluateSuricataRule(makeMinimalSuricataRule());
    expect(result.warnings.some(w => w.includes('reference'))).toBe(true);
  });

  it('warns about both ports "any" without flow', () => {
    const result = evaluateSuricataRule(makeMinimalSuricataRule());
    expect(
      result.warnings.some(w => w.includes('source and destination ports are "any"')),
    ).toBe(true);
  });

  it('warns about short content matches', () => {
    const rule = makeValidSuricataRule({
      options: [
        { keyword: 'msg', value: '"Short Content"' },
        { keyword: 'flow', value: 'established,to_server' },
        { keyword: 'content', value: '"ab"' },
        { keyword: 'classtype', value: 'trojan-activity' },
        { keyword: 'reference', value: 'url,example.com' },
        { keyword: 'sid', value: '1000003' },
        { keyword: 'rev', value: '1' },
      ],
    });
    const result = evaluateSuricataRule(rule);
    expect(result.warnings.some(w => w.includes('short') || w.includes('Content match'))).toBe(true);
  });

  it('counts pcre as a content-matching keyword', () => {
    const rule = makeMinimalSuricataRule({
      options: [
        { keyword: 'msg', value: '"PCRE Rule"' },
        { keyword: 'pcre', value: '"/malware/i"' },
        { keyword: 'sid', value: '2000003' },
        { keyword: 'rev', value: '1' },
      ],
    });
    const result = evaluateSuricataRule(rule);
    expect(result.contentMatchCount).toBe(1);
    expect(result.hasContentMatch).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// evaluateSuricataRuleSuite
// ---------------------------------------------------------------------------

describe('evaluateSuricataRuleSuite', () => {
  it('returns correct totalRules count', () => {
    const rules = [makeValidSuricataRule(), makeMinimalSuricataRule()];
    const result = evaluateSuricataRuleSuite(rules);
    expect(result.totalRules).toBe(2);
  });

  it('calculates syntaxPassRate correctly', () => {
    const valid = makeValidSuricataRule();
    const invalid = makeValidSuricataRule({
      action: 'invalid_action' as never,
      sid: 3000001,
    });
    const result = evaluateSuricataRuleSuite([valid, invalid]);
    expect(result.syntaxPassRate).toBe(0.5);
  });

  it('returns 1.0 syntaxPassRate when all rules are valid', () => {
    const rules = [
      makeValidSuricataRule(),
      makeValidSuricataRule({ sid: 1000002 }),
    ];
    // Fix the sid option in the second rule to match
    rules[1].options = rules[1].options.map(o =>
      o.keyword === 'sid' ? { keyword: 'sid', value: '1000002' } : o,
    );
    const result = evaluateSuricataRuleSuite(rules);
    expect(result.syntaxPassRate).toBe(1);
  });

  it('returns 0 rates for empty suite', () => {
    const result = evaluateSuricataRuleSuite([]);
    expect(result.totalRules).toBe(0);
    expect(result.syntaxPassRate).toBe(0);
    expect(result.duplicateSIDs).toEqual([]);
  });

  it('detects duplicate SIDs', () => {
    const rule1 = makeValidSuricataRule({ sid: 1000001 });
    const rule2 = makeValidSuricataRule({ sid: 1000001 });
    const result = evaluateSuricataRuleSuite([rule1, rule2]);
    expect(result.duplicateSIDs).toContain(1000001);
  });

  it('returns empty duplicateSIDs when all SIDs are unique', () => {
    const rule1 = makeValidSuricataRule({ sid: 1000001 });
    const rule2 = makeValidSuricataRule({ sid: 1000002 });
    rule2.options = rule2.options.map(o =>
      o.keyword === 'sid' ? { keyword: 'sid', value: '1000002' } : o,
    );
    const result = evaluateSuricataRuleSuite([rule1, rule2]);
    expect(result.duplicateSIDs).toEqual([]);
  });

  it('computes averageSpecificity from the modal value', () => {
    const highRule = makeValidSuricataRule();
    const lowRule1 = makeMinimalSuricataRule();
    const lowRule2 = makeMinimalSuricataRule({ sid: 2000002 });
    lowRule2.options = lowRule2.options.map(o =>
      o.keyword === 'sid' ? { keyword: 'sid', value: '2000002' } : o,
    );
    const result = evaluateSuricataRuleSuite([highRule, lowRule1, lowRule2]);
    expect(result.averageSpecificity).toBe('low');
  });

  it('includes perRuleResults for each rule', () => {
    const rules = [makeValidSuricataRule(), makeMinimalSuricataRule()];
    const result = evaluateSuricataRuleSuite(rules);
    expect(result.perRuleResults).toHaveLength(2);
    expect(result.perRuleResults[0].sid).toBe(1000001);
    expect(result.perRuleResults[1].sid).toBe(2000001);
  });
});
