/**
 * Unit tests for Suricata rule validation: structured rules, raw text, and rule sets.
 *
 * Covers:
 * - validateSuricataRule: action, protocol, IP/port fields, direction, options,
 *   SID/rev ranges, warnings (SID mismatch, unquoted content)
 * - validateSuricataRaw: header parsing, parenthesized options block, msg/sid/rev
 *   presence, semicolons, quoted content/msg values
 * - validateSuricataRuleSet: individual validation propagation, duplicate SID detection
 */

import { describe, it, expect } from 'vitest';
import {
  validateSuricataRule,
  validateSuricataRaw,
  validateSuricataRuleSet,
} from '@/generation/suricata/validator.js';
import type { SuricataRule, SuricataOption } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers: factory for a valid SuricataRule
// ---------------------------------------------------------------------------

function makeValidRule(overrides: Partial<SuricataRule> = {}): SuricataRule {
  return {
    action: 'alert',
    protocol: 'tcp',
    sourceIp: '$HOME_NET',
    sourcePort: 'any',
    direction: '->',
    destIp: '$EXTERNAL_NET',
    destPort: 'any',
    options: [
      { keyword: 'msg', value: '"DetectForge - Test rule"' },
      { keyword: 'flow', value: 'established,to_server' },
      { keyword: 'content', value: '"evil"' },
      { keyword: 'sid', value: '9000001' },
      { keyword: 'rev', value: '1' },
    ],
    sid: 9000001,
    rev: 1,
    raw: '',
    ...overrides,
  };
}

function makeValidRaw(): string {
  return 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"DetectForge - Test"; content:"evil"; sid:9000001; rev:1;)';
}

// ===================================================================
// validateSuricataRule — happy path
// ===================================================================

describe('validateSuricataRule', () => {
  it('passes validation for a fully valid rule', () => {
    const result = validateSuricataRule(makeValidRule());
    expect(result.valid).toBe(true);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // ---- Action ----

  it('rejects an invalid action', () => {
    const rule = makeValidRule({ action: 'block' as any });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid action'))).toBe(true);
  });

  it.each(['alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'rejectboth'] as const)(
    'accepts valid action "%s"',
    (action) => {
      const rule = makeValidRule({ action });
      const result = validateSuricataRule(rule);
      expect(result.errors.filter(e => e.includes('action'))).toHaveLength(0);
    },
  );

  // ---- Protocol ----

  it('rejects an invalid protocol', () => {
    const rule = makeValidRule({ protocol: 'gopher' });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid protocol'))).toBe(true);
  });

  it.each([
    'tcp', 'udp', 'icmp', 'ip', 'http', 'dns', 'tls', 'ssh', 'ftp', 'smtp',
    'http2', 'pkthdr', 'nfs', 'smb', 'dcerpc', 'dhcp', 'krb5', 'snmp', 'sip',
    'rfb', 'mqtt', 'pgsql',
  ])('accepts valid protocol "%s"', (protocol) => {
    const rule = makeValidRule({ protocol });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('protocol'))).toHaveLength(0);
  });

  // ---- Source IP ----

  it('rejects an invalid source IP', () => {
    const rule = makeValidRule({ sourceIp: 'not-an-ip' });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid source IP'))).toBe(true);
  });

  it.each([
    '$HOME_NET',
    '$EXTERNAL_NET',
    '$DNS_SERVERS',
    'any',
  ])('accepts IP variable "%s"', (ip) => {
    const rule = makeValidRule({ sourceIp: ip });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('source IP'))).toHaveLength(0);
  });

  it('accepts a valid IPv4 address as source IP', () => {
    const rule = makeValidRule({ sourceIp: '192.168.1.100' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('source IP'))).toHaveLength(0);
  });

  it('accepts a valid IPv6 address as source IP', () => {
    const rule = makeValidRule({ sourceIp: '2001:db8::1' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('source IP'))).toHaveLength(0);
  });

  it('accepts CIDR notation as IP', () => {
    const rule = makeValidRule({ sourceIp: '10.0.0.0/8' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('source IP'))).toHaveLength(0);
  });

  it('accepts negated IP variable (!$HOME_NET)', () => {
    const rule = makeValidRule({ sourceIp: '!$HOME_NET' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('source IP'))).toHaveLength(0);
  });

  it('accepts IP group notation ([$HOME_NET,$DNS_SERVERS])', () => {
    const rule = makeValidRule({ sourceIp: '[$HOME_NET,$DNS_SERVERS]' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('source IP'))).toHaveLength(0);
  });

  it('accepts negated IPv4 address', () => {
    const rule = makeValidRule({ destIp: '!192.168.1.1' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('destination IP'))).toHaveLength(0);
  });

  // ---- Source Port ----

  it('rejects an invalid source port', () => {
    const rule = makeValidRule({ sourcePort: 'abc' });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid source port'))).toBe(true);
  });

  it.each([
    '$HTTP_PORTS',
    '$SSH_PORTS',
    'any',
  ])('accepts port variable "%s"', (port) => {
    const rule = makeValidRule({ sourcePort: port });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('source port'))).toHaveLength(0);
  });

  it('accepts a numeric port (80)', () => {
    const rule = makeValidRule({ destPort: '80' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('destination port'))).toHaveLength(0);
  });

  it('accepts port 0 and port 65535', () => {
    const rule0 = makeValidRule({ destPort: '0' });
    expect(validateSuricataRule(rule0).errors.filter(e => e.includes('port'))).toHaveLength(0);

    const rule65535 = makeValidRule({ destPort: '65535' });
    expect(validateSuricataRule(rule65535).errors.filter(e => e.includes('port'))).toHaveLength(0);
  });

  it('accepts port range (1024:65535)', () => {
    const rule = makeValidRule({ destPort: '1024:65535' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('destination port'))).toHaveLength(0);
  });

  it('accepts negated port (!80)', () => {
    const rule = makeValidRule({ destPort: '!80' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('destination port'))).toHaveLength(0);
  });

  it('accepts port group ([80,443])', () => {
    const rule = makeValidRule({ destPort: '[80,443]' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('destination port'))).toHaveLength(0);
  });

  it('rejects port number out of range (70000)', () => {
    const rule = makeValidRule({ destPort: '70000' });
    const result = validateSuricataRule(rule);
    expect(result.errors.some(e => e.includes('destination port'))).toBe(true);
  });

  // ---- Direction ----

  it('rejects an invalid direction', () => {
    const rule = makeValidRule({ direction: '<-' as any });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid direction'))).toBe(true);
  });

  it('accepts "->" direction', () => {
    const rule = makeValidRule({ direction: '->' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('direction'))).toHaveLength(0);
  });

  it('accepts "<>" direction', () => {
    const rule = makeValidRule({ direction: '<>' });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('direction'))).toHaveLength(0);
  });

  // ---- Options: msg ----

  it('produces an error when the msg option is missing', () => {
    const rule = makeValidRule({
      options: [
        { keyword: 'content', value: '"evil"' },
        { keyword: 'sid', value: '9000001' },
        { keyword: 'rev', value: '1' },
      ],
    });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('missing required "msg"'))).toBe(true);
  });

  // ---- SID ----

  it('rejects SID of 0', () => {
    const rule = makeValidRule({ sid: 0 });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('SID'))).toBe(true);
  });

  it('rejects negative SID', () => {
    const rule = makeValidRule({ sid: -5 });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('SID'))).toBe(true);
  });

  it('rejects SID exceeding 9999999', () => {
    const rule = makeValidRule({ sid: 10000000 });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('SID'))).toBe(true);
  });

  it('accepts SID at boundary values (1 and 9999999)', () => {
    const rule1 = makeValidRule({ sid: 1, options: [
      { keyword: 'msg', value: '"test"' },
      { keyword: 'sid', value: '1' },
      { keyword: 'rev', value: '1' },
    ] });
    expect(validateSuricataRule(rule1).errors.filter(e => e.includes('SID must'))).toHaveLength(0);

    const ruleMax = makeValidRule({ sid: 9999999, options: [
      { keyword: 'msg', value: '"test"' },
      { keyword: 'sid', value: '9999999' },
      { keyword: 'rev', value: '1' },
    ] });
    expect(validateSuricataRule(ruleMax).errors.filter(e => e.includes('SID must'))).toHaveLength(0);
  });

  it('rejects non-integer SID', () => {
    const rule = makeValidRule({ sid: 1.5 });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('SID'))).toBe(true);
  });

  // ---- rev ----

  it('rejects rev of 0', () => {
    const rule = makeValidRule({ rev: 0 });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('rev'))).toBe(true);
  });

  it('rejects negative rev', () => {
    const rule = makeValidRule({ rev: -1 });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('rev'))).toBe(true);
  });

  it('accepts rev = 1', () => {
    const rule = makeValidRule({ rev: 1 });
    const result = validateSuricataRule(rule);
    expect(result.errors.filter(e => e.includes('rev must'))).toHaveLength(0);
  });

  // ---- Warnings: SID mismatch ----

  it('warns when SID in options does not match rule.sid', () => {
    const rule = makeValidRule({
      sid: 9000001,
      options: [
        { keyword: 'msg', value: '"test"' },
        { keyword: 'sid', value: '9000099' },
        { keyword: 'rev', value: '1' },
      ],
    });
    const result = validateSuricataRule(rule);
    // Should still be valid (warning not error)
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('SID in options'))).toBe(true);
  });

  // ---- Warnings: rev mismatch ----

  it('warns when rev in options does not match rule.rev', () => {
    const rule = makeValidRule({
      rev: 1,
      options: [
        { keyword: 'msg', value: '"test"' },
        { keyword: 'sid', value: '9000001' },
        { keyword: 'rev', value: '5' },
      ],
    });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('rev in options'))).toBe(true);
  });

  // ---- Warnings: content not quoted ----

  it('warns when content value is not enclosed in double quotes', () => {
    const rule = makeValidRule({
      options: [
        { keyword: 'msg', value: '"test"' },
        { keyword: 'content', value: 'evil' },
        { keyword: 'sid', value: '9000001' },
        { keyword: 'rev', value: '1' },
      ],
    });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('Content value should be enclosed'))).toBe(true);
  });

  it('does not warn when content value is properly quoted', () => {
    const rule = makeValidRule({
      options: [
        { keyword: 'msg', value: '"test"' },
        { keyword: 'content', value: '"evil"' },
        { keyword: 'sid', value: '9000001' },
        { keyword: 'rev', value: '1' },
      ],
    });
    const result = validateSuricataRule(rule);
    expect(result.warnings.filter(w => w.includes('Content value'))).toHaveLength(0);
  });

  // ---- Multiple errors ----

  it('collects multiple errors when several fields are invalid', () => {
    const rule = makeValidRule({
      action: 'invalid' as any,
      protocol: 'invalid',
      sourceIp: '???',
      sourcePort: 'xyz',
      direction: '<<' as any,
      destIp: '???',
      destPort: 'xyz',
      sid: 0,
      rev: 0,
      options: [],
    });
    const result = validateSuricataRule(rule);
    expect(result.valid).toBe(false);
    // Should have at least one error per invalid field
    expect(result.errors.length).toBeGreaterThanOrEqual(7);
  });
});

// ===================================================================
// validateSuricataRaw
// ===================================================================

describe('validateSuricataRaw', () => {
  it('passes validation for a valid raw rule', () => {
    const result = validateSuricataRaw(makeValidRaw());
    expect(result.valid).toBe(true);
    expect(result.syntaxValid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('errors when parenthesized options block is missing', () => {
    const raw = 'alert tcp $HOME_NET any -> $EXTERNAL_NET any msg:"test"; sid:1; rev:1;';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('parentheses'))).toBe(true);
  });

  it('errors when header has too few parts', () => {
    const raw = 'alert tcp $HOME_NET any -> (msg:"test"; sid:1; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('7 parts'))).toBe(true);
  });

  it('errors for invalid action in raw rule', () => {
    const raw = 'block tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test"; sid:1; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid action'))).toBe(true);
  });

  it('errors for invalid protocol in raw rule', () => {
    const raw = 'alert gopher $HOME_NET any -> $EXTERNAL_NET any (msg:"test"; sid:1; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid protocol'))).toBe(true);
  });

  it('errors for invalid source IP in raw rule', () => {
    const raw = 'alert tcp not-an-ip any -> $EXTERNAL_NET any (msg:"test"; sid:1; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid source IP'))).toBe(true);
  });

  it('errors for invalid port in raw rule', () => {
    const raw = 'alert tcp $HOME_NET abc -> $EXTERNAL_NET any (msg:"test"; sid:1; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid source port'))).toBe(true);
  });

  it('errors for invalid direction in raw rule', () => {
    const raw = 'alert tcp $HOME_NET any <- $EXTERNAL_NET any (msg:"test"; sid:1; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Invalid direction'))).toBe(true);
  });

  it('errors when msg option is missing in raw rule', () => {
    const raw = 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (content:"evil"; sid:1; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('missing "msg"'))).toBe(true);
  });

  it('errors when sid option is missing in raw rule', () => {
    const raw = 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test"; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('missing "sid"'))).toBe(true);
  });

  it('errors when rev option is missing in raw rule', () => {
    const raw = 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test"; sid:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('missing "rev"'))).toBe(true);
  });

  it('errors when SID is out of range in raw rule', () => {
    const raw = 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test"; sid:99999999; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('out of valid range'))).toBe(true);
  });

  it('warns when options block does not end with a semicolon', () => {
    const raw = 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test"; sid:9000001; rev:1)';
    const result = validateSuricataRaw(raw);
    // The rule may still be valid (warnings are not errors) but SID/rev are parsed.
    // The absence of trailing semicolon is a warning.
    expect(result.warnings.some(w => w.includes('semicolon'))).toBe(true);
  });

  it('warns when content value is not quoted in raw rule', () => {
    const raw = 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test"; content:evil; sid:9000001; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.warnings.some(w => w.includes('Content value should be enclosed'))).toBe(true);
  });

  it('warns when msg value is not quoted in raw rule', () => {
    const raw = 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:test; sid:9000001; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.warnings.some(w => w.includes('msg value should be enclosed'))).toBe(true);
  });

  it('accepts a raw rule with bidirectional operator (<>)', () => {
    const raw = 'alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"test"; sid:9000001; rev:1;)';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(true);
  });

  it('accepts valid raw rules using dns and tls protocols', () => {
    const dnsRaw = 'alert dns $HOME_NET any -> any 53 (msg:"DNS query"; dns.query; content:"evil.com"; sid:9000010; rev:1;)';
    expect(validateSuricataRaw(dnsRaw).valid).toBe(true);

    const tlsRaw = 'alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"TLS SNI"; tls.sni; content:"evil.com"; sid:9000011; rev:1;)';
    expect(validateSuricataRaw(tlsRaw).valid).toBe(true);
  });

  it('handles leading and trailing whitespace in raw text', () => {
    const raw = '  alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test"; sid:9000001; rev:1;)  ';
    const result = validateSuricataRaw(raw);
    expect(result.valid).toBe(true);
  });
});

// ===================================================================
// validateSuricataRuleSet
// ===================================================================

describe('validateSuricataRuleSet', () => {
  it('passes validation for a set of valid rules with unique SIDs', () => {
    const rules = [
      makeValidRule({ sid: 9000001 }),
      makeValidRule({ sid: 9000002 }),
      makeValidRule({ sid: 9000003 }),
    ];
    const result = validateSuricataRuleSet(rules);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('detects duplicate SIDs across rules', () => {
    const rules = [
      makeValidRule({ sid: 9000001 }),
      makeValidRule({ sid: 9000001 }),
    ];
    const result = validateSuricataRuleSet(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Duplicate SID'))).toBe(true);
    expect(result.errors.some(e => e.includes('9000001'))).toBe(true);
  });

  it('includes the rule indices in the duplicate SID error', () => {
    const rules = [
      makeValidRule({ sid: 9000001 }),
      makeValidRule({ sid: 9000002 }),
      makeValidRule({ sid: 9000001 }),
    ];
    const result = validateSuricataRuleSet(rules);
    // Rules 1 and 3 (1-indexed) share SID 9000001
    expect(result.errors.some(e => e.includes('1') && e.includes('3'))).toBe(true);
  });

  it('propagates individual rule validation errors into the result', () => {
    const rules = [
      makeValidRule({ sid: 9000001 }),
      makeValidRule({ sid: 9000002, action: 'invalid' as any }),
    ];
    const result = validateSuricataRuleSet(rules);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Rule 2') && e.includes('Invalid action'))).toBe(true);
  });

  it('prefixes individual errors with rule number and SID', () => {
    const rules = [
      makeValidRule({ sid: 9000001, protocol: 'bad' }),
    ];
    const result = validateSuricataRuleSet(rules);
    expect(result.errors[0]).toMatch(/^Rule 1 \(SID 9000001\):/);
  });

  it('returns valid:true for an empty rule set', () => {
    const result = validateSuricataRuleSet([]);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('aggregates errors from multiple invalid rules and duplicate SIDs', () => {
    const rules = [
      makeValidRule({ sid: 9000001, action: 'bad' as any }),
      makeValidRule({ sid: 9000001, protocol: 'bad' }),
    ];
    const result = validateSuricataRuleSet(rules);
    expect(result.valid).toBe(false);
    // At least: 1 action error from rule 1, 1 protocol error from rule 2, 1 duplicate SID
    expect(result.errors.length).toBeGreaterThanOrEqual(3);
  });

  it('does not report duplicate SIDs when all SIDs are unique', () => {
    const rules = [
      makeValidRule({ sid: 1 }),
      makeValidRule({ sid: 2 }),
      makeValidRule({ sid: 3 }),
    ];
    const result = validateSuricataRuleSet(rules);
    expect(result.errors.filter(e => e.includes('Duplicate SID'))).toHaveLength(0);
  });
});
