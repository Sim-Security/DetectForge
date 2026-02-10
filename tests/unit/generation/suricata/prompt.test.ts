/**
 * Unit tests for Suricata AI prompt builder, response parser, and Zod schema.
 *
 * Covers:
 * - buildSuricataGenerationPrompt: system/user prompt structure and content
 * - parseSuricataAIResponse: valid JSON, markdown-wrapped JSON, multi-rule,
 *   field validation, optional metadata, missing fields, empty options
 * - SuricataAIResponseSchema: direct Zod validation checks
 */

import { describe, it, expect } from 'vitest';
import {
  buildSuricataGenerationPrompt,
  parseSuricataAIResponse,
  SuricataAIResponseSchema,
} from '@/ai/prompts/suricata-generation.js';
import type { SuricataTemplate } from '@/generation/suricata/templates.js';
import type { ExtractedIOC, ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeIOC(overrides: Partial<ExtractedIOC> & { value: string; type: string }): ExtractedIOC {
  return {
    context: 'observed in C2 traffic',
    confidence: 'high',
    defanged: false,
    originalValue: overrides.value,
    relationships: [],
    ...overrides,
  } as ExtractedIOC;
}

function makeTTP(overrides: Partial<ExtractedTTP> = {}): ExtractedTTP {
  return {
    description: 'DNS tunneling for C2 communication',
    tools: ['iodine'],
    targetPlatforms: ['windows', 'linux'],
    artifacts: [
      { type: 'network', description: 'High-frequency DNS queries' },
    ],
    detectionOpportunities: ['Monitor DNS query volume'],
    confidence: 'high',
    ...overrides,
  };
}

function makeMapping(overrides: Partial<AttackMappingResult> = {}): AttackMappingResult {
  return {
    techniqueId: 'T1071.004',
    techniqueName: 'Application Layer Protocol: DNS',
    tactic: 'command-and-control',
    confidence: 'high',
    reasoning: 'DNS tunneling observed for C2 communication',
    sourceTtp: makeTTP(),
    suggestedRuleFormats: ['suricata'],
    validated: true,
    ...overrides,
  };
}

function makeTemplate(overrides: Partial<SuricataTemplate> = {}): SuricataTemplate {
  return {
    category: 'dns_query',
    protocol: 'dns',
    description: 'DNS lookups to known C2 or malicious domains',
    defaultAction: 'alert',
    defaultDirection: '->',
    defaultSourceIp: '$HOME_NET',
    defaultSourcePort: 'any',
    defaultDestIp: 'any',
    defaultDestPort: '53',
    requiredKeywords: ['dns.query', 'content', 'nocase'],
    exampleOptions: [
      { keyword: 'msg', value: '"DetectForge - DNS query to malicious domain"' },
      { keyword: 'dns.query' },
      { keyword: 'content', value: '"evil.com"' },
    ],
    commonClasstype: 'trojan-activity',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Valid AI response payloads
// ---------------------------------------------------------------------------

const VALID_SINGLE_RULE_JSON = JSON.stringify({
  rules: [
    {
      msg: 'DetectForge - DNS query to evil.com',
      options: [
        { keyword: 'dns.query' },
        { keyword: 'content', value: '"evil.com"' },
        { keyword: 'nocase' },
      ],
      classtype: 'trojan-activity',
      metadata: { mitre_attack: 'T1071.004' },
      rationale: 'Detects DNS resolution of C2 domain.',
    },
  ],
});

const VALID_MULTI_RULE_JSON = JSON.stringify({
  rules: [
    {
      msg: 'DetectForge - DNS query to evil.com',
      options: [{ keyword: 'dns.query' }, { keyword: 'content', value: '"evil.com"' }],
      classtype: 'trojan-activity',
      rationale: 'First rule rationale.',
    },
    {
      msg: 'DetectForge - DNS query to bad.com',
      options: [{ keyword: 'dns.query' }, { keyword: 'content', value: '"bad.com"' }],
      classtype: 'trojan-activity',
      metadata: { mitre_attack: 'T1071.004', severity: 'high' },
      rationale: 'Second rule rationale.',
    },
  ],
});

// ===================================================================
// buildSuricataGenerationPrompt
// ===================================================================

describe('buildSuricataGenerationPrompt', () => {
  const iocs: ExtractedIOC[] = [
    makeIOC({ value: 'evil.com', type: 'domain' }),
    makeIOC({ value: '10.0.0.1', type: 'ipv4', context: 'C2 server IP' }),
  ];
  const ttps: ExtractedTTP[] = [
    makeTTP({ description: 'DNS tunneling via iodine' }),
  ];
  const mapping = makeMapping();
  const template = makeTemplate();

  const prompt = buildSuricataGenerationPrompt(iocs, ttps, mapping, template);

  it('returns an object with system and user string properties', () => {
    expect(prompt).toHaveProperty('system');
    expect(prompt).toHaveProperty('user');
    expect(typeof prompt.system).toBe('string');
    expect(typeof prompt.user).toBe('string');
  });

  it('returns non-empty system and user prompts', () => {
    expect(prompt.system.length).toBeGreaterThan(0);
    expect(prompt.user.length).toBeGreaterThan(0);
  });

  // ---- System prompt content ----

  it('system prompt contains Suricata syntax reference', () => {
    expect(prompt.system).toContain('SURICATA RULE SYNTAX REFERENCE');
    expect(prompt.system).toContain('action protocol src_ip src_port direction dest_ip dest_port');
  });

  it('system prompt includes keyword reference', () => {
    expect(prompt.system).toContain('KEYWORD REFERENCE');
    expect(prompt.system).toContain('content:');
    expect(prompt.system).toContain('dns.query');
    expect(prompt.system).toContain('tls.sni');
  });

  it('system prompt includes template defaults', () => {
    expect(prompt.system).toContain('TEMPLATE DEFAULTS');
    expect(prompt.system).toContain(template.category);
    expect(prompt.system).toContain(template.protocol);
    expect(prompt.system).toContain(template.defaultSourceIp);
    expect(prompt.system).toContain(template.defaultSourcePort);
    expect(prompt.system).toContain(template.defaultDestIp);
    expect(prompt.system).toContain(template.defaultDestPort);
    expect(prompt.system).toContain(template.commonClasstype);
  });

  it('system prompt includes required keywords from template', () => {
    for (const kw of template.requiredKeywords) {
      expect(prompt.system).toContain(kw);
    }
  });

  it('system prompt specifies JSON output format', () => {
    expect(prompt.system).toContain('OUTPUT FORMAT');
    expect(prompt.system).toContain('"rules"');
  });

  it('system prompt includes quality guidelines', () => {
    expect(prompt.system).toContain('QUALITY GUIDELINES');
    expect(prompt.system).toContain('nocase');
    expect(prompt.system).toContain('DetectForge');
  });

  // ---- User prompt content ----

  it('user prompt includes ATT&CK technique info', () => {
    expect(prompt.user).toContain(mapping.techniqueId);
    expect(prompt.user).toContain(mapping.techniqueName);
    expect(prompt.user).toContain(mapping.tactic);
    expect(prompt.user).toContain(mapping.reasoning);
  });

  it('user prompt includes the IOC list', () => {
    expect(prompt.user).toContain('evil.com');
    expect(prompt.user).toContain('10.0.0.1');
    expect(prompt.user).toContain('[domain]');
    expect(prompt.user).toContain('[ipv4]');
  });

  it('user prompt includes IOC context text', () => {
    expect(prompt.user).toContain('observed in C2 traffic');
    expect(prompt.user).toContain('C2 server IP');
  });

  it('user prompt includes the TTP list', () => {
    expect(prompt.user).toContain('DNS tunneling via iodine');
    expect(prompt.user).toContain('RELATED TTPs');
  });

  it('user prompt includes TTP tool names', () => {
    // The TTP factory includes tool 'iodine'
    expect(prompt.user).toContain('iodine');
  });

  it('user prompt includes the template category name', () => {
    expect(prompt.user).toContain(template.category);
    expect(prompt.user).toContain(template.protocol);
  });

  it('user prompt mentions generating one rule per IOC', () => {
    expect(prompt.user).toContain('one Suricata rule per IOC');
  });

  // ---- Different template propagation ----

  it('adapts system prompt when a different template is provided', () => {
    const httpTemplate = makeTemplate({
      category: 'http_request',
      protocol: 'http',
      defaultDestPort: '$HTTP_PORTS',
      defaultDestIp: '$EXTERNAL_NET',
      requiredKeywords: ['http.host', 'content'],
      commonClasstype: 'trojan-activity',
    });
    const httpPrompt = buildSuricataGenerationPrompt(iocs, ttps, mapping, httpTemplate);
    expect(httpPrompt.system).toContain('http_request');
    expect(httpPrompt.system).toContain('http');
    expect(httpPrompt.system).toContain('$HTTP_PORTS');
    expect(httpPrompt.system).toContain('http.host');
    expect(httpPrompt.user).toContain('http_request');
  });
});

// ===================================================================
// parseSuricataAIResponse
// ===================================================================

describe('parseSuricataAIResponse', () => {
  it('parses a valid JSON response with a single rule', () => {
    const result = parseSuricataAIResponse(VALID_SINGLE_RULE_JSON);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0].msg).toBe('DetectForge - DNS query to evil.com');
    expect(result.rules[0].classtype).toBe('trojan-activity');
    expect(result.rules[0].rationale).toBe('Detects DNS resolution of C2 domain.');
  });

  it('parses a valid JSON response with multiple rules', () => {
    const result = parseSuricataAIResponse(VALID_MULTI_RULE_JSON);
    expect(result.rules).toHaveLength(2);
    expect(result.rules[0].msg).toContain('evil.com');
    expect(result.rules[1].msg).toContain('bad.com');
  });

  it('parses JSON wrapped in markdown code block (```json ... ```)', () => {
    const wrapped = '```json\n' + VALID_SINGLE_RULE_JSON + '\n```';
    const result = parseSuricataAIResponse(wrapped);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0].msg).toContain('evil.com');
  });

  it('parses JSON wrapped in plain markdown code block (``` ... ```)', () => {
    const wrapped = '```\n' + VALID_SINGLE_RULE_JSON + '\n```';
    const result = parseSuricataAIResponse(wrapped);
    expect(result.rules).toHaveLength(1);
  });

  it('parses JSON with surrounding text (preamble/postamble)', () => {
    const withText = 'Here are the rules:\n\n' + VALID_SINGLE_RULE_JSON + '\n\nLet me know if you need changes.';
    const result = parseSuricataAIResponse(withText);
    expect(result.rules).toHaveLength(1);
  });

  it('preserves all option keywords and values', () => {
    const result = parseSuricataAIResponse(VALID_SINGLE_RULE_JSON);
    const options = result.rules[0].options;
    expect(options).toHaveLength(3);
    expect(options[0]).toEqual({ keyword: 'dns.query' });
    expect(options[1]).toEqual({ keyword: 'content', value: '"evil.com"' });
    expect(options[2]).toEqual({ keyword: 'nocase' });
  });

  it('preserves optional metadata when present', () => {
    const result = parseSuricataAIResponse(VALID_SINGLE_RULE_JSON);
    expect(result.rules[0].metadata).toEqual({ mitre_attack: 'T1071.004' });
  });

  it('accepts a rule without metadata (metadata is optional)', () => {
    const json = JSON.stringify({
      rules: [
        {
          msg: 'Test rule',
          options: [],
          classtype: 'trojan-activity',
          rationale: 'Test rationale.',
        },
      ],
    });
    const result = parseSuricataAIResponse(json);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0].metadata).toBeUndefined();
  });

  it('accepts a rule with an empty options array', () => {
    const json = JSON.stringify({
      rules: [
        {
          msg: 'Empty options rule',
          options: [],
          classtype: 'trojan-activity',
          rationale: 'No extra options needed.',
        },
      ],
    });
    const result = parseSuricataAIResponse(json);
    expect(result.rules[0].options).toEqual([]);
  });

  it('accepts options where value is undefined (keyword-only)', () => {
    const json = JSON.stringify({
      rules: [
        {
          msg: 'Test',
          options: [{ keyword: 'nocase' }],
          classtype: 'trojan-activity',
          rationale: 'Keyword without value.',
        },
      ],
    });
    const result = parseSuricataAIResponse(json);
    expect(result.rules[0].options[0].keyword).toBe('nocase');
    expect(result.rules[0].options[0].value).toBeUndefined();
  });

  it('preserves metadata with multiple key-value pairs', () => {
    const result = parseSuricataAIResponse(VALID_MULTI_RULE_JSON);
    const meta = result.rules[1].metadata;
    expect(meta).toBeDefined();
    expect(meta!.mitre_attack).toBe('T1071.004');
    expect(meta!.severity).toBe('high');
  });

  // ---- Error cases ----

  it('throws when the rules array is missing', () => {
    const json = JSON.stringify({ data: [] });
    expect(() => parseSuricataAIResponse(json)).toThrow();
  });

  it('throws when rules is not an array', () => {
    const json = JSON.stringify({ rules: 'not an array' });
    expect(() => parseSuricataAIResponse(json)).toThrow();
  });

  it('throws when a rule is missing the msg field', () => {
    const json = JSON.stringify({
      rules: [
        {
          options: [],
          classtype: 'trojan-activity',
          rationale: 'Missing msg.',
        },
      ],
    });
    expect(() => parseSuricataAIResponse(json)).toThrow();
  });

  it('throws when a rule is missing the options field', () => {
    const json = JSON.stringify({
      rules: [
        {
          msg: 'Test',
          classtype: 'trojan-activity',
          rationale: 'Missing options.',
        },
      ],
    });
    expect(() => parseSuricataAIResponse(json)).toThrow();
  });

  it('throws when a rule is missing the classtype field', () => {
    const json = JSON.stringify({
      rules: [
        {
          msg: 'Test',
          options: [],
          rationale: 'Missing classtype.',
        },
      ],
    });
    expect(() => parseSuricataAIResponse(json)).toThrow();
  });

  it('throws when a rule is missing the rationale field', () => {
    const json = JSON.stringify({
      rules: [
        {
          msg: 'Test',
          options: [],
          classtype: 'trojan-activity',
        },
      ],
    });
    expect(() => parseSuricataAIResponse(json)).toThrow();
  });

  it('throws for completely invalid JSON', () => {
    expect(() => parseSuricataAIResponse('not json at all')).toThrow();
  });

  it('throws an error whose message references validation failure', () => {
    const json = JSON.stringify({ rules: [{ msg: 'x' }] });
    try {
      parseSuricataAIResponse(json);
      expect.fail('Should have thrown');
    } catch (err: any) {
      expect(err.message).toContain('validation failed');
    }
  });
});

// ===================================================================
// SuricataAIResponseSchema (direct Zod)
// ===================================================================

describe('SuricataAIResponseSchema', () => {
  it('validates a correct payload', () => {
    const payload = {
      rules: [
        {
          msg: 'Test rule',
          options: [{ keyword: 'content', value: '"test"' }],
          classtype: 'trojan-activity',
          rationale: 'Detects test pattern.',
        },
      ],
    };
    const result = SuricataAIResponseSchema.safeParse(payload);
    expect(result.success).toBe(true);
  });

  it('rejects payload with empty rules array (schema allows it)', () => {
    // Empty rules array should actually be valid per the Zod schema (z.array allows empty)
    const payload = { rules: [] };
    const result = SuricataAIResponseSchema.safeParse(payload);
    expect(result.success).toBe(true);
  });

  it('rejects payload without rules key', () => {
    const result = SuricataAIResponseSchema.safeParse({ notRules: [] });
    expect(result.success).toBe(false);
  });

  it('rejects a rule with an option missing keyword field', () => {
    const payload = {
      rules: [
        {
          msg: 'Test',
          options: [{ value: '"evil"' }],
          classtype: 'trojan-activity',
          rationale: 'Test.',
        },
      ],
    };
    const result = SuricataAIResponseSchema.safeParse(payload);
    expect(result.success).toBe(false);
  });

  it('accepts metadata with arbitrary string key-value pairs', () => {
    const payload = {
      rules: [
        {
          msg: 'Test',
          options: [],
          classtype: 'x',
          rationale: 'y',
          metadata: { a: 'b', c: 'd', e: 'f' },
        },
      ],
    };
    const result = SuricataAIResponseSchema.safeParse(payload);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.rules[0].metadata).toEqual({ a: 'b', c: 'd', e: 'f' });
    }
  });

  it('rejects metadata with non-string values', () => {
    const payload = {
      rules: [
        {
          msg: 'Test',
          options: [],
          classtype: 'x',
          rationale: 'y',
          metadata: { a: 123 },
        },
      ],
    };
    const result = SuricataAIResponseSchema.safeParse(payload);
    expect(result.success).toBe(false);
  });
});
