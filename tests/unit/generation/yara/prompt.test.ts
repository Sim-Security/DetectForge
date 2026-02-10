import { describe, it, expect, vi } from 'vitest';
import {
  buildYaraGenerationPrompt,
  parseYaraAIResponse,
  YaraAIResponseSchema,
} from '@/ai/prompts/yara-generation.js';
import type { ExtractedIOC, ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';
import type { YaraTemplate } from '@/generation/yara/templates.js';

// ---------------------------------------------------------------------------
// Helpers — factory functions for test data
// ---------------------------------------------------------------------------

function makeIOC(overrides: Partial<ExtractedIOC> = {}): ExtractedIOC {
  return {
    value: '192.168.1.1',
    type: 'ipv4',
    context: 'C2 server IP address',
    confidence: 'high',
    defanged: false,
    originalValue: '192.168.1.1',
    relationships: [],
    ...overrides,
  };
}

function makeTTP(overrides: Partial<ExtractedTTP> = {}): ExtractedTTP {
  return {
    description: 'Uses PowerShell encoded commands for payload execution',
    tools: ['PowerShell'],
    targetPlatforms: ['windows'],
    artifacts: [
      { type: 'file', description: 'PowerShell script', value: 'stage2.ps1' },
    ],
    detectionOpportunities: ['Monitor for encoded PowerShell commands'],
    confidence: 'high',
    ...overrides,
  };
}

function makeMapping(overrides: Partial<AttackMappingResult> = {}): AttackMappingResult {
  return {
    techniqueId: 'T1059.001',
    techniqueName: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    confidence: 'high',
    reasoning: 'Report describes PowerShell-based payload execution',
    sourceTtp: makeTTP(),
    suggestedRuleFormats: ['yara', 'sigma'],
    validated: true,
    ...overrides,
  };
}

function makeTemplate(overrides: Partial<YaraTemplate> = {}): YaraTemplate {
  return {
    category: 'script_powershell',
    description: 'Detects malicious PowerShell scripts using encoded commands or download cradles.',
    commonStrings: ['-EncodedCommand', 'Invoke-Expression', 'IEX', 'Net.WebClient'],
    conditionTemplate: 'filesize < 5MB and <string_condition>',
    exampleMeta: {
      description: 'Detects PowerShell download cradle',
      author: 'DetectForge',
      date: '2026-02-10',
      reference: 'https://example.com',
      mitre_attack: 'T1059.001',
    },
    ...overrides,
  };
}

/**
 * Build a valid AI response JSON string with one rule.
 */
function makeValidResponseJSON(overrides: Record<string, any> = {}): string {
  const rule = {
    name: 'Detect_PS_Encoded_Cmd',
    tags: ['malware', 'powershell'],
    meta: {
      description: 'Detects PowerShell with encoded command execution',
      author: 'DetectForge',
      date: '2026-02-10',
      reference: 'https://example.com/report',
      mitre_attack: 'T1059.001',
    },
    strings: [
      {
        identifier: '$s1',
        value: '-EncodedCommand',
        type: 'text',
        modifiers: ['ascii', 'nocase'],
      },
      {
        identifier: '$s2',
        value: 'Invoke-Expression',
        type: 'text',
        modifiers: ['ascii'],
      },
    ],
    condition: 'filesize < 5MB and any of ($s*)',
    ...overrides,
  };

  return JSON.stringify({ rules: [rule] });
}

// ===========================================================================
// buildYaraGenerationPrompt
// ===========================================================================

describe('buildYaraGenerationPrompt', () => {
  const iocs = [makeIOC(), makeIOC({ value: 'evil.exe', type: 'filepath_windows', context: 'Dropped binary' })];
  const ttps = [makeTTP()];
  const mapping = makeMapping();
  const template = makeTemplate();

  it('returns an object with system and user strings', () => {
    const result = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(result).toHaveProperty('system');
    expect(result).toHaveProperty('user');
    expect(typeof result.system).toBe('string');
    expect(typeof result.user).toBe('string');
    expect(result.system.length).toBeGreaterThan(0);
    expect(result.user.length).toBeGreaterThan(0);
  });

  it('system prompt contains YARA syntax reference', () => {
    const { system } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(system).toContain('YARA Rule Syntax Reference');
    expect(system).toContain('meta:');
    expect(system).toContain('strings:');
    expect(system).toContain('condition:');
    expect(system).toContain('Text strings');
    expect(system).toContain('Hex strings');
    expect(system).toContain('Regex strings');
  });

  it('system prompt includes template category context', () => {
    const { system } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(system).toContain('script_powershell');
    expect(system).toContain(template.description);
  });

  it('system prompt includes template common strings', () => {
    const { system } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    for (const s of template.commonStrings) {
      expect(system).toContain(s);
    }
  });

  it('system prompt includes condition template', () => {
    const { system } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(system).toContain(template.conditionTemplate);
  });

  it('system prompt includes magic bytes info when template has them', () => {
    const peTemplate = makeTemplate({
      category: 'binary_pe',
      magicBytes: ['4D5A'],
    });
    const { system } = buildYaraGenerationPrompt(iocs, ttps, mapping, peTemplate);
    expect(system).toContain('4D5A');
    expect(system).toContain('Magic bytes');
  });

  it('system prompt notes no magic bytes when template lacks them', () => {
    const { system } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(system).toContain('No magic byte constraint');
  });

  it('system prompt includes quality guidelines', () => {
    const { system } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(system).toContain('Quality Guidelines');
    expect(system).toContain('false positives');
  });

  it('system prompt includes output format specification', () => {
    const { system } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(system).toContain('Output Format');
    expect(system).toContain('"rules"');
  });

  it('user prompt includes ATT&CK technique info', () => {
    const { user } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(user).toContain('T1059.001');
    expect(user).toContain('Command and Scripting Interpreter: PowerShell');
    expect(user).toContain('Execution');
    expect(user).toContain(mapping.reasoning);
  });

  it('user prompt includes IOC summary', () => {
    const { user } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(user).toContain('Indicators of Compromise');
    expect(user).toContain('192.168.1.1');
    expect(user).toContain('evil.exe');
  });

  it('user prompt includes TTP summary', () => {
    const { user } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(user).toContain('Tactics, Techniques, and Procedures');
    expect(user).toContain('PowerShell encoded commands');
    expect(user).toContain('stage2.ps1');
  });

  it('user prompt includes tool names from TTPs', () => {
    const { user } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(user).toContain('PowerShell');
  });

  it('user prompt includes platform info from TTPs', () => {
    const { user } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(user).toContain('windows');
  });

  it('user prompt includes detection opportunities from TTPs', () => {
    const { user } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(user).toContain('Monitor for encoded PowerShell commands');
  });

  it('user prompt handles empty IOCs gracefully', () => {
    const { user } = buildYaraGenerationPrompt([], ttps, mapping, template);
    expect(user).toContain('No IOCs provided');
  });

  it('user prompt handles empty TTPs gracefully', () => {
    const { user } = buildYaraGenerationPrompt(iocs, [], mapping, template);
    expect(user).toContain('No TTPs provided');
  });

  it('user prompt handles both empty IOCs and TTPs', () => {
    const { user } = buildYaraGenerationPrompt([], [], mapping, template);
    expect(user).toContain('No IOCs provided');
    expect(user).toContain('No TTPs provided');
  });

  it('user prompt includes template category in instructions', () => {
    const { user } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(user).toContain('"script_powershell"');
  });

  it('user prompt instructs to set mitre_attack to the technique ID', () => {
    const { user } = buildYaraGenerationPrompt(iocs, ttps, mapping, template);
    expect(user).toContain(`"${mapping.techniqueId}"`);
  });

  it('user prompt groups IOCs by type', () => {
    const multiIocs: ExtractedIOC[] = [
      makeIOC({ value: '10.0.0.1', type: 'ipv4', context: 'IP 1' }),
      makeIOC({ value: '10.0.0.2', type: 'ipv4', context: 'IP 2' }),
      makeIOC({ value: 'abc123', type: 'md5', context: 'Hash' }),
    ];
    const { user } = buildYaraGenerationPrompt(multiIocs, ttps, mapping, template);
    expect(user).toContain('ipv4');
    expect(user).toContain('md5');
  });
});

// ===========================================================================
// parseYaraAIResponse
// ===========================================================================

describe('parseYaraAIResponse', () => {
  // ---- Happy path: valid JSON ----

  it('parses valid JSON with one rule', () => {
    const raw = makeValidResponseJSON();
    const result = parseYaraAIResponse(raw);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0].name).toBe('Detect_PS_Encoded_Cmd');
    expect(result.rules[0].strings).toHaveLength(2);
    expect(result.rules[0].condition).toBe('filesize < 5MB and any of ($s*)');
  });

  it('parses valid JSON with multiple rules', () => {
    const data = {
      rules: [
        {
          name: 'Rule_One',
          tags: ['malware'],
          meta: {
            description: 'First rule',
            author: 'DetectForge',
            date: '2026-02-10',
            reference: '',
            mitre_attack: 'T1059.001',
          },
          strings: [
            { identifier: '$s1', value: 'test_one', type: 'text', modifiers: [] },
          ],
          condition: 'any of them',
        },
        {
          name: 'Rule_Two',
          tags: [],
          meta: {
            description: 'Second rule',
            author: 'DetectForge',
            date: '2026-02-10',
            reference: '',
            mitre_attack: 'T1059.001',
          },
          strings: [
            { identifier: '$s1', value: 'test_two', type: 'text', modifiers: [] },
          ],
          condition: 'all of them',
        },
      ],
    };
    const result = parseYaraAIResponse(JSON.stringify(data));
    expect(result.rules).toHaveLength(2);
    expect(result.rules[0].name).toBe('Rule_One');
    expect(result.rules[1].name).toBe('Rule_Two');
  });

  // ---- Markdown-wrapped JSON ----

  it('parses JSON wrapped in markdown code fences', () => {
    const raw = '```json\n' + makeValidResponseJSON() + '\n```';
    const result = parseYaraAIResponse(raw);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0].name).toBe('Detect_PS_Encoded_Cmd');
  });

  it('parses JSON wrapped in plain markdown code fences (no language tag)', () => {
    const raw = '```\n' + makeValidResponseJSON() + '\n```';
    const result = parseYaraAIResponse(raw);
    expect(result.rules).toHaveLength(1);
  });

  it('parses JSON with extra commentary text around it', () => {
    const raw = 'Here is the generated YARA rule:\n\n' + makeValidResponseJSON() + '\n\nLet me know if you need changes.';
    const result = parseYaraAIResponse(raw);
    expect(result.rules).toHaveLength(1);
  });

  // ---- Validation: invalid rule name ----

  it('rejects a rule with an invalid name (starts with number)', () => {
    const raw = makeValidResponseJSON({ name: '123_invalid' });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  it('rejects a rule with an invalid name (contains spaces)', () => {
    const raw = makeValidResponseJSON({ name: 'Invalid Name' });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  it('rejects a rule with an invalid name (contains hyphens)', () => {
    const raw = makeValidResponseJSON({ name: 'Invalid-Name' });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  // ---- Validation: empty strings array ----

  it('rejects a rule with an empty strings array', () => {
    const raw = makeValidResponseJSON({ strings: [] });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  // ---- Validation: empty condition ----

  it('rejects a rule with an empty condition', () => {
    const raw = makeValidResponseJSON({ condition: '' });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  // ---- Validation: invalid string identifier ----

  it('rejects a rule with a string identifier missing $', () => {
    const raw = makeValidResponseJSON({
      strings: [
        { identifier: 's1', value: 'test', type: 'text', modifiers: [] },
      ],
    });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  it('rejects a rule with a string identifier starting with $number', () => {
    const raw = makeValidResponseJSON({
      strings: [
        { identifier: '$1abc', value: 'test', type: 'text', modifiers: [] },
      ],
    });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  // ---- Validation: empty string value ----

  it('rejects a rule with an empty string value', () => {
    const raw = makeValidResponseJSON({
      strings: [
        { identifier: '$s1', value: '', type: 'text', modifiers: [] },
      ],
    });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  // ---- Validation: invalid string type ----

  it('rejects a rule with an invalid string type', () => {
    const raw = makeValidResponseJSON({
      strings: [
        { identifier: '$s1', value: 'test', type: 'binary', modifiers: [] },
      ],
    });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  // ---- Validation: missing required meta fields ----

  it('rejects a rule with empty description', () => {
    const raw = makeValidResponseJSON({
      meta: {
        description: '',
        author: 'DetectForge',
        date: '2026-02-10',
      },
    });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  it('rejects a rule with empty author', () => {
    const raw = makeValidResponseJSON({
      meta: {
        description: 'Test rule',
        author: '',
        date: '2026-02-10',
      },
    });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  it('rejects a rule with empty date', () => {
    const raw = makeValidResponseJSON({
      meta: {
        description: 'Test rule',
        author: 'DetectForge',
        date: '',
      },
    });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  // ---- Defaults for optional fields ----

  it('provides default empty array for tags when omitted', () => {
    const data = {
      rules: [
        {
          name: 'Test_Rule',
          // tags omitted
          meta: {
            description: 'Test',
            author: 'DetectForge',
            date: '2026-02-10',
          },
          strings: [
            { identifier: '$s1', value: 'test', type: 'text' },
          ],
          condition: 'any of them',
        },
      ],
    };
    const result = parseYaraAIResponse(JSON.stringify(data));
    expect(result.rules[0].tags).toEqual([]);
  });

  it('provides default empty array for modifiers when omitted', () => {
    const data = {
      rules: [
        {
          name: 'Test_Rule',
          tags: [],
          meta: {
            description: 'Test',
            author: 'DetectForge',
            date: '2026-02-10',
          },
          strings: [
            { identifier: '$s1', value: 'test', type: 'text' },
            // modifiers omitted
          ],
          condition: 'any of them',
        },
      ],
    };
    const result = parseYaraAIResponse(JSON.stringify(data));
    expect(result.rules[0].strings[0].modifiers).toEqual([]);
  });

  it('provides default empty string for reference when omitted', () => {
    const data = {
      rules: [
        {
          name: 'Test_Rule',
          tags: [],
          meta: {
            description: 'Test',
            author: 'DetectForge',
            date: '2026-02-10',
            // reference omitted
          },
          strings: [
            { identifier: '$s1', value: 'test', type: 'text', modifiers: [] },
          ],
          condition: 'any of them',
        },
      ],
    };
    const result = parseYaraAIResponse(JSON.stringify(data));
    expect(result.rules[0].meta.reference).toBe('');
  });

  it('provides default empty string for mitre_attack when omitted', () => {
    const data = {
      rules: [
        {
          name: 'Test_Rule',
          tags: [],
          meta: {
            description: 'Test',
            author: 'DetectForge',
            date: '2026-02-10',
            // mitre_attack omitted
          },
          strings: [
            { identifier: '$s1', value: 'test', type: 'text', modifiers: [] },
          ],
          condition: 'any of them',
        },
      ],
    };
    const result = parseYaraAIResponse(JSON.stringify(data));
    expect(result.rules[0].meta.mitre_attack).toBe('');
  });

  it('accepts optional hash field in meta', () => {
    const raw = makeValidResponseJSON({
      meta: {
        description: 'Test',
        author: 'DetectForge',
        date: '2026-02-10',
        reference: '',
        mitre_attack: 'T1059.001',
        hash: 'abc123def456',
      },
    });
    const result = parseYaraAIResponse(raw);
    expect(result.rules[0].meta.hash).toBe('abc123def456');
  });

  it('allows hash to be absent from meta', () => {
    const raw = makeValidResponseJSON();
    const result = parseYaraAIResponse(raw);
    expect(result.rules[0].meta.hash).toBeUndefined();
  });

  // ---- Validation: empty rules array ----

  it('rejects a response with no rules', () => {
    const raw = JSON.stringify({ rules: [] });
    expect(() => parseYaraAIResponse(raw)).toThrow();
  });

  // ---- Validation: completely invalid JSON ----

  it('rejects completely invalid JSON', () => {
    expect(() => parseYaraAIResponse('not json at all {{{}')).toThrow();
  });

  // ---- Error message contains context ----

  it('error message includes details about what failed', () => {
    const raw = makeValidResponseJSON({ name: '1bad' });
    try {
      parseYaraAIResponse(raw);
      // Should not reach here
      expect(true).toBe(false);
    } catch (e: any) {
      expect(e.message).toContain('YARA AI response validation failed');
    }
  });
});

// ===========================================================================
// YaraAIResponseSchema (direct Zod validation)
// ===========================================================================

describe('YaraAIResponseSchema', () => {
  it('validates a correctly shaped object', () => {
    const data = {
      rules: [
        {
          name: 'Valid_Rule',
          tags: ['malware'],
          meta: {
            description: 'Test detection rule',
            author: 'DetectForge',
            date: '2026-02-10',
            reference: 'https://example.com',
            mitre_attack: 'T1059.001',
          },
          strings: [
            { identifier: '$s1', value: 'test', type: 'text', modifiers: ['ascii'] },
          ],
          condition: 'any of them',
        },
      ],
    };
    const result = YaraAIResponseSchema.safeParse(data);
    expect(result.success).toBe(true);
  });

  it('rejects object without rules key', () => {
    const result = YaraAIResponseSchema.safeParse({ notRules: [] });
    expect(result.success).toBe(false);
  });

  it('rejects rule with missing meta', () => {
    const data = {
      rules: [
        {
          name: 'Test_Rule',
          tags: [],
          // meta missing
          strings: [
            { identifier: '$s1', value: 'test', type: 'text', modifiers: [] },
          ],
          condition: 'any of them',
        },
      ],
    };
    const result = YaraAIResponseSchema.safeParse(data);
    expect(result.success).toBe(false);
  });

  it('allows passthrough of extra meta fields', () => {
    const data = {
      rules: [
        {
          name: 'Valid_Rule',
          tags: [],
          meta: {
            description: 'Test',
            author: 'DetectForge',
            date: '2026-02-10',
            reference: '',
            mitre_attack: '',
            custom_field: 'custom_value',
          },
          strings: [
            { identifier: '$s1', value: 'test', type: 'text', modifiers: [] },
          ],
          condition: 'any of them',
        },
      ],
    };
    const result = YaraAIResponseSchema.safeParse(data);
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data.rules[0].meta as any).custom_field).toBe('custom_value');
    }
  });

  it('validates all three string types (text, hex, regex)', () => {
    const data = {
      rules: [
        {
          name: 'Multi_Type_Rule',
          tags: [],
          meta: {
            description: 'Test',
            author: 'DetectForge',
            date: '2026-02-10',
          },
          strings: [
            { identifier: '$text1', value: 'hello world', type: 'text', modifiers: ['ascii'] },
            { identifier: '$hex1', value: '4D 5A 90 00', type: 'hex', modifiers: [] },
            { identifier: '$re1', value: 'mal[a-z]+ware', type: 'regex', modifiers: [] },
          ],
          condition: 'any of them',
        },
      ],
    };
    const result = YaraAIResponseSchema.safeParse(data);
    expect(result.success).toBe(true);
  });
});
