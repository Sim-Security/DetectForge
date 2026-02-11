/**
 * Unit tests for the Sigma rule validator.
 *
 * Covers: validateSigmaRule, validateSigmaYaml
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { validateSigmaRule, validateSigmaYaml } from '@/generation/sigma/validator.js';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Mock the logsource catalog so tests do not depend on catalog data
// ---------------------------------------------------------------------------

vi.mock('@/knowledge/logsource-catalog/index.js', () => ({
  validateSigmaLogsource: vi.fn(
    (product: string, category?: string, _service?: string) => {
      // Recognise a handful of common logsource combos used in tests
      const known = new Set([
        'windows|process_creation|',
        'windows|network_connection|',
        'windows||security',
        'windows|dns_query|',
        'windows|file_event|',
        'windows|registry_set|',
        'windows|ps_script|powershell',
        'linux|process_creation|',
      ]);
      const key = `${product}|${category ?? ''}|${_service ?? ''}`;
      return known.has(key);
    },
  ),
  getFieldsForLogsource: vi.fn(() => []),
}));

// ---------------------------------------------------------------------------
// Helpers — build a valid SigmaRule fixture
// ---------------------------------------------------------------------------

function makeValidRule(overrides: Partial<SigmaRule> = {}): SigmaRule {
  return {
    id: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    title: 'Suspicious Process Creation via cmd.exe',
    status: 'experimental',
    description:
      'Detects suspicious process creation patterns indicative of malicious activity.',
    references: ['https://example.com/report'],
    author: 'DetectForge',
    date: '2026/02/10',
    modified: '2026/02/10',
    tags: ['attack.execution', 'attack.t1059.001'],
    logsource: { product: 'windows', category: 'process_creation' },
    detection: {
      selection: {
        Image: ['*\\cmd.exe'],
        CommandLine: ['*-encodedcommand*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate admin scripts'],
    level: 'high',
    raw: '---\ntitle: test\n',
    ...overrides,
  };
}

// ===========================================================================
// validateSigmaRule
// ===========================================================================

describe('validateSigmaRule', () => {
  // -----------------------------------------------------------------------
  // Happy path
  // -----------------------------------------------------------------------

  it('returns valid=true for a fully valid rule', () => {
    const result = validateSigmaRule(makeValidRule());
    expect(result.valid).toBe(true);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // -----------------------------------------------------------------------
  // Required field errors
  // -----------------------------------------------------------------------

  describe('required field: title', () => {
    it('produces error when title is missing', () => {
      const rule = makeValidRule({ title: '' });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('title')]),
      );
    });

    it('produces error when title is only whitespace', () => {
      const rule = makeValidRule({ title: '   ' });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('title')]),
      );
    });
  });

  describe('required field: id (UUID v4)', () => {
    it('produces error when id is missing', () => {
      const rule = makeValidRule({ id: '' });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('id')]),
      );
    });

    it('produces error for non-UUID id', () => {
      const rule = makeValidRule({ id: 'not-a-uuid' });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('UUID')]),
      );
    });

    it('produces error for UUID v1 (wrong version nibble)', () => {
      // UUID v1 has the version nibble "1" instead of "4"
      const rule = makeValidRule({
        id: 'f47ac10b-58cc-1372-a567-0e02b2c3d479',
      });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('UUID')]),
      );
    });

    it('accepts a valid UUID v4', () => {
      const rule = makeValidRule({
        id: 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
      });
      const result = validateSigmaRule(rule);
      expect(result.errors.filter((e) => e.includes('id'))).toHaveLength(0);
    });

    it('accepts uppercase UUID v4', () => {
      const rule = makeValidRule({
        id: 'A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D',
      });
      const result = validateSigmaRule(rule);
      expect(result.errors.filter((e) => e.includes('UUID'))).toHaveLength(0);
    });
  });

  describe('required field: status', () => {
    it('produces error when status is missing', () => {
      const rule = makeValidRule({ status: '' as any });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('status')]),
      );
    });

    it('produces error for invalid status value', () => {
      const rule = makeValidRule({ status: 'production' as any });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('status')]),
      );
    });

    it.each([
      'experimental',
      'test',
      'stable',
      'deprecated',
      'unsupported',
    ] as const)('accepts valid status "%s"', (status) => {
      const rule = makeValidRule({ status });
      const result = validateSigmaRule(rule);
      expect(result.errors.filter((e) => e.includes('status'))).toHaveLength(0);
    });
  });

  describe('required field: description', () => {
    it('produces error when description is missing', () => {
      const rule = makeValidRule({ description: '' });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('description')]),
      );
    });
  });

  describe('required field: level', () => {
    it('produces error when level is missing', () => {
      const rule = makeValidRule({ level: '' as any });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('level')]),
      );
    });

    it('produces error for invalid level value', () => {
      const rule = makeValidRule({ level: 'urgent' as any });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('level')]),
      );
    });

    it.each([
      'informational',
      'low',
      'medium',
      'high',
      'critical',
    ] as const)('accepts valid level "%s"', (level) => {
      const rule = makeValidRule({ level });
      const result = validateSigmaRule(rule);
      expect(result.errors.filter((e) => e.includes('level'))).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // Logsource validation
  // -----------------------------------------------------------------------

  describe('logsource', () => {
    it('produces error when logsource is missing entirely', () => {
      const rule = makeValidRule();
      (rule as any).logsource = undefined;
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('logsource')]),
      );
    });

    it('produces error when logsource has neither product nor category', () => {
      const rule = makeValidRule({
        logsource: {} as any,
      });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.stringContaining('product'),
        ]),
      );
    });

    it('accepts logsource with only product', () => {
      const rule = makeValidRule({
        logsource: { product: 'windows' },
      });
      const result = validateSigmaRule(rule);
      expect(
        result.errors.filter((e) => e.includes('product') || e.includes('category')),
      ).toHaveLength(0);
    });

    it('accepts logsource with only category', () => {
      const rule = makeValidRule({
        logsource: { category: 'process_creation' },
      });
      const result = validateSigmaRule(rule);
      expect(
        result.errors.filter(
          (e) =>
            e.includes('Logsource must have at least'),
        ),
      ).toHaveLength(0);
    });

    it('produces warning when logsource combination is not in catalog', () => {
      const rule = makeValidRule({
        logsource: {
          product: 'windows',
          category: 'totally_unknown_category',
        },
      });
      const result = validateSigmaRule(rule);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('catalog')]),
      );
    });

    it('produces no warning for known logsource combination', () => {
      const rule = makeValidRule({
        logsource: { product: 'windows', category: 'process_creation' },
      });
      const result = validateSigmaRule(rule);
      expect(
        result.warnings.filter((w) => w.includes('catalog')),
      ).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // Detection validation
  // -----------------------------------------------------------------------

  describe('detection', () => {
    it('produces error when detection is missing', () => {
      const rule = makeValidRule();
      (rule as any).detection = undefined;
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('detection')]),
      );
    });

    it('produces error when detection has no condition', () => {
      const rule = makeValidRule({
        detection: {
          selection: { Image: ['*\\cmd.exe'] },
          condition: undefined as any,
        } as any,
      });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('condition')]),
      );
    });

    it('produces error when condition is not a string', () => {
      const rule = makeValidRule({
        detection: {
          selection: { Image: ['*\\cmd.exe'] },
          condition: 123 as any,
        } as any,
      });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('condition')]),
      );
    });

    it('produces error when condition references non-existent key', () => {
      const rule = makeValidRule({
        detection: {
          selection: { Image: ['*\\cmd.exe'] },
          condition: 'selection and filter_legitimate',
        },
      });
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.stringContaining('filter_legitimate'),
        ]),
      );
    });

    it('validates correctly when condition references existing keys', () => {
      const rule = makeValidRule({
        detection: {
          selection: { Image: ['*\\cmd.exe'] },
          filter_legitimate: { User: ['SYSTEM'] },
          condition: 'selection and not filter_legitimate',
        },
      });
      const result = validateSigmaRule(rule);
      expect(
        result.errors.filter((e) => e.includes('does not exist')),
      ).toHaveLength(0);
    });

    it('validates condition with wildcard patterns correctly', () => {
      const rule = makeValidRule({
        detection: {
          selection_main: { Image: ['*\\cmd.exe'] },
          selection_args: { CommandLine: ['*-enc*'] },
          condition: '1 of selection_*',
        },
      });
      const result = validateSigmaRule(rule);
      expect(
        result.errors.filter((e) => e.includes('does not exist') || e.includes('pattern')),
      ).toHaveLength(0);
    });

    it('produces error when wildcard pattern matches no keys', () => {
      const rule = makeValidRule({
        detection: {
          selection: { Image: ['*\\cmd.exe'] },
          condition: '1 of filter_*',
        },
      });
      const result = validateSigmaRule(rule);
      expect(result.errors).toEqual(
        expect.arrayContaining([expect.stringContaining('filter_*')]),
      );
    });

    it('handles complex condition with parentheses', () => {
      const rule = makeValidRule({
        detection: {
          selection_proc: { Image: ['*\\powershell.exe'] },
          selection_cmd: { CommandLine: ['*invoke-*'] },
          filter_admin: { User: ['admin'] },
          condition: '(selection_proc and selection_cmd) and not filter_admin',
        },
      });
      const result = validateSigmaRule(rule);
      expect(
        result.errors.filter((e) => e.includes('does not exist')),
      ).toHaveLength(0);
    });

    it('handles condition with "them" keyword', () => {
      const rule = makeValidRule({
        detection: {
          selection: { Image: ['*\\cmd.exe'] },
          condition: 'all of them',
        },
      });
      const result = validateSigmaRule(rule);
      expect(
        result.errors.filter((e) => e.includes('does not exist')),
      ).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // ATT&CK tag validation
  // -----------------------------------------------------------------------

  describe('ATT&CK tags', () => {
    it('valid ATT&CK tags produce no warnings', () => {
      const rule = makeValidRule({
        tags: ['attack.execution', 'attack.t1059', 'attack.t1059.001'],
      });
      const result = validateSigmaRule(rule);
      expect(
        result.warnings.filter((w) => w.includes('ATT&CK tag')),
      ).toHaveLength(0);
    });

    it('invalid ATT&CK tag format produces warning', () => {
      const rule = makeValidRule({
        tags: ['attack.T1059'],
      });
      const result = validateSigmaRule(rule);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('ATT&CK tag')]),
      );
    });

    it('non-attack tags do not trigger ATT&CK format warnings', () => {
      const rule = makeValidRule({
        tags: ['cve.2024.12345', 'custom.tag'],
      });
      const result = validateSigmaRule(rule);
      expect(
        result.warnings.filter((w) => w.includes('ATT&CK tag')),
      ).toHaveLength(0);
    });

    it('missing tags produces warning', () => {
      const rule = makeValidRule({ tags: [] });
      const result = validateSigmaRule(rule);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('tags')]),
      );
    });

    it('undefined tags produces warning', () => {
      const rule = makeValidRule({ tags: undefined as any });
      const result = validateSigmaRule(rule);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('tags')]),
      );
    });
  });

  // -----------------------------------------------------------------------
  // Additional warnings
  // -----------------------------------------------------------------------

  describe('additional warnings', () => {
    it('missing date produces warning', () => {
      const rule = makeValidRule({ date: '' });
      const result = validateSigmaRule(rule);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('date')]),
      );
    });

    it('missing author produces warning', () => {
      const rule = makeValidRule({ author: '' });
      const result = validateSigmaRule(rule);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('author')]),
      );
    });

    it('whitespace-only author produces warning', () => {
      const rule = makeValidRule({ author: '   ' });
      const result = validateSigmaRule(rule);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('author')]),
      );
    });

    it('missing falsepositives produces warning', () => {
      const rule = makeValidRule({ falsepositives: [] });
      const result = validateSigmaRule(rule);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('false-positive')]),
      );
    });

    it('undefined falsepositives produces warning', () => {
      const rule = makeValidRule({ falsepositives: undefined as any });
      const result = validateSigmaRule(rule);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('false-positive')]),
      );
    });
  });

  // -----------------------------------------------------------------------
  // Multiple errors
  // -----------------------------------------------------------------------

  describe('multiple errors', () => {
    it('accumulates all errors for a completely invalid rule', () => {
      const rule = makeValidRule({
        title: '',
        id: '',
        status: '' as any,
        description: '',
        level: '' as any,
      });
      (rule as any).logsource = undefined;
      (rule as any).detection = undefined;
      const result = validateSigmaRule(rule);
      expect(result.valid).toBe(false);
      // title, id, status, description, level, logsource, detection = 7 errors
      expect(result.errors.length).toBeGreaterThanOrEqual(7);
    });
  });
});

// ===========================================================================
// validateSigmaYaml
// ===========================================================================

describe('validateSigmaYaml', () => {
  const validYaml = `
title: Suspicious Process Creation
id: f47ac10b-58cc-4372-a567-0e02b2c3d479
status: experimental
description: Detects suspicious process creation patterns indicative of malicious activity.
references:
  - https://example.com/report
author: DetectForge
date: "2026/02/10"
modified: "2026/02/10"
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image:
      - '*\\cmd.exe'
    CommandLine:
      - '*-encodedcommand*'
  condition: selection
falsepositives:
  - Legitimate admin scripts
level: high
`;

  it('returns valid result for well-formed YAML', () => {
    const result = validateSigmaYaml(validYaml);
    expect(result.valid).toBe(true);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('returns syntaxValid=false for unparseable YAML', () => {
    const badYaml = `
title: Test Rule
  id: broken indentation
    status: experimental
logsource:
- this: is wrong
  detection:
    condition: [[[invalid
`;
    const result = validateSigmaYaml(badYaml);
    expect(result.valid).toBe(false);
    expect(result.syntaxValid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('YAML parsing failed');
  });

  it('returns schemaValid=false for non-object YAML (string)', () => {
    const stringYaml = '"just a string"';
    const result = validateSigmaYaml(stringYaml);
    expect(result.valid).toBe(false);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([expect.stringContaining('not a valid Sigma rule object')]),
    );
  });

  it('returns schemaValid=false for array YAML', () => {
    const arrayYaml = `
- item1
- item2
- item3
`;
    const result = validateSigmaYaml(arrayYaml);
    expect(result.valid).toBe(false);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([expect.stringContaining('not a valid Sigma rule object')]),
    );
  });

  it('returns schemaValid=false for null YAML', () => {
    const result = validateSigmaYaml('null');
    expect(result.valid).toBe(false);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(false);
  });

  it('returns schemaValid=false for numeric YAML', () => {
    const result = validateSigmaYaml('42');
    expect(result.valid).toBe(false);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(false);
  });

  it('delegates structural validation to validateSigmaRule for valid YAML objects', () => {
    // YAML is valid but the rule is structurally incomplete (missing title, id, etc.)
    const incompleteYaml = `
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: '*\\cmd.exe'
  condition: selection
`;
    const result = validateSigmaYaml(incompleteYaml);
    expect(result.valid).toBe(false);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(false);
    // Should have structural errors from validateSigmaRule
    expect(result.errors).toEqual(
      expect.arrayContaining([expect.stringContaining('title')]),
    );
  });

  it('propagates warnings from structural validation', () => {
    // Valid YAML and structurally valid rule but missing optional fields that produce warnings
    const yamlWithoutOptionals = `
title: Suspicious Process Creation via cmd.exe
id: f47ac10b-58cc-4372-a567-0e02b2c3d479
status: experimental
description: Detects suspicious process creation patterns indicative of malicious activity.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image:
      - '*\\cmd.exe'
  condition: selection
level: high
`;
    const result = validateSigmaYaml(yamlWithoutOptionals);
    // Should still be valid since warnings don't make it invalid
    expect(result.valid).toBe(true);
    // But should have warnings about missing date, author, falsepositives, tags
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  it('handles empty string gracefully', () => {
    const result = validateSigmaYaml('');
    // Empty string parses to undefined/null in YAML
    expect(result.valid).toBe(false);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(false);
  });

  it('handles YAML with only comments', () => {
    const result = validateSigmaYaml('# just a comment\n# another comment\n');
    expect(result.valid).toBe(false);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(false);
  });

  it('correctly parses condition references from YAML', () => {
    const yamlBadCondition = `
title: Test Rule With Bad Condition Reference
id: f47ac10b-58cc-4372-a567-0e02b2c3d479
status: experimental
description: This rule has a condition that references a non-existent detection key.
author: DetectForge
date: "2026/02/10"
tags:
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image:
      - '*\\cmd.exe'
  condition: selection and nonexistent_filter
falsepositives:
  - None known
level: high
`;
    const result = validateSigmaYaml(yamlBadCondition);
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([expect.stringContaining('nonexistent_filter')]),
    );
  });
});
