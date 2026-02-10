import { describe, it, expect } from 'vitest';
import {
  validateYaraRule,
  validateYaraRaw,
} from '@/generation/yara/validator.js';
import type { YaraRule, ValidationResult } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal valid YaraRule object for testing.
 * Override any field via the `overrides` parameter.
 */
function makeValidRule(overrides: Partial<YaraRule> = {}): YaraRule {
  return {
    name: 'Test_Rule',
    tags: ['malware', 'trojan'],
    meta: {
      description: 'Detects test malware',
      author: 'DetectForge',
      date: '2026-02-10',
      reference: 'https://example.com',
      mitre_attack: 'T1059.001',
    },
    strings: [
      {
        identifier: '$s1',
        value: 'VirtualAlloc',
        type: 'text',
        modifiers: ['ascii', 'wide'],
      },
      {
        identifier: '$hex1',
        value: '4D 5A 90 00',
        type: 'hex',
        modifiers: [],
      },
    ],
    condition: 'uint16(0) == 0x5A4D and all of ($s*)',
    raw: 'rule Test_Rule { ... }',
    ...overrides,
  };
}

/**
 * Build a minimal valid raw YARA rule string for testing.
 */
function makeValidRaw(): string {
  return `rule Test_Rule : malware trojan
{
    meta:
        description = "Detects test malware"
        author = "DetectForge"
        date = "2026-02-10"
        reference = "https://example.com"
        mitre_attack = "T1059.001"

    strings:
        $s1 = "VirtualAlloc" ascii wide
        $hex1 = { 4D 5A 90 00 }

    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}`;
}

// ===========================================================================
// validateYaraRule
// ===========================================================================

describe('validateYaraRule', () => {
  // ---- Happy path ----

  it('passes validation for a well-formed rule', () => {
    const result = validateYaraRule(makeValidRule());
    expect(result.valid).toBe(true);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // ---- Rule name ----

  it('errors when rule name starts with a number', () => {
    const result = validateYaraRule(makeValidRule({ name: '1Invalid' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Invalid rule name'))).toBe(true);
  });

  it('errors when rule name contains spaces', () => {
    const result = validateYaraRule(makeValidRule({ name: 'Invalid Rule' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Invalid rule name'))).toBe(true);
  });

  it('errors when rule name is empty', () => {
    const result = validateYaraRule(makeValidRule({ name: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Invalid rule name'))).toBe(true);
  });

  it('accepts rule name starting with underscore', () => {
    const result = validateYaraRule(makeValidRule({ name: '_private_rule' }));
    expect(result.valid).toBe(true);
  });

  // ---- Required meta fields ----

  it('errors when description meta is missing', () => {
    const rule = makeValidRule();
    rule.meta.description = '';
    const result = validateYaraRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('"description"'))).toBe(true);
  });

  it('errors when author meta is missing', () => {
    const rule = makeValidRule();
    rule.meta.author = '';
    const result = validateYaraRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('"author"'))).toBe(true);
  });

  it('errors when date meta is missing', () => {
    const rule = makeValidRule();
    rule.meta.date = '';
    const result = validateYaraRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('"date"'))).toBe(true);
  });

  it('errors when multiple required meta fields are missing', () => {
    const rule = makeValidRule();
    rule.meta.description = '';
    rule.meta.author = '';
    rule.meta.date = '';
    const result = validateYaraRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(3);
  });

  // ---- Date format warning ----

  it('warns when date is not in YYYY-MM-DD format', () => {
    const rule = makeValidRule();
    rule.meta.date = '02/10/2026';
    const result = validateYaraRule(rule);
    // Not an error, just a warning
    expect(result.valid).toBe(true);
    expect(result.warnings.some((w) => w.includes('YYYY-MM-DD'))).toBe(true);
  });

  it('does not warn for valid YYYY-MM-DD date format', () => {
    const result = validateYaraRule(makeValidRule());
    expect(result.warnings.some((w) => w.includes('YYYY-MM-DD'))).toBe(false);
  });

  // ---- Strings section ----

  it('errors when strings array is empty', () => {
    const result = validateYaraRule(makeValidRule({ strings: [] }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('at least one string'))).toBe(true);
  });

  // ---- String identifiers ----

  it('errors when string identifier does not start with $', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: 's1', value: 'test', type: 'text', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Invalid string identifier'))).toBe(true);
  });

  it('errors when string identifier starts with $number', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$1abc', value: 'test', type: 'text', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Invalid string identifier'))).toBe(true);
  });

  it('accepts valid string identifiers', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: 'test', type: 'text', modifiers: [] },
          { identifier: '$_private', value: 'test2', type: 'text', modifiers: [] },
          { identifier: '$abc_123', value: 'test3', type: 'text', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.errors.filter((e) => e.includes('Invalid string identifier'))).toHaveLength(0);
  });

  // ---- Duplicate string identifiers ----

  it('errors when there are duplicate string identifiers', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: 'first', type: 'text', modifiers: [] },
          { identifier: '$s1', value: 'second', type: 'text', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Duplicate string identifier'))).toBe(true);
  });

  // ---- Empty string value ----

  it('errors when string value is empty', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: '', type: 'text', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('empty value'))).toBe(true);
  });

  it('errors when string value is whitespace only', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: '   ', type: 'text', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('empty value'))).toBe(true);
  });

  // ---- Invalid string type ----

  it('errors when string type is not text/hex/regex', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: 'test', type: 'binary' as any, modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('invalid type'))).toBe(true);
  });

  // ---- Hex string validation ----

  it('errors when hex string contains invalid characters', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$hex1', value: '4D 5A GG ZZ', type: 'hex', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('invalid characters'))).toBe(true);
  });

  it('accepts valid hex string with wildcards and jumps', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$hex1', value: '4D 5A ?? 00 [4-6] (AA | BB)', type: 'hex', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.errors.filter((e) => e.includes('invalid characters'))).toHaveLength(0);
  });

  it('accepts valid hex string with only hex pairs', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$hex1', value: 'AABBCCDD', type: 'hex', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.errors.filter((e) => e.includes('Hex string'))).toHaveLength(0);
  });

  it('accepts hex string with lowercase characters', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$hex1', value: '4d 5a 90 00', type: 'hex', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.errors.filter((e) => e.includes('Hex string'))).toHaveLength(0);
  });

  // ---- Text string modifier validation ----

  it('warns when text string has an unknown modifier', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: 'test', type: 'text', modifiers: ['ascii', 'bogus_mod'] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.warnings.some((w) => w.includes('unknown modifier'))).toBe(true);
    expect(result.warnings.some((w) => w.includes('bogus_mod'))).toBe(true);
  });

  it('does not warn for valid text modifiers', () => {
    const validMods = ['ascii', 'wide', 'nocase', 'fullword', 'xor', 'base64', 'base64wide', 'private'];
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: 'test', type: 'text', modifiers: validMods },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.warnings.filter((w) => w.includes('unknown modifier'))).toHaveLength(0);
  });

  // ---- Condition ----

  it('errors when condition is empty', () => {
    const result = validateYaraRule(makeValidRule({ condition: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Condition must not be empty'))).toBe(true);
  });

  it('errors when condition is whitespace only', () => {
    const result = validateYaraRule(makeValidRule({ condition: '   ' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Condition must not be empty'))).toBe(true);
  });

  // ---- Condition references undefined string identifier (warning) ----

  it('warns when condition references an undefined string identifier', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: 'test', type: 'text', modifiers: [] },
        ],
        condition: '$s1 and $s2',
      }),
    );
    // $s2 is not defined
    expect(result.warnings.some((w) => w.includes('$s2') && w.includes('not defined'))).toBe(true);
  });

  it('does not warn when condition references only defined strings', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: 'test', type: 'text', modifiers: [] },
          { identifier: '$s2', value: 'test2', type: 'text', modifiers: [] },
        ],
        condition: '$s1 and $s2',
      }),
    );
    expect(result.warnings.filter((w) => w.includes('not defined'))).toHaveLength(0);
  });

  it('does not warn when condition uses "any of them" without explicit identifiers', () => {
    const result = validateYaraRule(
      makeValidRule({
        strings: [
          { identifier: '$s1', value: 'test', type: 'text', modifiers: [] },
        ],
        condition: 'any of them',
      }),
    );
    expect(result.warnings.filter((w) => w.includes('not defined'))).toHaveLength(0);
  });

  // ---- Tags ----

  it('warns when a tag contains invalid characters', () => {
    const result = validateYaraRule(
      makeValidRule({
        tags: ['valid_tag', 'invalid-tag', 'also invalid'],
      }),
    );
    expect(result.warnings.some((w) => w.includes('invalid-tag'))).toBe(true);
    expect(result.warnings.some((w) => w.includes('also invalid'))).toBe(true);
  });

  it('does not warn for valid tags', () => {
    const result = validateYaraRule(
      makeValidRule({
        tags: ['malware', 'trojan', 'apt29', '_internal'],
      }),
    );
    expect(result.warnings.filter((w) => w.includes('invalid characters'))).toHaveLength(0);
  });

  // ---- Multiple errors accumulate ----

  it('accumulates multiple errors for a badly formed rule', () => {
    const result = validateYaraRule({
      name: '123bad',
      tags: [],
      meta: {
        description: '',
        author: '',
        date: '',
        reference: '',
        mitre_attack: '',
      },
      strings: [],
      condition: '',
      raw: '',
    });
    expect(result.valid).toBe(false);
    // At minimum: invalid name, 3 missing meta fields, no strings, empty condition
    expect(result.errors.length).toBeGreaterThanOrEqual(6);
  });

  // ---- ValidationResult structure ----

  it('returns correct ValidationResult structure', () => {
    const result = validateYaraRule(makeValidRule());
    expect(result).toHaveProperty('valid');
    expect(result).toHaveProperty('syntaxValid');
    expect(result).toHaveProperty('schemaValid');
    expect(result).toHaveProperty('errors');
    expect(result).toHaveProperty('warnings');
    expect(typeof result.valid).toBe('boolean');
    expect(typeof result.syntaxValid).toBe('boolean');
    expect(typeof result.schemaValid).toBe('boolean');
    expect(Array.isArray(result.errors)).toBe(true);
    expect(Array.isArray(result.warnings)).toBe(true);
  });
});

// ===========================================================================
// validateYaraRaw
// ===========================================================================

describe('validateYaraRaw', () => {
  // ---- Happy path ----

  it('passes validation for a well-formed raw YARA rule', () => {
    const result = validateYaraRaw(makeValidRaw());
    expect(result.valid).toBe(true);
    expect(result.syntaxValid).toBe(true);
    expect(result.schemaValid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // ---- Missing "rule" keyword ----

  it('errors when raw text does not start with "rule" keyword', () => {
    const raw = `
{
    meta:
        description = "Test"
    strings:
        $s1 = "test"
    condition:
        $s1
}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('"rule" keyword'))).toBe(true);
  });

  it('errors when raw text is completely unrelated', () => {
    const result = validateYaraRaw('This is not a YARA rule at all.');
    expect(result.valid).toBe(false);
  });

  // ---- Missing sections ----

  it('errors when meta: section is missing', () => {
    const raw = `rule Test_Rule
{
    strings:
        $s1 = "test"
    condition:
        $s1
}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('meta:'))).toBe(true);
  });

  it('errors when strings: section is missing', () => {
    const raw = `rule Test_Rule
{
    meta:
        description = "Test"
        author = "DetectForge"
        date = "2026-02-10"
    condition:
        filesize < 1MB
}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('strings:'))).toBe(true);
  });

  it('errors when condition: section is missing', () => {
    const raw = `rule Test_Rule
{
    meta:
        description = "Test"
        author = "DetectForge"
        date = "2026-02-10"
    strings:
        $s1 = "test"
}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('condition:'))).toBe(true);
  });

  // ---- Unbalanced braces ----

  it('errors when curly braces are not balanced (missing closing)', () => {
    const raw = `rule Test_Rule
{
    meta:
        description = "Test"
        author = "DetectForge"
        date = "2026-02-10"
    strings:
        $s1 = "test"
    condition:
        $s1`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Unbalanced curly braces'))).toBe(true);
  });

  it('errors when there is an extra closing brace', () => {
    const raw = `rule Test_Rule
{
    meta:
        description = "Test"
        author = "DetectForge"
        date = "2026-02-10"
    strings:
        $s1 = "test"
    condition:
        $s1
}}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Unbalanced curly braces'))).toBe(true);
  });

  // ---- Invalid rule name ----

  it('errors when rule name in raw text is invalid (starts with number)', () => {
    const raw = `rule 123Invalid
{
    meta:
        description = "Test"
        author = "DetectForge"
        date = "2026-02-10"
    strings:
        $s1 = "test"
    condition:
        $s1
}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Invalid rule name'))).toBe(true);
  });

  it('errors when rule name contains special characters', () => {
    const raw = `rule Bad-Name!
{
    meta:
        description = "Test"
        author = "DetectForge"
        date = "2026-02-10"
    strings:
        $s1 = "test"
    condition:
        $s1
}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Invalid rule name'))).toBe(true);
  });

  // ---- Strings section without $identifier ----

  it('errors when strings section has no $identifier', () => {
    const raw = `rule Test_Rule
{
    meta:
        description = "Test"
        author = "DetectForge"
        date = "2026-02-10"
    strings:
        // no strings here
    condition:
        filesize < 1MB
}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    expect(
      result.errors.some((e) => e.includes('string definitions')),
    ).toBe(true);
  });

  // ---- Meta field warnings ----

  it('warns when author is missing from meta section', () => {
    const raw = `rule Test_Rule
{
    meta:
        description = "Test"
        date = "2026-02-10"
    strings:
        $s1 = "test"
    condition:
        $s1
}`;
    const result = validateYaraRaw(raw);
    expect(result.warnings.some((w) => w.includes('author'))).toBe(true);
  });

  it('warns when description is missing from meta section', () => {
    const raw = `rule Test_Rule
{
    meta:
        author = "DetectForge"
        date = "2026-02-10"
    strings:
        $s1 = "test"
    condition:
        $s1
}`;
    const result = validateYaraRaw(raw);
    expect(result.warnings.some((w) => w.includes('description'))).toBe(true);
  });

  it('warns when date is missing from meta section', () => {
    const raw = `rule Test_Rule
{
    meta:
        description = "Test"
        author = "DetectForge"
    strings:
        $s1 = "test"
    condition:
        $s1
}`;
    const result = validateYaraRaw(raw);
    expect(result.warnings.some((w) => w.includes('date'))).toBe(true);
  });

  it('produces all three meta field warnings when all are missing', () => {
    const raw = `rule Test_Rule
{
    meta:
        reference = "https://example.com"
    strings:
        $s1 = "test"
    condition:
        $s1
}`;
    const result = validateYaraRaw(raw);
    expect(result.warnings.some((w) => w.includes('author'))).toBe(true);
    expect(result.warnings.some((w) => w.includes('description'))).toBe(true);
    expect(result.warnings.some((w) => w.includes('date'))).toBe(true);
  });

  it('produces no meta warnings when all fields are present', () => {
    const result = validateYaraRaw(makeValidRaw());
    const metaWarnings = result.warnings.filter(
      (w) => w.includes('author') || w.includes('description') || w.includes('date'),
    );
    expect(metaWarnings).toHaveLength(0);
  });

  // ---- ValidationResult structure ----

  it('returns correct ValidationResult structure', () => {
    const result = validateYaraRaw(makeValidRaw());
    expect(result).toHaveProperty('valid');
    expect(result).toHaveProperty('syntaxValid');
    expect(result).toHaveProperty('schemaValid');
    expect(result).toHaveProperty('errors');
    expect(result).toHaveProperty('warnings');
    expect(typeof result.valid).toBe('boolean');
    expect(Array.isArray(result.errors)).toBe(true);
    expect(Array.isArray(result.warnings)).toBe(true);
  });

  // ---- Edge cases ----

  it('handles empty string input', () => {
    const result = validateYaraRaw('');
    expect(result.valid).toBe(false);
  });

  it('handles rule with tags in raw format', () => {
    const raw = `rule Test_Rule : apt malware
{
    meta:
        description = "Test"
        author = "DetectForge"
        date = "2026-02-10"
    strings:
        $s1 = "test"
    condition:
        $s1
}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('accumulates multiple errors for severely malformed raw text', () => {
    const raw = `not_a_rule 123bad {}}`;
    const result = validateYaraRaw(raw);
    expect(result.valid).toBe(false);
    // Should have errors for: missing rule keyword, missing meta/strings/condition, unbalanced braces
    expect(result.errors.length).toBeGreaterThanOrEqual(3);
  });
});
