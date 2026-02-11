/**
 * Unit tests for the field validator.
 */

import { describe, it, expect } from 'vitest';
import { validateRuleFields, extractDetectionFields } from '@/testing/field-validator.js';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(
  detection: Record<string, unknown> & { condition: string },
  overrides: Partial<SigmaRule> = {},
): SigmaRule {
  return {
    id: 'fv-test-0001-0000-000000000001',
    title: 'Field Validator Test Rule',
    status: 'experimental',
    description: 'A test rule for field validation.',
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
// extractDetectionFields
// ===========================================================================

describe('extractDetectionFields', () => {
  it('extracts field names from a simple selection', () => {
    const detection = {
      selection: {
        Image: '*\\cmd.exe',
        CommandLine: '*whoami*',
      },
      condition: 'selection',
    };

    const fields = extractDetectionFields(detection);
    expect(fields).toContain('Image');
    expect(fields).toContain('CommandLine');
    expect(fields).not.toContain('condition');
  });

  it('strips Sigma modifiers from field keys', () => {
    const detection = {
      selection: {
        'CommandLine|contains': 'whoami',
        'Image|endswith': '\\cmd.exe',
      },
      condition: 'selection',
    };

    const fields = extractDetectionFields(detection);
    expect(fields).toContain('CommandLine');
    expect(fields).toContain('Image');
    expect(fields).not.toContain('CommandLine|contains');
  });

  it('handles multiple selections and filters', () => {
    const detection = {
      selection_proc: { Image: '*\\cmd.exe' },
      selection_args: { CommandLine: '*whoami*' },
      filter_system: { User: 'SYSTEM' },
      condition: 'selection_proc and selection_args and not filter_system',
    };

    const fields = extractDetectionFields(detection);
    expect(fields).toContain('Image');
    expect(fields).toContain('CommandLine');
    expect(fields).toContain('User');
  });

  it('handles array-of-maps (list selections)', () => {
    const detection = {
      selection: [
        { Image: '*\\cmd.exe', CommandLine: '*whoami*' },
        { Image: '*\\powershell.exe', 'CommandLine|contains': 'Invoke-' },
      ],
      condition: 'selection',
    };

    const fields = extractDetectionFields(detection);
    expect(fields).toContain('Image');
    expect(fields).toContain('CommandLine');
  });

  it('deduplicates fields used in multiple selections', () => {
    const detection = {
      selection_a: { Image: '*\\cmd.exe' },
      selection_b: { Image: '*\\powershell.exe' },
      condition: 'selection_a or selection_b',
    };

    const fields = extractDetectionFields(detection);
    const imageCount = fields.filter((f) => f === 'Image').length;
    expect(imageCount).toBe(1);
  });

  it('handles empty detection gracefully', () => {
    const detection = { condition: 'selection' };
    const fields = extractDetectionFields(detection);
    expect(fields).toHaveLength(0);
  });
});

// ===========================================================================
// validateRuleFields
// ===========================================================================

describe('validateRuleFields', () => {
  it('marks valid process_creation fields as valid', () => {
    const rule = makeRule({
      selection: {
        Image: '*\\cmd.exe',
        CommandLine: '*whoami*',
        ParentImage: '*\\explorer.exe',
      },
      condition: 'selection',
    });

    const result = validateRuleFields(rule);
    expect(result.unknownLogsource).toBe(false);
    expect(result.validFields).toContain('Image');
    expect(result.validFields).toContain('CommandLine');
    expect(result.validFields).toContain('ParentImage');
    expect(result.invalidFields).toHaveLength(0);
    expect(result.fieldValidityRate).toBe(1);
  });

  it('detects fields not in the logsource catalog', () => {
    const rule = makeRule({
      selection: {
        Image: '*\\cmd.exe',
        IpAddress: '192.168.1.1', // Not a process_creation field
        QueryName: 'evil.com', // DNS field, not process_creation
      },
      condition: 'selection',
    });

    const result = validateRuleFields(rule);
    expect(result.unknownLogsource).toBe(false);
    expect(result.invalidFields).toContain('IpAddress');
    expect(result.invalidFields).toContain('QueryName');
    expect(result.validFields).toContain('Image');
    expect(result.fieldValidityRate).toBeCloseTo(1 / 3, 1);
  });

  it('strips modifiers before validating field names', () => {
    const rule = makeRule({
      selection: {
        'CommandLine|contains|all': ['whoami', 'ipconfig'],
        'Image|endswith': '\\cmd.exe',
      },
      condition: 'selection',
    });

    const result = validateRuleFields(rule);
    expect(result.validFields).toContain('CommandLine');
    expect(result.validFields).toContain('Image');
    expect(result.invalidFields).toHaveLength(0);
  });

  it('returns unknownLogsource for cloud/non-catalog products', () => {
    const rule = makeRule(
      {
        selection: { eventName: 'ConsoleLogin' },
        condition: 'selection',
      },
      {
        logsource: { product: 'aws', service: 'cloudtrail' },
      },
    );

    const result = validateRuleFields(rule);
    expect(result.unknownLogsource).toBe(true);
    expect(result.fieldValidityRate).toBe(1);
    expect(result.invalidFields).toHaveLength(0);
  });

  it('returns unknownLogsource when product is missing', () => {
    const rule = makeRule(
      {
        selection: { SomeField: 'value' },
        condition: 'selection',
      },
      {
        logsource: { category: 'proxy' },
      },
    );

    const result = validateRuleFields(rule);
    expect(result.unknownLogsource).toBe(true);
  });

  it('handles security logsource fields (IpAddress, LogonType, Status)', () => {
    const rule = makeRule(
      {
        selection: {
          IpAddress: '198.51.100.42',
          LogonType: 10,
          Status: '0xc000006d',
        },
        condition: 'selection',
      },
      {
        logsource: { product: 'windows', service: 'security' },
      },
    );

    const result = validateRuleFields(rule);
    expect(result.unknownLogsource).toBe(false);
    expect(result.validFields).toContain('IpAddress');
    expect(result.validFields).toContain('LogonType');
    expect(result.validFields).toContain('Status');
    expect(result.invalidFields).toHaveLength(0);
  });

  it('handles registry_event fields', () => {
    const rule = makeRule(
      {
        selection: {
          TargetObject: 'HKLM\\SOFTWARE\\*',
          Details: '*\\malware.exe',
          Image: '*\\reg.exe',
        },
        condition: 'selection',
      },
      {
        logsource: { product: 'windows', category: 'registry_set' },
      },
    );

    const result = validateRuleFields(rule);
    expect(result.unknownLogsource).toBe(false);
    // These are all valid registry_event fields
    expect(result.validFields.length).toBeGreaterThanOrEqual(2);
  });

  it('handles rule with no detection fields gracefully', () => {
    const rule = makeRule({
      condition: 'selection',
    });

    const result = validateRuleFields(rule);
    expect(result.allDetectionFields).toHaveLength(0);
    expect(result.fieldValidityRate).toBe(1);
  });
});
