/**
 * Unit tests for the SARIF reporter.
 *
 * Tests: generateSarifReport, writeSarifReport
 *
 * Note: The source file (src/reporting/sarif-reporter.ts) is being written
 * concurrently by another agent. These tests target the expected interface.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { writeFileSync, mkdirSync } from 'fs';
import {
  generateSarifReport,
  writeSarifReport,
} from '@/reporting/sarif-reporter.js';
import type { GeneratedRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('fs', async () => {
  const actual = await vi.importActual('fs');
  return {
    ...actual,
    writeFileSync: vi.fn(),
    mkdirSync: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Fixture Builders
// ---------------------------------------------------------------------------

function makeRule(overrides?: Partial<GeneratedRule>): GeneratedRule {
  return {
    format: 'sigma',
    sigma: {
      id: 'abc-123',
      title: 'Suspicious PowerShell Download Cradle',
      status: 'experimental',
      description: 'Detects PowerShell download cradle.',
      references: [],
      author: 'DetectForge',
      date: '2026-02-10',
      modified: '2026-02-10',
      tags: ['attack.execution', 'attack.t1059.001'],
      logsource: { product: 'windows', category: 'process_creation' },
      detection: { selection: { Image: ['*\\powershell.exe'] }, condition: 'selection' },
      falsepositives: ['Admin scripts'],
      level: 'high',
      raw: 'title: Suspicious PowerShell Download Cradle',
    },
    sourceReportId: 'report-1',
    attackTechniqueId: 'T1059.001',
    attackTactic: 'execution',
    confidence: 'high',
    validation: { valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] },
    ...overrides,
  };
}

/** Default input file path used throughout tests. */
const DEFAULT_INPUT_FILE = 'apt29-report.pdf';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

describe('generateSarifReport', () => {
  it('returns a SARIF v2.1.0 conformant object', () => {
    const rules = [makeRule()];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    expect(sarif).toBeDefined();
    expect(sarif.version).toBe('2.1.0');
  });

  it('has $schema field pointing to SARIF schema', () => {
    const rules = [makeRule()];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    expect(sarif.$schema).toBeDefined();
    expect(sarif.$schema).toContain('sarif');
  });

  it('has version "2.1.0"', () => {
    const rules = [makeRule()];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    expect(sarif.version).toBe('2.1.0');
  });

  it('has runs array with one run', () => {
    const rules = [makeRule()];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs).toHaveLength(1);
  });

  it('run has tool.driver.name "DetectForge"', () => {
    const rules = [makeRule()];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('DetectForge');
  });

  it('has one result per generated rule', () => {
    const rules = [
      makeRule(),
      makeRule({
        format: 'yara',
        sigma: undefined,
        yara: {
          name: 'APT29_Dropper',
          tags: ['apt29'],
          meta: {
            description: 'Detects APT29 dropper',
            author: 'DetectForge',
            date: '2026-02-10',
            reference: 'https://example.com',
            mitre_attack: 'T1059.001',
          },
          strings: [{ identifier: '$s1', value: 'malware', type: 'text', modifiers: [] }],
          condition: '$s1',
          raw: 'rule APT29_Dropper { condition: $s1 }',
        },
        validation: { valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] },
      }),
    ];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it('valid rules have level "note"', () => {
    const rules = [
      makeRule({ validation: { valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] } }),
    ];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    const result = sarif.runs[0].results[0];
    expect(result.level).toBe('note');
  });

  it('invalid rules have level "error"', () => {
    const rules = [
      makeRule({
        validation: {
          valid: false,
          syntaxValid: false,
          schemaValid: false,
          errors: ['Missing condition'],
          warnings: [],
        },
      }),
    ];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    const result = sarif.runs[0].results[0];
    expect(result.level).toBe('error');
  });

  it('rules with warnings have level "warning"', () => {
    const rules = [
      makeRule({
        validation: {
          valid: true,
          syntaxValid: true,
          schemaValid: true,
          errors: [],
          warnings: ['Missing author field'],
        },
      }),
    ];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    const result = sarif.runs[0].results[0];
    expect(result.level).toBe('warning');
  });

  it('result ruleId contains technique ID when available', () => {
    const rules = [makeRule({ attackTechniqueId: 'T1059.001' })];
    const sarif = generateSarifReport(rules, DEFAULT_INPUT_FILE);
    const result = sarif.runs[0].results[0];
    expect(result.ruleId).toContain('T1059.001');
  });
});

describe('writeSarifReport', () => {
  it('writes valid JSON to file', () => {
    const rules = [makeRule()];
    writeSarifReport(rules, DEFAULT_INPUT_FILE, '/tmp/output/report.sarif');

    expect(writeFileSync).toHaveBeenCalledTimes(1);
    const writtenContent = (writeFileSync as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
    // The written content should be valid JSON
    expect(() => JSON.parse(writtenContent)).not.toThrow();
    const parsed = JSON.parse(writtenContent);
    expect(parsed.version).toBe('2.1.0');
  });
});
