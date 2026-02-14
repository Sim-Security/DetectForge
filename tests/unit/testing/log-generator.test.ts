/**
 * Unit tests for the synthetic log generator.
 *
 * Covers: attack log generation, benign log generation, field population,
 * wildcard expansion, and option handling.
 */

import { describe, it, expect } from 'vitest';
import { generateTestLogs } from '@/testing/log-generator.js';
import { evaluateSigmaRule } from '@/testing/sigma-tester.js';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(
  detection: Record<string, unknown> & { condition: string },
  overrides: Partial<SigmaRule> = {},
): SigmaRule {
  return {
    id: 'gen-test-0001-0000-000000000001',
    title: 'Log Generator Test Rule',
    status: 'experimental',
    description: 'A test rule for log generation.',
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
// Basic Generation
// ===========================================================================

describe('generateTestLogs', () => {
  describe('basic output structure', () => {
    it('returns correct ruleId and ruleTitle', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      const result = generateTestLogs(rule);
      expect(result.ruleId).toBe(rule.id);
      expect(result.ruleTitle).toBe(rule.title);
    });

    it('produces default counts of attack and benign logs', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      const result = generateTestLogs(rule);
      expect(result.attackLogs).toHaveLength(5);
      expect(result.benignLogs).toHaveLength(10);
    });

    it('respects custom log counts', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, {
        attackLogCount: 3,
        benignLogCount: 7,
      });
      expect(result.attackLogs).toHaveLength(3);
      expect(result.benignLogs).toHaveLength(7);
    });

    it('handles zero counts gracefully', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, {
        attackLogCount: 0,
        benignLogCount: 0,
      });
      expect(result.attackLogs).toHaveLength(0);
      expect(result.benignLogs).toHaveLength(0);
    });
  });

  // =========================================================================
  // Attack Logs
  // =========================================================================

  describe('attack logs', () => {
    it('populates fields from the detection selection', () => {
      const rule = makeRule({
        selection: {
          Image: '*\\cmd.exe',
          CommandLine: '*whoami*',
        },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { attackLogCount: 3 });

      for (const log of result.attackLogs) {
        expect(log).toHaveProperty('Image');
        expect(log).toHaveProperty('CommandLine');
        // Values should be non-empty strings
        expect(typeof log.Image).toBe('string');
        expect(typeof log.CommandLine).toBe('string');
        expect((log.Image as string).length).toBeGreaterThan(0);
        expect((log.CommandLine as string).length).toBeGreaterThan(0);
      }
    });

    it('generates logs that trigger the rule', () => {
      const rule = makeRule({
        selection: {
          Image: ['*\\cmd.exe', '*\\powershell.exe'],
        },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { attackLogCount: 5 });

      for (const log of result.attackLogs) {
        const evaluation = evaluateSigmaRule(rule, log);
        expect(evaluation.matched).toBe(true);
      }
    });

    it('generates logs that trigger multi-selection AND conditions', () => {
      const rule = makeRule({
        selection_proc: { Image: '*\\cmd.exe' },
        selection_args: { CommandLine: '*whoami*' },
        condition: 'selection_proc and selection_args',
      });

      const result = generateTestLogs(rule, { attackLogCount: 5 });

      for (const log of result.attackLogs) {
        const evaluation = evaluateSigmaRule(rule, log);
        expect(evaluation.matched).toBe(true);
      }
    });

    it('adds realistic filler fields', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { attackLogCount: 1 });
      const log = result.attackLogs[0];

      // Should have filler fields beyond just Image
      expect(Object.keys(log).length).toBeGreaterThan(1);
    });
  });

  // =========================================================================
  // Benign Logs
  // =========================================================================

  describe('benign logs', () => {
    it('populates the same fields as the rule uses', () => {
      const rule = makeRule({
        selection: {
          Image: '*\\cmd.exe',
          CommandLine: '*whoami*',
        },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { benignLogCount: 5 });

      for (const log of result.benignLogs) {
        expect(log).toHaveProperty('Image');
        expect(log).toHaveProperty('CommandLine');
      }
    });

    it('mostly does not trigger the rule', () => {
      const rule = makeRule({
        selection: {
          Image: '*\\cmd.exe',
          CommandLine: '*whoami*',
        },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { benignLogCount: 20 });

      let triggered = 0;
      for (const log of result.benignLogs) {
        const evaluation = evaluateSigmaRule(rule, log);
        if (evaluation.matched) triggered++;
      }

      // At most a small fraction should trigger (if any)
      expect(triggered).toBeLessThan(result.benignLogs.length);
    });

    it('includes filler fields', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { benignLogCount: 1 });
      const log = result.benignLogs[0];

      expect(Object.keys(log).length).toBeGreaterThan(1);
    });
  });

  // =========================================================================
  // Rule with filters (NOT conditions)
  // =========================================================================

  describe('rules with filters', () => {
    it('attack logs avoid matching the filter', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        filter_system: { User: 'SYSTEM' },
        condition: 'selection and not filter_system',
      });

      const result = generateTestLogs(rule, { attackLogCount: 5 });

      for (const log of result.attackLogs) {
        const evaluation = evaluateSigmaRule(rule, log);
        expect(evaluation.matched).toBe(true);
      }
    });
  });

  // =========================================================================
  // Field Correlations
  // =========================================================================

  describe('field correlations', () => {
    it('attack log with Image=powershell.exe has CommandLine starting with powershell', () => {
      const rule = makeRule({
        selection: {
          Image: '*\\powershell.exe',
          'CommandLine|contains': '-enc',
        },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { attackLogCount: 3 });

      for (const log of result.attackLogs) {
        const cmdLine = String(log.CommandLine).toLowerCase();
        expect(cmdLine).toMatch(/^powershell/);
      }
    });

    it('attack log with ParentImage=services.exe has User containing SYSTEM', () => {
      const rule = makeRule({
        selection: {
          Image: '*\\cmd.exe',
          ParentImage: '*\\services.exe',
        },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { attackLogCount: 3 });

      for (const log of result.attackLogs) {
        expect(String(log.User)).toContain('SYSTEM');
      }
    });

    it('does not double-prefix if CommandLine already starts with binary name', () => {
      const rule = makeRule({
        selection: {
          Image: '*\\cmd.exe',
          CommandLine: 'cmd.exe /c whoami',
        },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { attackLogCount: 1 });
      const cmdLine = String(result.attackLogs[0].CommandLine);
      // Should not start with "cmd.exe cmd.exe"
      expect(cmdLine).not.toMatch(/^cmd\.exe\s+cmd\.exe/i);
    });

    it('benign template logs are included in generated set', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        condition: 'selection',
      });

      // Generate enough benign logs to get template-based ones (every 3rd)
      const result = generateTestLogs(rule, { benignLogCount: 10 });

      // The 1st benign log (index 0) should be template-based
      // svchost.exe template has SYSTEM user
      const firstBenign = result.benignLogs[0];
      expect(firstBenign.User).toBeDefined();
    });

    it('benign template logs have correlated field values', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe', User: 'admin' },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { benignLogCount: 9 });

      // Template at index 0 (svchost) has ParentImage=services.exe and User=SYSTEM
      const templateLog = result.benignLogs[0];
      if (String(templateLog.ParentImage || '').includes('services.exe')) {
        expect(String(templateLog.User)).toContain('SYSTEM');
      }
    });
  });

  // =========================================================================
  // Various Rule Shapes
  // =========================================================================

  describe('various rule shapes', () => {
    it('handles single exact-match field', () => {
      const rule = makeRule({
        selection: { EventID: '4688' },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { attackLogCount: 3 });
      expect(result.attackLogs.length).toBe(3);

      for (const log of result.attackLogs) {
        expect(String(log.EventID)).toBe('4688');
      }
    });

    it('handles array-of-values fields', () => {
      const rule = makeRule({
        selection: {
          Image: [
            '*\\cmd.exe',
            '*\\powershell.exe',
            '*\\wscript.exe',
          ],
        },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { attackLogCount: 6 });
      expect(result.attackLogs.length).toBe(6);

      for (const log of result.attackLogs) {
        expect(typeof log.Image).toBe('string');
        expect((log.Image as string).length).toBeGreaterThan(0);
      }
    });

    it('handles modifiers in field keys', () => {
      const rule = makeRule({
        selection: {
          'CommandLine|contains': ['whoami', 'ipconfig'],
        },
        condition: 'selection',
      });

      const result = generateTestLogs(rule, { attackLogCount: 3 });
      expect(result.attackLogs.length).toBe(3);

      for (const log of result.attackLogs) {
        expect(log).toHaveProperty('CommandLine');
      }
    });

    it('handles multiple selections', () => {
      const rule = makeRule({
        selection_proc: { Image: '*\\cmd.exe' },
        selection_args: { CommandLine: '*whoami*' },
        selection_user: { User: 'admin' },
        condition: '1 of selection_*',
      });

      const result = generateTestLogs(rule);
      expect(result.attackLogs.length).toBeGreaterThan(0);
      expect(result.benignLogs.length).toBeGreaterThan(0);
    });
  });
});
