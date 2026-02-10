/**
 * Unit tests for the Sigma rule evaluation engine.
 *
 * Covers: field matching, wildcards, modifiers, condition parsing,
 * selection evaluation, and suite evaluation.
 */

import { describe, it, expect } from 'vitest';
import {
  evaluateSigmaRule,
  evaluateSigmaRuleSuite,
} from '@/testing/sigma-tester.js';
import type { LogEntry } from '@/testing/sigma-tester.js';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(
  detection: Record<string, unknown> & { condition: string },
  overrides: Partial<SigmaRule> = {},
): SigmaRule {
  return {
    id: 'test-rule-0001-0000-000000000001',
    title: 'Test Rule',
    status: 'experimental',
    description: 'A test rule.',
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
// Field Matching
// ===========================================================================

describe('field matching', () => {
  it('matches exact string values (case-insensitive)', () => {
    const rule = makeRule({
      selection: { Image: 'cmd.exe' },
      condition: 'selection',
    });

    const match = evaluateSigmaRule(rule, { Image: 'CMD.EXE' });
    expect(match.matched).toBe(true);

    const noMatch = evaluateSigmaRule(rule, { Image: 'powershell.exe' });
    expect(noMatch.matched).toBe(false);
  });

  it('performs case-insensitive field lookup', () => {
    const rule = makeRule({
      selection: { CommandLine: 'test' },
      condition: 'selection',
    });

    const result = evaluateSigmaRule(rule, { commandline: 'test' });
    expect(result.matched).toBe(true);
  });

  it('matches numeric values by string comparison', () => {
    const rule = makeRule({
      selection: { EventID: '4688' },
      condition: 'selection',
    });

    const result = evaluateSigmaRule(rule, { EventID: 4688 });
    expect(result.matched).toBe(true);
  });

  it('handles null log values', () => {
    const rule = makeRule({
      selection: { Image: 'cmd.exe' },
      condition: 'selection',
    });

    const result = evaluateSigmaRule(rule, { Image: null });
    expect(result.matched).toBe(false);
  });

  it('handles undefined log values', () => {
    const rule = makeRule({
      selection: { Image: 'cmd.exe' },
      condition: 'selection',
    });

    const result = evaluateSigmaRule(rule, { OtherField: 'value' });
    expect(result.matched).toBe(false);
  });

  it('uses AND logic across fields within a selection', () => {
    const rule = makeRule({
      selection: {
        Image: 'cmd.exe',
        CommandLine: '*whoami*',
      },
      condition: 'selection',
    });

    // Both match
    const both = evaluateSigmaRule(rule, {
      Image: 'cmd.exe',
      CommandLine: 'cmd /c whoami',
    });
    expect(both.matched).toBe(true);

    // Only one matches
    const partial = evaluateSigmaRule(rule, {
      Image: 'cmd.exe',
      CommandLine: 'dir',
    });
    expect(partial.matched).toBe(false);
  });

  it('uses OR logic for array values on a single field', () => {
    const rule = makeRule({
      selection: {
        Image: ['cmd.exe', 'powershell.exe'],
      },
      condition: 'selection',
    });

    expect(
      evaluateSigmaRule(rule, { Image: 'cmd.exe' }).matched,
    ).toBe(true);
    expect(
      evaluateSigmaRule(rule, { Image: 'powershell.exe' }).matched,
    ).toBe(true);
    expect(
      evaluateSigmaRule(rule, { Image: 'notepad.exe' }).matched,
    ).toBe(false);
  });
});

// ===========================================================================
// Wildcard Matching
// ===========================================================================

describe('wildcard matching', () => {
  it('matches * at the beginning', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe' },
      condition: 'selection',
    });

    expect(
      evaluateSigmaRule(rule, {
        Image: 'C:\\Windows\\System32\\cmd.exe',
      }).matched,
    ).toBe(true);
  });

  it('matches * at the end', () => {
    const rule = makeRule({
      selection: { CommandLine: 'powershell*' },
      condition: 'selection',
    });

    expect(
      evaluateSigmaRule(rule, {
        CommandLine: 'powershell -enc abc123',
      }).matched,
    ).toBe(true);
  });

  it('matches * in the middle', () => {
    const rule = makeRule({
      selection: { CommandLine: 'cmd*whoami' },
      condition: 'selection',
    });

    expect(
      evaluateSigmaRule(rule, {
        CommandLine: 'cmd /c whoami',
      }).matched,
    ).toBe(true);
  });

  it('matches multiple * wildcards', () => {
    const rule = makeRule({
      selection: { CommandLine: '*powershell*-enc*' },
      condition: 'selection',
    });

    expect(
      evaluateSigmaRule(rule, {
        CommandLine:
          'C:\\Windows\\System32\\powershell.exe -encodedcommand ZW5j',
      }).matched,
    ).toBe(true);
  });

  it('matches ? as single character', () => {
    const rule = makeRule({
      selection: { Image: 'cm?.exe' },
      condition: 'selection',
    });

    expect(
      evaluateSigmaRule(rule, { Image: 'cmd.exe' }).matched,
    ).toBe(true);
    expect(
      evaluateSigmaRule(rule, { Image: 'cmdd.exe' }).matched,
    ).toBe(false);
  });

  it('pure * matches anything', () => {
    const rule = makeRule({
      selection: { Image: '*' },
      condition: 'selection',
    });

    expect(
      evaluateSigmaRule(rule, { Image: 'anything at all' }).matched,
    ).toBe(true);
  });

  it('no wildcards requires exact match', () => {
    const rule = makeRule({
      selection: { Image: 'cmd.exe' },
      condition: 'selection',
    });

    expect(
      evaluateSigmaRule(rule, { Image: 'cmd.exe' }).matched,
    ).toBe(true);
    expect(
      evaluateSigmaRule(rule, { Image: 'not_cmd.exe' }).matched,
    ).toBe(false);
  });
});

// ===========================================================================
// Modifiers
// ===========================================================================

describe('modifiers', () => {
  describe('|contains', () => {
    it('matches substring', () => {
      const rule = makeRule({
        selection: { 'CommandLine|contains': 'whoami' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, { CommandLine: 'cmd /c whoami /all' })
          .matched,
      ).toBe(true);
    });

    it('is case-insensitive', () => {
      const rule = makeRule({
        selection: { 'CommandLine|contains': 'WHOAMI' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, { CommandLine: 'cmd /c whoami' }).matched,
      ).toBe(true);
    });

    it('does not match when substring absent', () => {
      const rule = makeRule({
        selection: { 'CommandLine|contains': 'whoami' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, { CommandLine: 'dir /b' }).matched,
      ).toBe(false);
    });

    it('supports array values with OR logic', () => {
      const rule = makeRule({
        selection: {
          'CommandLine|contains': ['whoami', 'ipconfig'],
        },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, { CommandLine: 'run ipconfig /all' })
          .matched,
      ).toBe(true);
    });
  });

  describe('|startswith', () => {
    it('matches prefix', () => {
      const rule = makeRule({
        selection: { 'Image|startswith': 'C:\\Windows' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
        }).matched,
      ).toBe(true);
    });

    it('does not match non-prefix', () => {
      const rule = makeRule({
        selection: { 'Image|startswith': 'C:\\Windows' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, {
          Image: 'D:\\Tools\\cmd.exe',
        }).matched,
      ).toBe(false);
    });
  });

  describe('|endswith', () => {
    it('matches suffix', () => {
      const rule = makeRule({
        selection: { 'Image|endswith': '\\cmd.exe' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
        }).matched,
      ).toBe(true);
    });

    it('does not match non-suffix', () => {
      const rule = makeRule({
        selection: { 'Image|endswith': '\\cmd.exe' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\powershell.exe',
        }).matched,
      ).toBe(false);
    });
  });

  describe('|re', () => {
    it('matches regex pattern', () => {
      const rule = makeRule({
        selection: { 'CommandLine|re': 'cmd\\.exe.*\\/c\\s+whoami' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, {
          CommandLine: 'cmd.exe /c whoami',
        }).matched,
      ).toBe(true);
    });

    it('does not match when regex fails', () => {
      const rule = makeRule({
        selection: { 'CommandLine|re': '^powershell\\s' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, {
          CommandLine: 'cmd /c dir',
        }).matched,
      ).toBe(false);
    });
  });

  describe('|base64', () => {
    it('matches base64-decoded log value', () => {
      const rule = makeRule({
        selection: { 'Payload|base64': 'hello' },
        condition: 'selection',
      });

      // btoa('hello') === 'aGVsbG8='
      expect(
        evaluateSigmaRule(rule, { Payload: 'aGVsbG8=' }).matched,
      ).toBe(true);
    });

    it('does not match invalid base64', () => {
      const rule = makeRule({
        selection: { 'Payload|base64': 'hello' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, { Payload: 'not-base64!!!' }).matched,
      ).toBe(false);
    });
  });

  describe('|all', () => {
    it('requires ALL values to match (AND logic)', () => {
      const rule = makeRule({
        selection: {
          'CommandLine|contains|all': ['whoami', '/all'],
        },
        condition: 'selection',
      });

      // Both present
      expect(
        evaluateSigmaRule(rule, {
          CommandLine: 'cmd /c whoami /all',
        }).matched,
      ).toBe(true);

      // Only one present
      expect(
        evaluateSigmaRule(rule, {
          CommandLine: 'cmd /c whoami',
        }).matched,
      ).toBe(false);
    });
  });
});

// ===========================================================================
// Condition Parsing
// ===========================================================================

describe('condition parsing', () => {
  describe('simple conditions', () => {
    it('evaluates a single selection reference', () => {
      const rule = makeRule({
        selection: { Image: 'cmd.exe' },
        condition: 'selection',
      });

      expect(
        evaluateSigmaRule(rule, { Image: 'cmd.exe' }).matched,
      ).toBe(true);
    });
  });

  describe('AND conditions', () => {
    it('requires both selections to match', () => {
      const rule = makeRule({
        selection_proc: { Image: '*\\cmd.exe' },
        selection_args: { CommandLine: '*whoami*' },
        condition: 'selection_proc and selection_args',
      });

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
          CommandLine: 'cmd /c whoami',
        }).matched,
      ).toBe(true);

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
          CommandLine: 'dir',
        }).matched,
      ).toBe(false);
    });
  });

  describe('OR conditions', () => {
    it('matches if either selection matches', () => {
      const rule = makeRule({
        selection_cmd: { Image: '*\\cmd.exe' },
        selection_ps: { Image: '*\\powershell.exe' },
        condition: 'selection_cmd or selection_ps',
      });

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
        }).matched,
      ).toBe(true);

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\powershell.exe',
        }).matched,
      ).toBe(true);

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\notepad.exe',
        }).matched,
      ).toBe(false);
    });
  });

  describe('NOT conditions', () => {
    it('negates a selection', () => {
      const rule = makeRule({
        selection: { Image: '*\\cmd.exe' },
        filter: { User: 'SYSTEM' },
        condition: 'selection and not filter',
      });

      // Match selection, no filter -> should match
      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
          User: 'john.doe',
        }).matched,
      ).toBe(true);

      // Match selection AND filter -> should NOT match
      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
          User: 'SYSTEM',
        }).matched,
      ).toBe(false);
    });
  });

  describe('parenthesised conditions', () => {
    it('respects grouping', () => {
      const rule = makeRule({
        selection_proc: { Image: '*\\powershell.exe' },
        selection_cmd: { CommandLine: '*invoke-*' },
        filter_admin: { User: 'admin' },
        condition:
          '(selection_proc and selection_cmd) and not filter_admin',
      });

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\powershell.exe',
          CommandLine: 'powershell -command invoke-expression',
          User: 'john.doe',
        }).matched,
      ).toBe(true);

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\powershell.exe',
          CommandLine: 'powershell -command invoke-expression',
          User: 'admin',
        }).matched,
      ).toBe(false);
    });

    it('handles nested parentheses', () => {
      const rule = makeRule({
        sel_a: { Image: 'a.exe' },
        sel_b: { Image: 'b.exe' },
        sel_c: { Image: 'c.exe' },
        condition: '(sel_a or sel_b) and sel_c',
      });

      // sel_a matches but sel_c doesn't -> false
      expect(
        evaluateSigmaRule(rule, { Image: 'a.exe' }).matched,
      ).toBe(false);

      // sel_c alone -> false (need sel_a or sel_b too)
      expect(
        evaluateSigmaRule(rule, { Image: 'c.exe' }).matched,
      ).toBe(false);
    });
  });

  describe('quantified conditions ("1 of", "all of")', () => {
    it('1 of selection_* matches if any selection_* matches', () => {
      const rule = makeRule({
        selection_cmd: { Image: '*\\cmd.exe' },
        selection_ps: { Image: '*\\powershell.exe' },
        condition: '1 of selection_*',
      });

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
        }).matched,
      ).toBe(true);

      expect(
        evaluateSigmaRule(rule, {
          Image: 'notepad.exe',
        }).matched,
      ).toBe(false);
    });

    it('all of selection_* requires all to match', () => {
      const rule = makeRule({
        selection_proc: { Image: '*\\cmd.exe' },
        selection_args: { CommandLine: '*whoami*' },
        condition: 'all of selection_*',
      });

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
          CommandLine: 'cmd /c whoami',
        }).matched,
      ).toBe(true);

      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
          CommandLine: 'dir',
        }).matched,
      ).toBe(false);
    });

    it('1 of them matches any selection', () => {
      const rule = makeRule({
        selection_a: { Image: 'cmd.exe' },
        filter_b: { User: 'SYSTEM' },
        condition: '1 of them',
      });

      expect(
        evaluateSigmaRule(rule, { User: 'SYSTEM' }).matched,
      ).toBe(true);

      expect(
        evaluateSigmaRule(rule, { User: 'nobody', Image: 'other' })
          .matched,
      ).toBe(false);
    });

    it('all of them requires every selection to match', () => {
      const rule = makeRule({
        selection_a: { Image: 'cmd.exe' },
        selection_b: { User: 'SYSTEM' },
        condition: 'all of them',
      });

      expect(
        evaluateSigmaRule(rule, { Image: 'cmd.exe', User: 'SYSTEM' })
          .matched,
      ).toBe(true);

      expect(
        evaluateSigmaRule(rule, { Image: 'cmd.exe', User: 'john' })
          .matched,
      ).toBe(false);
    });
  });

  describe('complex conditions', () => {
    it('handles "1 of selection_* and not filter"', () => {
      const rule = makeRule({
        selection_cmd: { Image: '*\\cmd.exe' },
        selection_ps: { Image: '*\\powershell.exe' },
        filter_system: { User: 'SYSTEM' },
        condition: '1 of selection_* and not filter_system',
      });

      // Match a selection, not the filter
      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
          User: 'john.doe',
        }).matched,
      ).toBe(true);

      // Match a selection and the filter
      expect(
        evaluateSigmaRule(rule, {
          Image: 'C:\\Windows\\System32\\cmd.exe',
          User: 'SYSTEM',
        }).matched,
      ).toBe(false);
    });
  });
});

// ===========================================================================
// Selection Evaluation — list-of-maps
// ===========================================================================

describe('selection as list of maps', () => {
  it('treats array-of-objects as OR alternatives', () => {
    const rule = makeRule({
      selection: [
        { Image: 'cmd.exe', CommandLine: '*whoami*' },
        { Image: 'powershell.exe', CommandLine: '*invoke*' },
      ],
      condition: 'selection',
    });

    // First alternative matches
    expect(
      evaluateSigmaRule(rule, {
        Image: 'cmd.exe',
        CommandLine: 'whoami /all',
      }).matched,
    ).toBe(true);

    // Second alternative matches
    expect(
      evaluateSigmaRule(rule, {
        Image: 'powershell.exe',
        CommandLine: 'invoke-webrequest',
      }).matched,
    ).toBe(true);

    // Neither matches
    expect(
      evaluateSigmaRule(rule, {
        Image: 'notepad.exe',
        CommandLine: 'hello',
      }).matched,
    ).toBe(false);
  });
});

// ===========================================================================
// SigmaTestResult structure
// ===========================================================================

describe('SigmaTestResult structure', () => {
  it('includes ruleId and ruleTitle', () => {
    const rule = makeRule(
      { selection: { Image: 'cmd.exe' }, condition: 'selection' },
      { id: 'my-id', title: 'My Title' },
    );

    const result = evaluateSigmaRule(rule, { Image: 'cmd.exe' });
    expect(result.ruleId).toBe('my-id');
    expect(result.ruleTitle).toBe('My Title');
  });

  it('lists matched and failed selections', () => {
    const rule = makeRule({
      selection_a: { Image: 'cmd.exe' },
      selection_b: { User: 'admin' },
      condition: '1 of them',
    });

    const result = evaluateSigmaRule(rule, {
      Image: 'cmd.exe',
      User: 'other',
    });

    expect(result.matchedSelections).toContain('selection_a');
    expect(result.failedSelections).toContain('selection_b');
  });

  it('provides evaluationDetails as a non-empty string', () => {
    const rule = makeRule({
      selection: { Image: 'cmd.exe' },
      condition: 'selection',
    });

    const result = evaluateSigmaRule(rule, { Image: 'cmd.exe' });
    expect(result.evaluationDetails).toBeTruthy();
    expect(result.evaluationDetails).toContain('MATCHED');
  });
});

// ===========================================================================
// Suite Evaluation
// ===========================================================================

describe('evaluateSigmaRuleSuite', () => {
  const rule = makeRule({
    selection: { Image: '*\\cmd.exe' },
    condition: 'selection',
  });

  it('counts true positives and false negatives', () => {
    const attackLogs: LogEntry[] = [
      { Image: 'C:\\Windows\\System32\\cmd.exe' },
      { Image: 'cmd.exe' }, // won't match because no backslash before cmd.exe
      { Image: 'C:\\cmd.exe' },
    ];

    const result = evaluateSigmaRuleSuite(rule, attackLogs, []);
    expect(result.truePositives + result.falseNegatives).toBe(3);
  });

  it('counts true negatives and false positives', () => {
    const benignLogs: LogEntry[] = [
      { Image: 'C:\\Windows\\System32\\notepad.exe' },
      { Image: 'explorer.exe' },
    ];

    const result = evaluateSigmaRuleSuite(rule, [], benignLogs);
    expect(result.trueNegatives).toBe(2);
    expect(result.falsePositives).toBe(0);
  });

  it('computes tpRate correctly', () => {
    const attackLogs: LogEntry[] = [
      { Image: 'C:\\Windows\\System32\\cmd.exe' },
      { Image: 'D:\\tools\\cmd.exe' },
      { Image: 'notepad.exe' }, // false negative
    ];

    const result = evaluateSigmaRuleSuite(rule, attackLogs, []);
    expect(result.tpRate).toBeCloseTo(2 / 3);
  });

  it('computes fpRate correctly', () => {
    const benignLogs: LogEntry[] = [
      { Image: 'C:\\Windows\\System32\\notepad.exe' },
      { Image: 'explorer.exe' },
      { Image: 'chrome.exe' },
    ];

    const result = evaluateSigmaRuleSuite(rule, [], benignLogs);
    expect(result.fpRate).toBe(0);
  });

  it('handles empty log sets', () => {
    const result = evaluateSigmaRuleSuite(rule, [], []);
    expect(result.truePositives).toBe(0);
    expect(result.falseNegatives).toBe(0);
    expect(result.trueNegatives).toBe(0);
    expect(result.falsePositives).toBe(0);
    expect(result.tpRate).toBe(0);
    expect(result.fpRate).toBe(0);
  });

  it('sets ruleId and ruleTitle', () => {
    const result = evaluateSigmaRuleSuite(rule, [], []);
    expect(result.ruleId).toBe(rule.id);
    expect(result.ruleTitle).toBe(rule.title);
  });
});
