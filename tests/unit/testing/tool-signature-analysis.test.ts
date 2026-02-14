/**
 * Unit tests for tool-signature analysis in quality scorer (Level 7 Phase 2).
 *
 * Tests that rules with tool-specific filenames as primary detection
 * get penalized, while behavioral rules are rewarded.
 */

import { describe, it, expect } from 'vitest';
import { scoreRuleQuality } from '@/testing/quality-scorer.js';
import type {
  GeneratedRule,
  ValidationResult,
} from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeValidation(): ValidationResult {
  return {
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
  };
}

function makeSigmaGeneratedRule(
  detection: Record<string, unknown>,
  overrides: Partial<GeneratedRule> = {},
): GeneratedRule {
  return {
    format: 'sigma',
    sigma: {
      id: 'tool-sig-test',
      title: 'Tool Signature Test Rule',
      status: 'experimental',
      description: 'Test rule for tool signature analysis. This description is long enough to score documentation points.',
      references: ['https://example.com'],
      author: 'Test',
      date: '2026-02-12',
      modified: '2026-02-12',
      tags: ['attack.credential_access', 'attack.t1003.001'],
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        ...detection,
        condition: detection.condition as string,
      },
      falsepositives: ['Legitimate admin activity', 'Security scanning tools'],
      level: 'high',
      raw: '',
    },
    sourceReportId: 'report-001',
    attackTechniqueId: 'T1003.001',
    attackTactic: 'credential-access',
    confidence: 'high',
    documentation: undefined,
    validation: makeValidation(),
    ...overrides,
  };
}

// ===========================================================================
// Tool-Signature Penalty
// ===========================================================================

describe('tool-signature detection penalty', () => {
  it('penalizes rules that only detect by tool filename (mimikatz.exe)', () => {
    const toolRule = makeSigmaGeneratedRule({
      selection: { Image: '*\\mimikatz.exe' },
      condition: 'selection',
    });

    // Behavioral rule using process_access logsource (correct for TargetImage/GrantedAccess)
    const behavioralRule = makeSigmaGeneratedRule({
      selection: {
        TargetImage: '*\\lsass.exe',
        GrantedAccess: ['0x1010', '0x1038', '0x1fffff'],
      },
      condition: 'selection',
    }, {
      sigma: {
        id: 'tool-sig-test',
        title: 'Tool Signature Test Rule',
        status: 'experimental',
        description: 'Test rule for tool signature analysis. This description is long enough to score documentation points.',
        references: ['https://example.com'],
        author: 'Test',
        date: '2026-02-12',
        modified: '2026-02-12',
        tags: ['attack.credential_access', 'attack.t1003.001'],
        logsource: { category: 'process_access', product: 'windows' },
        detection: {
          selection: {
            TargetImage: '*\\lsass.exe',
            GrantedAccess: ['0x1010', '0x1038', '0x1fffff'],
          },
          condition: 'selection',
        },
        falsepositives: ['Legitimate admin activity', 'Security scanning tools'],
        level: 'high',
        raw: '',
      },
    });

    const toolScore = scoreRuleQuality(toolRule);
    const behavioralScore = scoreRuleQuality(behavioralRule);

    // Behavioral rule should score higher than tool-signature rule
    expect(behavioralScore.dimensions.detectionLogic)
      .toBeGreaterThan(toolScore.dimensions.detectionLogic);
  });

  it('does NOT penalize rules detecting system binaries (cmd.exe)', () => {
    const systemBinaryRule = makeSigmaGeneratedRule({
      selection: { Image: '*\\cmd.exe', CommandLine: '*whoami*' },
      filter: { User: 'SYSTEM' },
      condition: 'selection and not filter',
    });

    const score = scoreRuleQuality(systemBinaryRule);

    // cmd.exe is a system binary — should NOT be penalized as tool-signature
    // Score should be reasonable (not severely penalized)
    expect(score.dimensions.detectionLogic).toBeGreaterThanOrEqual(4);
  });

  it('does NOT penalize rules detecting powershell.exe', () => {
    const psRule = makeSigmaGeneratedRule({
      selection: { Image: '*\\powershell.exe', CommandLine: '*-enc*' },
      condition: 'selection',
    });

    const score = scoreRuleQuality(psRule);
    expect(score.dimensions.detectionLogic).toBeGreaterThanOrEqual(4);
  });

  it('penalizes rules with Seatbelt.exe as only detection', () => {
    const seatbeltRule = makeSigmaGeneratedRule({
      selection: { Image: '*\\Seatbelt.exe' },
      condition: 'selection',
    });

    const score = scoreRuleQuality(seatbeltRule);

    // Should get the -3 penalty for primary tool-signature detection
    expect(score.dimensions.detectionLogic).toBeLessThanOrEqual(4);
  });

  it('rewards rules with multiple detection variants', () => {
    const multiVariant = makeSigmaGeneratedRule({
      selection_comsvcs: {
        Image: '*\\rundll32.exe',
        CommandLine: '*comsvcs*MiniDump*',
      },
      selection_procdump: {
        Image: '*\\procdump64.exe',
        CommandLine: '*lsass*',
      },
      selection_taskmgr: {
        TargetImage: '*\\lsass.exe',
        GrantedAccess: '0x1fffff',
      },
      condition: '1 of selection_*',
    });

    const singleVariant = makeSigmaGeneratedRule({
      selection: { Image: '*\\mimikatz.exe' },
      condition: 'selection',
    });

    const multiScore = scoreRuleQuality(multiVariant);
    const singleScore = scoreRuleQuality(singleVariant);

    expect(multiScore.dimensions.detectionLogic)
      .toBeGreaterThan(singleScore.dimensions.detectionLogic);
  });

  it('does not penalize tool name when behavioral fields are present', () => {
    // Use process_access logsource which is correct for TargetImage/GrantedAccess
    const mixedRule = makeSigmaGeneratedRule({
      selection: {
        Image: '*\\procdump64.exe',
        TargetImage: '*\\lsass.exe',
        GrantedAccess: '0x1fffff',
      },
      condition: 'selection',
    }, {
      sigma: {
        id: 'tool-sig-test',
        title: 'Tool Signature Test Rule',
        status: 'experimental',
        description: 'Test rule for tool signature analysis. This description is long enough to score documentation points.',
        references: ['https://example.com'],
        author: 'Test',
        date: '2026-02-12',
        modified: '2026-02-12',
        tags: ['attack.credential_access', 'attack.t1003.001'],
        logsource: { category: 'process_access', product: 'windows' },
        detection: {
          selection: {
            Image: '*\\procdump64.exe',
            TargetImage: '*\\lsass.exe',
            GrantedAccess: '0x1fffff',
          },
          condition: 'selection',
        },
        falsepositives: ['Legitimate admin activity', 'Security scanning tools'],
        level: 'high',
        raw: '',
      },
    });

    const score = scoreRuleQuality(mixedRule);

    // Has behavioral fields alongside tool name — should NOT get severe penalty
    expect(score.dimensions.detectionLogic).toBeGreaterThanOrEqual(3);
  });
});
