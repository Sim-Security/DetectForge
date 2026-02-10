/**
 * Unit tests for the quality scorer module.
 */

import { describe, it, expect } from 'vitest';
import { scoreRuleQuality, generateQualityReport } from '@/testing/quality-scorer.js';
import type {
  GeneratedRule,
  ValidationResult,
  RuleDocumentation,
} from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers — test fixture factories
// ---------------------------------------------------------------------------

function makeValidation(overrides: Partial<ValidationResult> = {}): ValidationResult {
  return {
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
    ...overrides,
  };
}

function makeFullDocumentation(): RuleDocumentation {
  return {
    whatItDetects: 'Detects PowerShell execution with encoded commands.',
    howItWorks: 'Matches process creation events with powershell.exe and -enc flag.',
    attackMapping: {
      techniqueId: 'T1059.001',
      techniqueName: 'PowerShell',
      tactic: 'Execution',
      platform: 'Windows',
    },
    falsePositives: [
      {
        scenario: 'Legitimate admin scripts using encoded commands',
        likelihood: 'medium',
        tuningAdvice: 'Whitelist known admin script hashes.',
      },
      {
        scenario: 'SCCM deployment scripts',
        likelihood: 'low',
        tuningAdvice: 'Exclude SCCM service account.',
      },
      {
        scenario: 'Third-party monitoring agents',
        likelihood: 'low',
        tuningAdvice: 'Exclude known agent processes.',
      },
    ],
    coverageGaps: ['Does not detect PowerShell v2 downgrade attacks.'],
    recommendedLogSources: ['Windows Event Log 4688', 'Sysmon Event ID 1'],
    tuningRecommendations: ['Add hash-based exclusions for known legitimate scripts.'],
  };
}

function makeYaraGeneratedRule(overrides: Partial<GeneratedRule> = {}): GeneratedRule {
  return {
    format: 'yara',
    yara: {
      name: 'APT_Test',
      tags: ['apt'],
      meta: {
        description: 'Test rule',
        author: 'Test',
        date: '2025-01-01',
        reference: 'https://example.com',
        mitre_attack: 'T1059.001',
      },
      strings: [
        { identifier: '$s1', value: 'LoadLibraryA', type: 'text', modifiers: ['ascii'] },
        { identifier: '$s2', value: 'VirtualAlloc', type: 'text', modifiers: ['ascii'] },
        { identifier: '$s3', value: 'CreateThread', type: 'text', modifiers: ['ascii'] },
      ],
      condition: '$s1 and $s2 and $s3',
      raw: '',
    },
    sourceReportId: 'report-001',
    attackTechniqueId: 'T1059.001',
    attackTactic: 'execution',
    confidence: 'high',
    documentation: makeFullDocumentation(),
    validation: makeValidation(),
    ...overrides,
  };
}

function makeSuricataGeneratedRule(overrides: Partial<GeneratedRule> = {}): GeneratedRule {
  return {
    format: 'suricata',
    suricata: {
      action: 'alert',
      protocol: 'http',
      sourceIp: '$HOME_NET',
      sourcePort: 'any',
      direction: '->',
      destIp: '$EXTERNAL_NET',
      destPort: '$HTTP_PORTS',
      options: [
        { keyword: 'msg', value: '"Test Alert"' },
        { keyword: 'flow', value: 'established,to_server' },
        { keyword: 'content', value: '"/malware"' },
        { keyword: 'content', value: '"beacon"' },
        { keyword: 'sid', value: '1000001' },
        { keyword: 'rev', value: '1' },
      ],
      sid: 1000001,
      rev: 1,
      raw: '',
    },
    sourceReportId: 'report-002',
    attackTechniqueId: 'T1071.001',
    attackTactic: 'command-and-control',
    confidence: 'medium',
    documentation: makeFullDocumentation(),
    validation: makeValidation(),
    ...overrides,
  };
}

function makeSigmaGeneratedRule(overrides: Partial<GeneratedRule> = {}): GeneratedRule {
  return {
    format: 'sigma',
    sigma: {
      id: 'sigma-001',
      title: 'PowerShell Encoded Command',
      status: 'experimental',
      description: 'Detects encoded PowerShell commands',
      references: ['https://example.com'],
      author: 'Test',
      date: '2025-01-01',
      modified: '2025-01-01',
      tags: ['attack.execution', 'attack.t1059.001'],
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        selection: { CommandLine: '*-enc*' },
        filter: { User: 'SYSTEM' },
        condition: 'selection and not filter',
      },
      falsepositives: ['Legitimate admin scripts'],
      level: 'high',
      raw: '',
    },
    sourceReportId: 'report-003',
    attackTechniqueId: 'T1059.001',
    attackTactic: 'execution',
    confidence: 'high',
    documentation: makeFullDocumentation(),
    validation: makeValidation(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// scoreRuleQuality
// ---------------------------------------------------------------------------

describe('scoreRuleQuality', () => {
  it('returns a score between 1 and 10', () => {
    const result = scoreRuleQuality(makeYaraGeneratedRule());
    expect(result.overallScore).toBeGreaterThanOrEqual(1);
    expect(result.overallScore).toBeLessThanOrEqual(10);
  });

  it('returns format and ruleId', () => {
    const result = scoreRuleQuality(makeYaraGeneratedRule());
    expect(result.format).toBe('yara');
    expect(result.ruleId).toBe('APT_Test');
  });

  it('extracts SID-based ruleId for Suricata rules', () => {
    const result = scoreRuleQuality(makeSuricataGeneratedRule());
    expect(result.ruleId).toBe('SID:1000001');
    expect(result.format).toBe('suricata');
  });

  it('extracts sigma id as ruleId for Sigma rules', () => {
    const result = scoreRuleQuality(makeSigmaGeneratedRule());
    expect(result.ruleId).toBe('sigma-001');
    expect(result.format).toBe('sigma');
  });

  it('scores syntaxValidity at 10 when validation has no errors or warnings', () => {
    const result = scoreRuleQuality(makeYaraGeneratedRule());
    expect(result.dimensions.syntaxValidity).toBe(10);
  });

  it('reduces syntaxValidity by 2 per error', () => {
    const rule = makeYaraGeneratedRule({
      validation: makeValidation({
        valid: false,
        syntaxValid: false,
        errors: ['Error 1', 'Error 2'],
        warnings: [],
      }),
    });
    const result = scoreRuleQuality(rule);
    expect(result.dimensions.syntaxValidity).toBe(6);
  });

  it('reduces syntaxValidity by 1 per warning', () => {
    const rule = makeYaraGeneratedRule({
      validation: makeValidation({
        warnings: ['Warning 1', 'Warning 2', 'Warning 3'],
      }),
    });
    const result = scoreRuleQuality(rule);
    expect(result.dimensions.syntaxValidity).toBe(7);
  });

  it('clamps syntaxValidity to minimum 1', () => {
    const rule = makeYaraGeneratedRule({
      validation: makeValidation({
        valid: false,
        syntaxValid: false,
        errors: ['E1', 'E2', 'E3', 'E4', 'E5', 'E6'],
      }),
    });
    const result = scoreRuleQuality(rule);
    expect(result.dimensions.syntaxValidity).toBe(1);
  });

  it('scores documentation at 1 when missing', () => {
    const rule = makeYaraGeneratedRule({ documentation: undefined });
    const result = scoreRuleQuality(rule);
    expect(result.dimensions.documentation).toBe(1);
  });

  it('scores documentation highly when fully populated', () => {
    const result = scoreRuleQuality(makeYaraGeneratedRule());
    expect(result.dimensions.documentation).toBeGreaterThanOrEqual(7);
  });

  it('scores attackMapping highly with valid technique and tactic', () => {
    const result = scoreRuleQuality(makeYaraGeneratedRule());
    expect(result.dimensions.attackMapping).toBeGreaterThanOrEqual(8);
  });

  it('scores attackMapping low when no technique or tactic', () => {
    const rule = makeYaraGeneratedRule({
      attackTechniqueId: undefined,
      attackTactic: undefined,
      documentation: undefined,
    });
    const result = scoreRuleQuality(rule);
    expect(result.dimensions.attackMapping).toBeLessThanOrEqual(2);
  });

  it('gives partial attackMapping credit for malformed technique ID', () => {
    const rule = makeYaraGeneratedRule({
      attackTechniqueId: 'T1234_bad',
      attackTactic: 'execution',
      documentation: undefined,
    });
    const result = scoreRuleQuality(rule);
    // Should get some credit for starting with T but not full marks
    expect(result.dimensions.attackMapping).toBeGreaterThanOrEqual(4);
    expect(result.dimensions.attackMapping).toBeLessThanOrEqual(7);
  });

  it('scores falsePosHandling at 1 when documentation is missing', () => {
    const rule = makeYaraGeneratedRule({ documentation: undefined });
    const result = scoreRuleQuality(rule);
    expect(result.dimensions.falsePosHandling).toBe(1);
  });

  it('scores falsePosHandling highly with multiple scenarios and tuning advice', () => {
    const result = scoreRuleQuality(makeYaraGeneratedRule());
    expect(result.dimensions.falsePosHandling).toBeGreaterThanOrEqual(8);
  });

  it('scores detectionLogic for YARA rules based on string count and operators', () => {
    const result = scoreRuleQuality(makeYaraGeneratedRule());
    expect(result.dimensions.detectionLogic).toBeGreaterThanOrEqual(6);
  });

  it('scores detectionLogic for Suricata rules based on content count', () => {
    const result = scoreRuleQuality(makeSuricataGeneratedRule());
    expect(result.dimensions.detectionLogic).toBeGreaterThanOrEqual(6);
  });

  it('scores detectionLogic for Sigma rules based on detection selections', () => {
    const result = scoreRuleQuality(makeSigmaGeneratedRule());
    expect(result.dimensions.detectionLogic).toBeGreaterThanOrEqual(6);
  });

  it('returns a non-empty explanation', () => {
    const result = scoreRuleQuality(makeYaraGeneratedRule());
    expect(result.explanation.length).toBeGreaterThan(0);
  });

  it('includes all five dimension scores', () => {
    const result = scoreRuleQuality(makeYaraGeneratedRule());
    expect(result.dimensions).toHaveProperty('syntaxValidity');
    expect(result.dimensions).toHaveProperty('detectionLogic');
    expect(result.dimensions).toHaveProperty('documentation');
    expect(result.dimensions).toHaveProperty('attackMapping');
    expect(result.dimensions).toHaveProperty('falsePosHandling');
  });
});

// ---------------------------------------------------------------------------
// generateQualityReport
// ---------------------------------------------------------------------------

describe('generateQualityReport', () => {
  it('returns correct totalRules count', () => {
    const rules = [makeYaraGeneratedRule(), makeSuricataGeneratedRule()];
    const report = generateQualityReport(rules);
    expect(report.totalRules).toBe(2);
  });

  it('calculates averageScore', () => {
    const rules = [makeYaraGeneratedRule(), makeSuricataGeneratedRule()];
    const report = generateQualityReport(rules);
    expect(report.averageScore).toBeGreaterThan(0);
    expect(report.averageScore).toBeLessThanOrEqual(10);
  });

  it('returns 0 averageScore for empty rule set', () => {
    const report = generateQualityReport([]);
    expect(report.totalRules).toBe(0);
    expect(report.averageScore).toBe(0);
  });

  it('populates scoreDistribution buckets', () => {
    const rules = [makeYaraGeneratedRule(), makeSuricataGeneratedRule()];
    const report = generateQualityReport(rules);
    expect(report.scoreDistribution).toHaveProperty('1-3');
    expect(report.scoreDistribution).toHaveProperty('4-6');
    expect(report.scoreDistribution).toHaveProperty('7-10');
    // Sum should equal total rules
    const sum =
      report.scoreDistribution['1-3'] +
      report.scoreDistribution['4-6'] +
      report.scoreDistribution['7-10'];
    expect(sum).toBe(2);
  });

  it('includes perRuleScores for each rule', () => {
    const rules = [makeYaraGeneratedRule(), makeSuricataGeneratedRule()];
    const report = generateQualityReport(rules);
    expect(report.perRuleScores).toHaveLength(2);
  });

  it('generates recommendations for low-scoring dimensions', () => {
    const weakRule = makeYaraGeneratedRule({
      validation: makeValidation({
        valid: false,
        syntaxValid: false,
        errors: ['E1', 'E2', 'E3', 'E4'],
      }),
      documentation: undefined,
      attackTechniqueId: undefined,
      attackTactic: undefined,
    });
    const report = generateQualityReport([weakRule]);
    expect(report.recommendations.length).toBeGreaterThan(0);
  });

  it('flags low-score rules in recommendations', () => {
    const terribleRule = makeYaraGeneratedRule({
      validation: makeValidation({
        valid: false,
        syntaxValid: false,
        errors: ['E1', 'E2', 'E3', 'E4', 'E5'],
        warnings: ['W1', 'W2', 'W3'],
      }),
      yara: {
        name: 'Bad_Rule',
        tags: [],
        meta: { description: '', author: '', date: '', reference: '', mitre_attack: '' },
        strings: [],
        condition: '',
        raw: '',
      },
      documentation: undefined,
      attackTechniqueId: undefined,
      attackTactic: undefined,
    });
    const report = generateQualityReport([terribleRule]);
    expect(report.recommendations.some(r => r.includes('scored 3 or below'))).toBe(true);
  });

  it('returns empty recommendations for high-quality rules', () => {
    const rules = [makeYaraGeneratedRule()];
    const report = generateQualityReport(rules);
    // High quality rules might still get some general recommendations
    // but should not have the "scored 3 or below" message
    expect(report.recommendations.every(r => !r.includes('scored 3 or below'))).toBe(true);
  });
});
