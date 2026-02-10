/**
 * Unit tests for the JSON reporter.
 *
 * Tests: generateJsonReport, writePipelineReport
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { writeFileSync, mkdirSync } from 'fs';
import {
  generateJsonReport,
  writePipelineReport,
  type PipelineReport,
} from '@/reporting/json-reporter.js';
import type { GeneratedRule } from '@/types/detection-rule.js';
import type {
  ExtractedIOC,
  ExtractedTTP,
  AttackMappingResult,
} from '@/types/extraction.js';

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

function makeIOC(overrides?: Partial<ExtractedIOC>): ExtractedIOC {
  return {
    type: 'ipv4',
    value: '192.168.1.100',
    confidence: 'high',
    context: 'C2 traffic observed from this IP',
    defanged: false,
    originalValue: '192.168.1.100',
    relationships: [],
    ...overrides,
  };
}

function makeTTP(overrides?: Partial<ExtractedTTP>): ExtractedTTP {
  return {
    description: 'PowerShell download cradle execution',
    tools: ['PowerShell'],
    targetPlatforms: ['windows'],
    artifacts: [{ type: 'process', description: 'powershell.exe spawned' }],
    detectionOpportunities: ['Monitor process creation'],
    confidence: 'high',
    ...overrides,
  };
}

function makeMapping(overrides?: Partial<AttackMappingResult>): AttackMappingResult {
  return {
    techniqueId: 'T1059.001',
    techniqueName: 'PowerShell',
    tactic: 'execution',
    confidence: 'high',
    reasoning: 'Uses PowerShell',
    sourceTtp: makeTTP(),
    suggestedRuleFormats: ['sigma'],
    validated: true,
    ...overrides,
  };
}

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

function makePipelineReport(overrides?: Partial<PipelineReport>): PipelineReport {
  return {
    metadata: {
      generatedAt: '2026-02-10T12:00:00.000Z',
      detectforgeVersion: '0.1.0',
      inputFile: 'apt29-report.pdf',
      processingTimeMs: 45200,
    },
    extraction: {
      iocs: [makeIOC()],
      ttps: [makeTTP()],
      attackMappings: [makeMapping()],
    },
    rules: [makeRule()],
    validation: {
      totalRules: 1,
      validRules: 1,
      invalidRules: 0,
      passRate: 100,
    },
    cost: {
      totalUsd: 0.234,
      byOperation: { extraction: 0.05, generation: 0.15, analysis: 0.034 },
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

describe('generateJsonReport', () => {
  it('returns a valid JSON string', () => {
    const report = makePipelineReport();
    const json = generateJsonReport(report);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('parsed JSON matches input data', () => {
    const report = makePipelineReport();
    const json = generateJsonReport(report);
    const parsed = JSON.parse(json);
    expect(parsed).toEqual(report);
  });

  it('contains all required top-level keys', () => {
    const report = makePipelineReport();
    const json = generateJsonReport(report);
    const parsed = JSON.parse(json);

    expect(parsed).toHaveProperty('metadata');
    expect(parsed).toHaveProperty('extraction');
    expect(parsed).toHaveProperty('rules');
    expect(parsed).toHaveProperty('validation');
    expect(parsed).toHaveProperty('cost');
  });

  it('includes optional quality field when provided', () => {
    const report = makePipelineReport({
      quality: {
        totalRules: 1,
        averageScore: 8.5,
        scoreDistribution: { '1-3': 0, '4-6': 0, '7-10': 1 },
        perRuleScores: [],
        recommendations: [],
      },
    });
    const json = generateJsonReport(report);
    const parsed = JSON.parse(json);
    expect(parsed).toHaveProperty('quality');
    expect(parsed.quality.averageScore).toBe(8.5);
  });

  it('includes optional coverage field when provided', () => {
    const report = makePipelineReport({
      coverage: {
        totalTechniques: 10,
        coveredTechniques: 3,
        coveragePercentage: 30,
        tacticBreakdown: {},
        coveredTechniqueIds: ['T1059.001', 'T1053.005', 'T1071.001'],
        uncoveredTechniqueIds: [],
        navigatorLayer: {
          name: 'Test Layer',
          versions: { attack: '14', navigator: '4.9.5', layer: '4.5' },
          domain: 'enterprise-attack',
          description: 'Test',
          techniques: [],
        },
      },
    });
    const json = generateJsonReport(report);
    const parsed = JSON.parse(json);
    expect(parsed).toHaveProperty('coverage');
    expect(parsed.coverage.coveredTechniques).toBe(3);
  });

  it('omits quality field when not provided', () => {
    const report = makePipelineReport();
    const json = generateJsonReport(report);
    const parsed = JSON.parse(json);
    expect(parsed.quality).toBeUndefined();
  });

  it('omits coverage field when not provided', () => {
    const report = makePipelineReport();
    const json = generateJsonReport(report);
    const parsed = JSON.parse(json);
    expect(parsed.coverage).toBeUndefined();
  });
});

describe('writePipelineReport', () => {
  it('writes JSON to the specified file path', () => {
    const report = makePipelineReport();
    writePipelineReport(report, '/tmp/output/report.json');

    expect(writeFileSync).toHaveBeenCalledTimes(1);
    expect(writeFileSync).toHaveBeenCalledWith(
      '/tmp/output/report.json',
      expect.any(String),
      'utf-8',
    );

    // Verify the written content is valid JSON matching the report
    const writtenContent = (writeFileSync as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
    const parsed = JSON.parse(writtenContent);
    expect(parsed).toEqual(report);
  });

  it('creates parent directories recursively', () => {
    const report = makePipelineReport();
    writePipelineReport(report, '/tmp/deep/nested/dir/report.json');

    expect(mkdirSync).toHaveBeenCalledTimes(1);
    expect(mkdirSync).toHaveBeenCalledWith('/tmp/deep/nested/dir', { recursive: true });
  });
});
