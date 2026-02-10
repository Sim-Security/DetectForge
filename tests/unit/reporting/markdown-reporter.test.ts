/**
 * Unit tests for the Markdown reporter.
 *
 * Tests: generateMarkdownReport
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { generateMarkdownReport } from '@/reporting/markdown-reporter.js';
import type { PipelineReport } from '@/reporting/json-reporter.js';
import type { GeneratedRule } from '@/types/detection-rule.js';
import type {
  ExtractedIOC,
  ExtractedTTP,
  AttackMappingResult,
} from '@/types/extraction.js';

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
      iocs: [
        makeIOC(),
        makeIOC({ type: 'domain', value: 'evil.com' }),
        makeIOC({ type: 'sha256', value: 'deadbeef' }),
      ],
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

describe('generateMarkdownReport', () => {
  it('returns a string', () => {
    const result = generateMarkdownReport(makePipelineReport());
    expect(typeof result).toBe('string');
  });

  it('contains the main report heading', () => {
    const result = generateMarkdownReport(makePipelineReport());
    expect(result).toContain('# DetectForge Analysis Report');
  });

  it('contains Executive Summary section', () => {
    const result = generateMarkdownReport(makePipelineReport());
    expect(result).toContain('## Executive Summary');
  });

  it('contains Extraction Results section with IOC table', () => {
    const result = generateMarkdownReport(makePipelineReport());
    expect(result).toContain('## Extraction Results');
    // Should contain IOC type/count table headers
    expect(result).toContain('| Type | Count | Examples |');
  });

  it('contains Generated Rules section', () => {
    const result = generateMarkdownReport(makePipelineReport());
    expect(result).toContain('## Generated Rules');
  });

  it('contains Validation Results section', () => {
    const result = generateMarkdownReport(makePipelineReport());
    expect(result).toContain('## Validation Results');
  });

  it('contains Cost Summary section', () => {
    const result = generateMarkdownReport(makePipelineReport());
    expect(result).toContain('## Cost Summary');
    expect(result).toContain('$0.234');
  });

  it('includes rule content when includeRuleContent is true', () => {
    const report = makePipelineReport();
    const result = generateMarkdownReport(report, { includeRuleContent: true });
    // The raw rule text should appear in a code block
    expect(result).toContain('title: Suspicious PowerShell Download Cradle');
    expect(result).toContain('```');
  });

  it('omits rule content when includeRuleContent is false', () => {
    const report = makePipelineReport();
    const result = generateMarkdownReport(report, { includeRuleContent: false });
    // The raw rule text should NOT appear in a code block.
    // However the title will appear as a heading. Check for the code fence.
    const codeBlockCount = (result.match(/```yaml/g) || []).length;
    expect(codeBlockCount).toBe(0);
  });

  it('includes coverage section when coverage data is provided', () => {
    const report = makePipelineReport({
      coverage: {
        totalTechniques: 10,
        coveredTechniques: 3,
        coveragePercentage: 30,
        tacticBreakdown: {
          execution: { covered: 1, total: 3, percentage: 33.33 },
        },
        coveredTechniqueIds: ['T1059.001'],
        uncoveredTechniqueIds: ['T1053.005'],
        navigatorLayer: {
          name: 'Test Layer',
          versions: { attack: '14', navigator: '4.9.5', layer: '4.5' },
          domain: 'enterprise-attack',
          description: 'Test',
          techniques: [],
        },
      },
    });
    const result = generateMarkdownReport(report);
    expect(result).toContain('## ATT&CK Coverage');
  });

  it('omits coverage section when coverage data is not provided', () => {
    const report = makePipelineReport();
    const result = generateMarkdownReport(report);
    expect(result).not.toContain('## ATT&CK Coverage');
  });

  it('includes quality section when quality data is provided', () => {
    const report = makePipelineReport({
      quality: {
        totalRules: 1,
        averageScore: 8.5,
        scoreDistribution: { '1-3': 0, '4-6': 0, '7-10': 1 },
        perRuleScores: [
          {
            ruleId: 'abc-123',
            format: 'sigma',
            overallScore: 8.5,
            dimensions: {
              syntaxValidity: 10,
              detectionLogic: 8,
              documentation: 7,
              attackMapping: 9,
              falsePosHandling: 6,
            },
            explanation: 'Good rule quality.',
          },
        ],
        recommendations: ['Improve FP handling.'],
      },
    });
    const result = generateMarkdownReport(report);
    expect(result).toContain('## Quality Assessment');
  });

  it('formats IOC counts by type in a table', () => {
    const report = makePipelineReport({
      extraction: {
        iocs: [
          makeIOC({ type: 'ipv4', value: '10.0.0.1' }),
          makeIOC({ type: 'ipv4', value: '10.0.0.2' }),
          makeIOC({ type: 'domain', value: 'bad.com' }),
        ],
        ttps: [makeTTP()],
        attackMappings: [makeMapping()],
      },
    });
    const result = generateMarkdownReport(report);
    // Should have a table row for ipv4 with count 2
    expect(result).toContain('ipv4');
    expect(result).toContain('2');
    expect(result).toContain('domain');
  });

  it('lists ATT&CK technique IDs for TTP mappings', () => {
    const report = makePipelineReport({
      extraction: {
        iocs: [makeIOC()],
        ttps: [makeTTP()],
        attackMappings: [
          makeMapping({ techniqueId: 'T1059.001', techniqueName: 'PowerShell' }),
          makeMapping({ techniqueId: 'T1053.005', techniqueName: 'Scheduled Task' }),
        ],
      },
    });
    const result = generateMarkdownReport(report);
    expect(result).toContain('T1059.001');
    expect(result).toContain('T1053.005');
  });
});
