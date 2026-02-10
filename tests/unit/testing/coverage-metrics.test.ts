/**
 * Unit tests for the coverage metrics module.
 */

import { describe, it, expect } from 'vitest';
import {
  calculateCoverageMetrics,
  exportNavigatorLayer,
} from '@/testing/coverage-metrics.js';
import type { GeneratedRule, ValidationResult } from '@/types/detection-rule.js';
import type { AttackMappingResult, ExtractedTTP } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Helpers — test fixture factories
// ---------------------------------------------------------------------------

function makeValidation(valid = true): ValidationResult {
  return {
    valid,
    syntaxValid: valid,
    schemaValid: valid,
    errors: valid ? [] : ['Error'],
    warnings: [],
  };
}

function makeTTP(description: string): ExtractedTTP {
  return {
    description,
    tools: [],
    targetPlatforms: ['Windows'],
    artifacts: [],
    detectionOpportunities: [],
    confidence: 'high',
  };
}

function makeMapping(
  techniqueId: string,
  tactic: string,
  overrides: Partial<AttackMappingResult> = {},
): AttackMappingResult {
  return {
    techniqueId,
    techniqueName: `Technique ${techniqueId}`,
    tactic,
    confidence: 'high',
    reasoning: 'Test mapping',
    sourceTtp: makeTTP(`TTP for ${techniqueId}`),
    suggestedRuleFormats: ['sigma'],
    validated: true,
    ...overrides,
  };
}

function makeGeneratedRule(
  techniqueId: string | undefined,
  tactic: string | undefined,
  valid = true,
): GeneratedRule {
  return {
    format: 'sigma',
    sigma: {
      id: `rule-${techniqueId ?? 'unknown'}`,
      title: `Rule for ${techniqueId ?? 'unknown'}`,
      status: 'experimental',
      description: 'Test rule',
      references: [],
      author: 'Test',
      date: '2025-01-01',
      modified: '2025-01-01',
      tags: [],
      logsource: { category: 'process_creation', product: 'windows' },
      detection: { selection: {}, condition: 'selection' },
      falsepositives: [],
      level: 'medium',
      raw: '',
    },
    sourceReportId: 'report-001',
    attackTechniqueId: techniqueId,
    attackTactic: tactic,
    confidence: 'high',
    validation: makeValidation(valid),
  };
}

// ---------------------------------------------------------------------------
// calculateCoverageMetrics
// ---------------------------------------------------------------------------

describe('calculateCoverageMetrics', () => {
  it('calculates 100% coverage when all techniques have rules', () => {
    const mappings = [
      makeMapping('T1059', 'execution'),
      makeMapping('T1071', 'command-and-control'),
    ];
    const rules = [
      makeGeneratedRule('T1059', 'execution'),
      makeGeneratedRule('T1071', 'command-and-control'),
    ];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.totalTechniques).toBe(2);
    expect(metrics.coveredTechniques).toBe(2);
    expect(metrics.coveragePercentage).toBe(100);
    expect(metrics.uncoveredTechniqueIds).toEqual([]);
  });

  it('calculates 50% coverage when half the techniques have rules', () => {
    const mappings = [
      makeMapping('T1059', 'execution'),
      makeMapping('T1071', 'command-and-control'),
    ];
    const rules = [
      makeGeneratedRule('T1059', 'execution'),
    ];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.totalTechniques).toBe(2);
    expect(metrics.coveredTechniques).toBe(1);
    expect(metrics.coveragePercentage).toBe(50);
  });

  it('calculates 0% coverage when no rules match', () => {
    const mappings = [
      makeMapping('T1059', 'execution'),
      makeMapping('T1071', 'command-and-control'),
    ];
    const rules: GeneratedRule[] = [];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.totalTechniques).toBe(2);
    expect(metrics.coveredTechniques).toBe(0);
    expect(metrics.coveragePercentage).toBe(0);
  });

  it('returns 0% for empty inputs', () => {
    const metrics = calculateCoverageMetrics([], []);
    expect(metrics.totalTechniques).toBe(0);
    expect(metrics.coveredTechniques).toBe(0);
    expect(metrics.coveragePercentage).toBe(0);
  });

  it('identifies covered and uncovered technique IDs', () => {
    const mappings = [
      makeMapping('T1059', 'execution'),
      makeMapping('T1071', 'command-and-control'),
      makeMapping('T1105', 'command-and-control'),
    ];
    const rules = [
      makeGeneratedRule('T1059', 'execution'),
      makeGeneratedRule('T1105', 'command-and-control'),
    ];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.coveredTechniqueIds).toContain('T1059');
    expect(metrics.coveredTechniqueIds).toContain('T1105');
    expect(metrics.uncoveredTechniqueIds).toContain('T1071');
  });

  it('does not count invalid rules as covering techniques', () => {
    const mappings = [makeMapping('T1059', 'execution')];
    const rules = [makeGeneratedRule('T1059', 'execution', false)]; // invalid

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.coveredTechniques).toBe(0);
  });

  it('handles subtechnique IDs (T1059.001)', () => {
    const mappings = [
      makeMapping('T1059.001', 'execution'),
      makeMapping('T1059.003', 'execution'),
    ];
    const rules = [makeGeneratedRule('T1059.001', 'execution')];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.totalTechniques).toBe(2);
    expect(metrics.coveredTechniques).toBe(1);
    expect(metrics.coveredTechniqueIds).toContain('T1059.001');
    expect(metrics.uncoveredTechniqueIds).toContain('T1059.003');
  });

  it('ignores invalid technique IDs from mappings', () => {
    const mappings = [
      makeMapping('T1059', 'execution'),
      makeMapping('INVALID', 'unknown'),
    ];
    const rules = [makeGeneratedRule('T1059', 'execution')];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.totalTechniques).toBe(1); // INVALID is filtered out
    expect(metrics.coveredTechniques).toBe(1);
  });

  it('includes technique IDs from rules not in mappings', () => {
    const mappings = [makeMapping('T1059', 'execution')];
    const rules = [
      makeGeneratedRule('T1059', 'execution'),
      makeGeneratedRule('T1071', 'command-and-control'), // not in mappings
    ];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.totalTechniques).toBe(2);
    expect(metrics.coveredTechniques).toBe(2);
  });

  it('deduplicates technique IDs across mappings and rules', () => {
    const mappings = [
      makeMapping('T1059', 'execution'),
      makeMapping('T1059', 'execution'), // duplicate
    ];
    const rules = [makeGeneratedRule('T1059', 'execution')];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.totalTechniques).toBe(1);
  });

  // --- Tactic breakdown ---

  it('provides per-tactic breakdown', () => {
    const mappings = [
      makeMapping('T1059', 'execution'),
      makeMapping('T1059.001', 'execution'),
      makeMapping('T1071', 'command-and-control'),
    ];
    const rules = [
      makeGeneratedRule('T1059', 'execution'),
      makeGeneratedRule('T1071', 'command-and-control'),
    ];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.tacticBreakdown).toHaveProperty('execution');
    expect(metrics.tacticBreakdown).toHaveProperty('command-and-control');

    expect(metrics.tacticBreakdown['execution'].total).toBe(2);
    expect(metrics.tacticBreakdown['execution'].covered).toBe(1);
    expect(metrics.tacticBreakdown['execution'].percentage).toBe(50);

    expect(metrics.tacticBreakdown['command-and-control'].total).toBe(1);
    expect(metrics.tacticBreakdown['command-and-control'].covered).toBe(1);
    expect(metrics.tacticBreakdown['command-and-control'].percentage).toBe(100);
  });

  it('normalizes tactic names to lowercase hyphenated', () => {
    const mappings = [
      makeMapping('T1059', 'Execution'),
      makeMapping('T1071', 'Command and Control'),
    ];
    const rules = [makeGeneratedRule('T1059', 'execution')];

    const metrics = calculateCoverageMetrics(rules, mappings);
    expect(metrics.tacticBreakdown).toHaveProperty('execution');
    expect(metrics.tacticBreakdown).toHaveProperty('command-and-control');
  });

  // --- Navigator layer ---

  it('generates a navigatorLayer with correct structure', () => {
    const mappings = [makeMapping('T1059', 'execution')];
    const rules = [makeGeneratedRule('T1059', 'execution')];

    const metrics = calculateCoverageMetrics(rules, mappings);
    const layer = metrics.navigatorLayer;

    expect(layer.name).toBe('DetectForge Coverage Layer');
    expect(layer.domain).toBe('enterprise-attack');
    expect(layer.versions).toHaveProperty('attack');
    expect(layer.versions).toHaveProperty('navigator');
    expect(layer.versions).toHaveProperty('layer');
    expect(layer.techniques).toHaveLength(1);
  });

  it('marks covered techniques with green and score 100', () => {
    const mappings = [makeMapping('T1059', 'execution')];
    const rules = [makeGeneratedRule('T1059', 'execution')];

    const metrics = calculateCoverageMetrics(rules, mappings);
    const tech = metrics.navigatorLayer.techniques[0];

    expect(tech.techniqueID).toBe('T1059');
    expect(tech.color).toBe('#31a354');
    expect(tech.score).toBe(100);
    expect(tech.enabled).toBe(true);
  });

  it('marks uncovered techniques with red and score 0', () => {
    const mappings = [makeMapping('T1059', 'execution')];
    const rules: GeneratedRule[] = [];

    const metrics = calculateCoverageMetrics(rules, mappings);
    const tech = metrics.navigatorLayer.techniques[0];

    expect(tech.color).toBe('#d73027');
    expect(tech.score).toBe(0);
    expect(tech.comment).toContain('No detection rule');
  });
});

// ---------------------------------------------------------------------------
// exportNavigatorLayer
// ---------------------------------------------------------------------------

describe('exportNavigatorLayer', () => {
  it('returns valid JSON string', () => {
    const mappings = [
      makeMapping('T1059', 'execution'),
      makeMapping('T1071', 'command-and-control'),
    ];
    const rules = [makeGeneratedRule('T1059', 'execution')];

    const metrics = calculateCoverageMetrics(rules, mappings);
    const json = exportNavigatorLayer(metrics);

    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('exported JSON contains the same layer data', () => {
    const mappings = [makeMapping('T1059', 'execution')];
    const rules = [makeGeneratedRule('T1059', 'execution')];

    const metrics = calculateCoverageMetrics(rules, mappings);
    const json = exportNavigatorLayer(metrics);
    const parsed = JSON.parse(json);

    expect(parsed.name).toBe('DetectForge Coverage Layer');
    expect(parsed.domain).toBe('enterprise-attack');
    expect(parsed.techniques).toHaveLength(1);
    expect(parsed.techniques[0].techniqueID).toBe('T1059');
  });

  it('is pretty-printed (indented)', () => {
    const mappings = [makeMapping('T1059', 'execution')];
    const rules = [makeGeneratedRule('T1059', 'execution')];

    const metrics = calculateCoverageMetrics(rules, mappings);
    const json = exportNavigatorLayer(metrics);

    // Pretty-printed JSON will have newlines
    expect(json).toContain('\n');
    // And indentation
    expect(json).toContain('  ');
  });

  it('handles empty metrics gracefully', () => {
    const metrics = calculateCoverageMetrics([], []);
    const json = exportNavigatorLayer(metrics);
    const parsed = JSON.parse(json);

    expect(parsed.techniques).toEqual([]);
    expect(parsed.description).toContain('0%');
  });
});
