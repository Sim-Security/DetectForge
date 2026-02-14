/**
 * Unit tests for the behavioral feedback loop in Sigma rule generation.
 *
 * Tests:
 * - assessBehavioralQuality rejects tool-signature-only rules
 * - assessBehavioralQuality accepts behavioral rules
 * - buildBehavioralFeedback generates proper feedback text
 * - buildSigmaGenerationPrompt accepts and appends feedback
 */

import { describe, it, expect, vi } from 'vitest';
import { assessBehavioralQuality, buildBehavioralFeedback } from '@/generation/sigma/generator.js';
import { buildSigmaGenerationPrompt } from '@/ai/prompts/sigma-generation.js';
import type { SigmaRule } from '@/types/detection-rule.js';
import type { ExtractedTTP, AttackMappingResult, ExtractedIOC } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Mock the logsource catalog
// ---------------------------------------------------------------------------

vi.mock('@/knowledge/logsource-catalog/index.js', () => ({
  validateSigmaLogsource: vi.fn(() => true),
  getFieldsForLogsource: vi.fn(() => []),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(detection: Record<string, unknown>): SigmaRule {
  return {
    id: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    title: 'Test Rule',
    status: 'experimental',
    description: 'Test rule for feedback loop testing.',
    references: [],
    author: 'DetectForge',
    date: '2026/02/12',
    modified: '2026/02/12',
    tags: ['attack.credential_access', 'attack.t1003.001'],
    logsource: { product: 'windows', category: 'process_creation' },
    detection,
    falsepositives: ['Legitimate admin activity'],
    level: 'high',
    raw: '',
  };
}

function makeTtp(): ExtractedTTP {
  return {
    id: 'ttp-1',
    description: 'Credential dumping via LSASS memory access',
    tools: ['mimikatz'],
    artifacts: [],
    detectionOpportunities: ['Process accessing LSASS memory'],
    confidence: 0.9,
    rawText: 'Test TTP',
  };
}

function makeMapping(): AttackMappingResult {
  return {
    techniqueId: 'T1003.001',
    techniqueName: 'LSASS Memory',
    tactic: 'credential_access',
    confidence: 0.9,
    reasoning: 'Direct LSASS access',
    suggestedRuleFormats: ['sigma'],
    sourceTtp: makeTtp(),
  };
}

function makeTemplate() {
  return {
    category: 'process_creation',
    logsource: { product: 'windows', category: 'process_creation' },
    availableFields: ['Image', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'User'],
    exampleDetection: {
      selection: { Image: ['*\\cmd.exe'] },
      condition: 'selection',
    },
  };
}

// ===========================================================================
// assessBehavioralQuality
// ===========================================================================

describe('assessBehavioralQuality', () => {
  it('rejects rule with only tool-specific Image and no behavioral fields', () => {
    const rule = makeRule({
      selection: { Image: '*\\mimikatz.exe' },
      condition: 'selection',
    });
    const result = assessBehavioralQuality(rule);
    expect(result.acceptable).toBe(false);
    expect(result.reasons).toHaveLength(2); // tool-signature + single variant
    expect(result.reasons[0]).toContain('tool-specific filename');
    expect(result.reasons[0]).toContain('mimikatz.exe');
  });

  it('accepts rule with GrantedAccess and TargetImage (behavioral fields)', () => {
    const rule = makeRule({
      selection_target: { 'TargetImage|endswith': '\\lsass.exe' },
      selection_access: { GrantedAccess: ['0x1010', '0x1038'] },
      filter_av: { SourceImage: ['*\\MsMpEng.exe'] },
      condition: 'selection_target and selection_access and not filter_av',
    });
    const result = assessBehavioralQuality(rule);
    expect(result.acceptable).toBe(true);
    expect(result.reasons).toHaveLength(0);
  });

  it('accepts multi-variant rule even with some tool names', () => {
    const rule = makeRule({
      selection_comsvcs: { 'CommandLine|contains|all': ['comsvcs', 'MiniDump'] },
      selection_procdump: { 'CommandLine|contains': 'procdump' },
      selection_generic: { 'CommandLine|contains': 'lsass' },
      filter_av: { Image: ['*\\MsMpEng.exe'] },
      condition: '(selection_comsvcs or selection_procdump or selection_generic) and not filter_av',
    });
    const result = assessBehavioralQuality(rule);
    expect(result.acceptable).toBe(true);
  });

  it('rejects single-variant rule with no behavioral fields', () => {
    const rule = makeRule({
      selection: { 'CommandLine|contains': 'suspicious_thing' },
      condition: 'selection',
    });
    const result = assessBehavioralQuality(rule);
    expect(result.acceptable).toBe(false);
    expect(result.reasons).toContain('Single variant with no behavioral fields');
  });

  it('accepts rule with CallTrace behavioral field', () => {
    const rule = makeRule({
      selection: { CallTrace: '*UNKNOWN*' },
      condition: 'selection',
    });
    const result = assessBehavioralQuality(rule);
    expect(result.acceptable).toBe(true);
  });
});

// ===========================================================================
// buildBehavioralFeedback
// ===========================================================================

describe('buildBehavioralFeedback', () => {
  it('includes tool names in feedback', () => {
    const rule = makeRule({
      selection: { Image: '*\\mimikatz.exe' },
      condition: 'selection',
    });
    const feedback = buildBehavioralFeedback(rule);
    expect(feedback).toContain('mimikatz.exe');
    expect(feedback).toContain('BEHAVIORAL FEEDBACK');
  });

  it('includes behavioral field suggestions', () => {
    const rule = makeRule({
      selection: { Image: '*\\custom_tool.exe' },
      condition: 'selection',
    });
    const feedback = buildBehavioralFeedback(rule);
    expect(feedback).toContain('GrantedAccess');
    expect(feedback).toContain('ParentImage');
    expect(feedback).toContain('CallTrace');
    expect(feedback).toContain('TargetObject');
    expect(feedback).toContain('TECHNIQUE');
    expect(feedback).toContain('TOOL');
  });
});

// ===========================================================================
// buildSigmaGenerationPrompt with feedback
// ===========================================================================

describe('buildSigmaGenerationPrompt with behavioral feedback', () => {
  it('appends feedback to user prompt when provided', () => {
    const result = buildSigmaGenerationPrompt(
      makeTtp(),
      makeMapping(),
      makeTemplate(),
      [],
      undefined,
      'BEHAVIORAL FEEDBACK: Your previous rule was rejected.',
    );
    expect(result.user).toContain('BEHAVIORAL FEEDBACK');
    expect(result.user).toContain('rejected');
  });

  it('does not append feedback when not provided', () => {
    const result = buildSigmaGenerationPrompt(
      makeTtp(),
      makeMapping(),
      makeTemplate(),
      [],
    );
    expect(result.user).not.toContain('BEHAVIORAL FEEDBACK');
  });

  it('preserves original prompt content with feedback', () => {
    const withFeedback = buildSigmaGenerationPrompt(
      makeTtp(),
      makeMapping(),
      makeTemplate(),
      [],
      undefined,
      'Test feedback',
    );
    const withoutFeedback = buildSigmaGenerationPrompt(
      makeTtp(),
      makeMapping(),
      makeTemplate(),
      [],
    );
    // Both should contain the technique info
    expect(withFeedback.user).toContain('T1003.001');
    expect(withoutFeedback.user).toContain('T1003.001');
    // Only the feedback version has the extra content
    expect(withFeedback.user).toContain('Test feedback');
    expect(withoutFeedback.user).not.toContain('Test feedback');
  });
});
