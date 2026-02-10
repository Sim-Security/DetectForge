/**
 * Unit tests for the Sigma rule template system.
 *
 * Covers: getTemplate, getAllTemplates, getSuggestedCategory
 */

import { describe, it, expect } from 'vitest';
import {
  getTemplate,
  getAllTemplates,
  getSuggestedCategory,
} from '@/generation/sigma/templates.js';
import type { SigmaTemplate } from '@/generation/sigma/templates.js';
import type { ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Helpers — build minimal TTP and Mapping fixtures
// ---------------------------------------------------------------------------

function makeTtp(overrides: Partial<ExtractedTTP> = {}): ExtractedTTP {
  return {
    description: 'Test TTP description for unit testing',
    tools: [],
    targetPlatforms: ['windows'],
    artifacts: [],
    detectionOpportunities: [],
    confidence: 'medium',
    ...overrides,
  };
}

function makeMapping(
  overrides: Partial<AttackMappingResult> = {},
): AttackMappingResult {
  const ttp = makeTtp();
  return {
    techniqueId: 'T9999',
    techniqueName: 'Unknown Technique',
    tactic: 'unknown-tactic',
    confidence: 'medium',
    reasoning: 'Unit test fixture',
    sourceTtp: ttp,
    suggestedRuleFormats: ['sigma'],
    validated: true,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// All 10 registered categories
// ---------------------------------------------------------------------------

const ALL_CATEGORIES = [
  'process_creation',
  'image_load',
  'file_event',
  'registry_event',
  'network_connection',
  'dns_query',
  'pipe_created',
  'wmi_event',
  'ps_script',
  'security',
] as const;

// ===========================================================================
// getTemplate
// ===========================================================================

describe('getTemplate', () => {
  it.each(ALL_CATEGORIES)(
    'returns a valid template for category "%s"',
    (category) => {
      const template = getTemplate(category);
      expect(template).toBeDefined();
      expect(template!.category).toBe(category);
    },
  );

  it('returns undefined for an unknown category', () => {
    expect(getTemplate('nonexistent_category')).toBeUndefined();
  });

  it('returns undefined for an empty string', () => {
    expect(getTemplate('')).toBeUndefined();
  });

  it('is case-sensitive (uppercase category returns undefined)', () => {
    expect(getTemplate('PROCESS_CREATION')).toBeUndefined();
  });
});

// ===========================================================================
// getAllTemplates
// ===========================================================================

describe('getAllTemplates', () => {
  it('returns exactly 10 templates', () => {
    const templates = getAllTemplates();
    expect(templates).toHaveLength(10);
  });

  it('returns an array of SigmaTemplate objects', () => {
    const templates = getAllTemplates();
    expect(Array.isArray(templates)).toBe(true);
  });

  it('contains all expected categories', () => {
    const templates = getAllTemplates();
    const categories = templates.map((t) => t.category);
    for (const expected of ALL_CATEGORIES) {
      expect(categories).toContain(expected);
    }
  });

  it('returns a new array each time (not a shared reference)', () => {
    const a = getAllTemplates();
    const b = getAllTemplates();
    expect(a).not.toBe(b);
    expect(a).toEqual(b);
  });
});

// ===========================================================================
// Template structure validation
// ===========================================================================

describe('template structure', () => {
  const templates = getAllTemplates();

  it.each(templates.map((t) => [t.category, t] as const))(
    '"%s" has all required fields',
    (_category, template) => {
      expect(template).toHaveProperty('category');
      expect(template).toHaveProperty('logsource');
      expect(template).toHaveProperty('availableFields');
      expect(template).toHaveProperty('commonFalsePositives');
      expect(template).toHaveProperty('exampleDetection');
    },
  );

  it.each(templates.map((t) => [t.category, t] as const))(
    '"%s" logsource has product="windows"',
    (_category, template) => {
      expect(template.logsource.product).toBe('windows');
    },
  );

  it.each(templates.map((t) => [t.category, t] as const))(
    '"%s" exampleDetection has a "condition" key',
    (_category, template) => {
      expect(template.exampleDetection).toHaveProperty('condition');
      expect(typeof template.exampleDetection['condition']).toBe('string');
    },
  );

  it.each(templates.map((t) => [t.category, t] as const))(
    '"%s" availableFields is a non-empty array of strings',
    (_category, template) => {
      expect(Array.isArray(template.availableFields)).toBe(true);
      expect(template.availableFields.length).toBeGreaterThan(0);
      for (const field of template.availableFields) {
        expect(typeof field).toBe('string');
      }
    },
  );

  it.each(templates.map((t) => [t.category, t] as const))(
    '"%s" commonFalsePositives is a non-empty array of strings',
    (_category, template) => {
      expect(Array.isArray(template.commonFalsePositives)).toBe(true);
      expect(template.commonFalsePositives.length).toBeGreaterThan(0);
      for (const fp of template.commonFalsePositives) {
        expect(typeof fp).toBe('string');
      }
    },
  );

  it('process_creation template has CommandLine in availableFields', () => {
    const t = getTemplate('process_creation')!;
    expect(t.availableFields).toContain('CommandLine');
    expect(t.availableFields).toContain('Image');
    expect(t.availableFields).toContain('ParentImage');
  });

  it('ps_script template has logsource service="powershell"', () => {
    const t = getTemplate('ps_script')!;
    expect(t.logsource.service).toBe('powershell');
  });

  it('security template has logsource service="security" and no category', () => {
    const t = getTemplate('security')!;
    expect(t.logsource.service).toBe('security');
    expect(t.logsource.category).toBeUndefined();
  });

  it('network_connection template has DestinationIp in availableFields', () => {
    const t = getTemplate('network_connection')!;
    expect(t.availableFields).toContain('DestinationIp');
    expect(t.availableFields).toContain('DestinationPort');
  });
});

// ===========================================================================
// getSuggestedCategory
// ===========================================================================

describe('getSuggestedCategory', () => {
  // -----------------------------------------------------------------------
  // 1. Specific sub-technique ID match
  // -----------------------------------------------------------------------

  describe('specific technique ID match', () => {
    it('T1059.001 returns ps_script and process_creation', () => {
      const ttp = makeTtp();
      const mapping = makeMapping({
        techniqueId: 'T1059.001',
        tactic: 'execution',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('ps_script');
      expect(result).toContain('process_creation');
    });

    it('T1547.001 returns registry_event', () => {
      const ttp = makeTtp();
      const mapping = makeMapping({
        techniqueId: 'T1547.001',
        tactic: 'persistence',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('registry_event');
    });

    it('T1071.004 returns dns_query', () => {
      const ttp = makeTtp();
      const mapping = makeMapping({
        techniqueId: 'T1071.004',
        tactic: 'command-and-control',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('dns_query');
    });

    it('T1047 returns wmi_event and process_creation', () => {
      const ttp = makeTtp();
      const mapping = makeMapping({
        techniqueId: 'T1047',
        tactic: 'execution',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('wmi_event');
      expect(result).toContain('process_creation');
    });
  });

  // -----------------------------------------------------------------------
  // 2. Parent technique fallback
  // -----------------------------------------------------------------------

  describe('parent technique fallback', () => {
    it('T1547 returns registry_event and process_creation', () => {
      const ttp = makeTtp();
      const mapping = makeMapping({
        techniqueId: 'T1547',
        tactic: 'persistence',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('registry_event');
      expect(result).toContain('process_creation');
    });

    it('sub-technique also includes parent technique results', () => {
      const ttp = makeTtp();
      // T1574.001 maps to image_load; parent T1574 maps to image_load, file_event, process_creation
      const mapping = makeMapping({
        techniqueId: 'T1574.001',
        tactic: 'persistence',
      });
      const result = getSuggestedCategory(ttp, mapping);
      // From the sub-technique
      expect(result).toContain('image_load');
      // From the parent technique
      expect(result).toContain('file_event');
      expect(result).toContain('process_creation');
    });
  });

  // -----------------------------------------------------------------------
  // 3. Tactic-based fallback
  // -----------------------------------------------------------------------

  describe('tactic-based fallback', () => {
    it('falls back to tactic when no technique match exists', () => {
      const ttp = makeTtp();
      // T9999 does not exist in TECHNIQUE_TO_CATEGORIES
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'execution',
      });
      const result = getSuggestedCategory(ttp, mapping);
      // 'execution' tactic maps to process_creation and ps_script
      expect(result).toContain('process_creation');
      expect(result).toContain('ps_script');
    });

    it('normalizes tactic with spaces to kebab-case', () => {
      const ttp = makeTtp();
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'Command and Control',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('network_connection');
      expect(result).toContain('dns_query');
    });

    it('normalizes tactic to lowercase before lookup', () => {
      const ttp = makeTtp();
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'LATERAL-MOVEMENT',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('security');
      expect(result).toContain('network_connection');
    });

    it('tactic results are merged with technique results (no duplicates)', () => {
      const ttp = makeTtp();
      const mapping = makeMapping({
        techniqueId: 'T1059.001',
        tactic: 'execution',
      });
      const result = getSuggestedCategory(ttp, mapping);
      // T1059.001 -> ps_script, process_creation
      // execution  -> process_creation, ps_script
      // Deduplicated via Set
      const uniqueCheck = new Set(result);
      expect(uniqueCheck.size).toBe(result.length);
      expect(result).toContain('ps_script');
      expect(result).toContain('process_creation');
    });
  });

  // -----------------------------------------------------------------------
  // 4. Artifact heuristic fallback
  // -----------------------------------------------------------------------

  describe('artifact heuristic fallback', () => {
    it('uses artifact heuristic when no technique or tactic match', () => {
      const ttp = makeTtp({
        artifacts: [
          { type: 'process', description: 'suspicious process spawn' },
        ],
      });
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'totally-unknown-tactic',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('process_creation');
    });

    it('process artifact returns process_creation', () => {
      const ttp = makeTtp({
        artifacts: [{ type: 'process', description: 'cmd.exe spawned' }],
      });
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'no-match-tactic',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('process_creation');
    });

    it('file artifact returns file_event', () => {
      const ttp = makeTtp({
        artifacts: [{ type: 'file', description: 'dropped payload' }],
      });
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'no-match-tactic',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('file_event');
    });

    it('registry artifact returns registry_event', () => {
      const ttp = makeTtp({
        artifacts: [
          { type: 'registry', description: 'modified Run key' },
        ],
      });
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'no-match-tactic',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('registry_event');
    });

    it('network artifact returns network_connection', () => {
      const ttp = makeTtp({
        artifacts: [
          { type: 'network', description: 'C2 callback over HTTPS' },
        ],
      });
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'no-match-tactic',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('network_connection');
    });

    it('event_log artifact returns security', () => {
      const ttp = makeTtp({
        artifacts: [
          { type: 'event_log', description: 'logon event 4624' },
        ],
      });
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'no-match-tactic',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('security');
    });

    it('other artifact type defaults to process_creation', () => {
      const ttp = makeTtp({
        artifacts: [
          { type: 'other', description: 'unknown artifact type' },
        ],
      });
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'no-match-tactic',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('process_creation');
    });

    it('multiple artifact types produce multiple categories', () => {
      const ttp = makeTtp({
        artifacts: [
          { type: 'file', description: 'dropped file' },
          { type: 'network', description: 'C2 beacon' },
          { type: 'registry', description: 'persistence key' },
        ],
      });
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'no-match-tactic',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toContain('file_event');
      expect(result).toContain('network_connection');
      expect(result).toContain('registry_event');
    });
  });

  // -----------------------------------------------------------------------
  // 5. Default fallback
  // -----------------------------------------------------------------------

  describe('default fallback', () => {
    it('defaults to process_creation when everything else fails', () => {
      const ttp = makeTtp({ artifacts: [] });
      const mapping = makeMapping({
        techniqueId: 'T9999',
        tactic: 'no-match-tactic',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toEqual(['process_creation']);
    });

    it('defaults to process_creation when TTP has empty artifacts and unknown technique/tactic', () => {
      const ttp = makeTtp({
        artifacts: [],
        tools: [],
        detectionOpportunities: [],
      });
      const mapping = makeMapping({
        techniqueId: 'T0000',
        tactic: 'xyz-nonexistent',
      });
      const result = getSuggestedCategory(ttp, mapping);
      expect(result).toHaveLength(1);
      expect(result[0]).toBe('process_creation');
    });
  });

  // -----------------------------------------------------------------------
  // 6. Return value structure
  // -----------------------------------------------------------------------

  describe('return value structure', () => {
    it('always returns an array', () => {
      const ttp = makeTtp();
      const mapping = makeMapping();
      const result = getSuggestedCategory(ttp, mapping);
      expect(Array.isArray(result)).toBe(true);
    });

    it('returns at least one category', () => {
      const ttp = makeTtp();
      const mapping = makeMapping();
      const result = getSuggestedCategory(ttp, mapping);
      expect(result.length).toBeGreaterThanOrEqual(1);
    });

    it('returns no duplicate categories', () => {
      const ttp = makeTtp();
      const mapping = makeMapping({
        techniqueId: 'T1059.001',
        tactic: 'execution',
      });
      const result = getSuggestedCategory(ttp, mapping);
      const unique = new Set(result);
      expect(unique.size).toBe(result.length);
    });
  });
});
