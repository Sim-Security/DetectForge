/**
 * Unit tests for the Sigma AI prompt builder and response parser.
 *
 * Covers: buildSigmaGenerationPrompt, parseSigmaAIResponse, SigmaAIResponseSchema
 */

import { describe, it, expect, vi } from 'vitest';
import {
  buildSigmaGenerationPrompt,
  parseSigmaAIResponse,
  SigmaAIResponseSchema,
} from '@/ai/prompts/sigma-generation.js';
import type { SigmaAIResponse } from '@/ai/prompts/sigma-generation.js';
import type { SigmaTemplate } from '@/generation/sigma/templates.js';
import type { ExtractedTTP, AttackMappingResult, ExtractedIOC } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Mock the extractJsonFromResponse function so tests are isolated
// from the response-parser's repair logic.
// ---------------------------------------------------------------------------

vi.mock('@/ai/response-parser.js', () => ({
  extractJsonFromResponse: vi.fn((raw: string) => {
    let cleaned = raw.trim();

    // Remove markdown code blocks
    const codeBlockMatch = cleaned.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
    if (codeBlockMatch) {
      cleaned = codeBlockMatch[1].trim();
    }

    // Extract JSON object
    const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      cleaned = jsonMatch[0];
    }

    return JSON.parse(cleaned);
  }),
}));

// ---------------------------------------------------------------------------
// Fixture Builders
// ---------------------------------------------------------------------------

function makeTtp(overrides: Partial<ExtractedTTP> = {}): ExtractedTTP {
  return {
    description:
      'Threat actor uses PowerShell to download and execute a payload from a remote C2 server via Invoke-WebRequest.',
    tools: ['PowerShell', 'Invoke-WebRequest'],
    targetPlatforms: ['windows'],
    artifacts: [
      {
        type: 'process',
        description: 'powershell.exe with encoded command line',
        value: 'powershell.exe -enc',
      },
      {
        type: 'network',
        description: 'HTTP connection to C2 server',
        value: 'https://evil.example.com/payload.ps1',
      },
    ],
    detectionOpportunities: [
      'Monitor for powershell.exe with download cradle arguments',
      'Monitor network connections to suspicious domains',
    ],
    confidence: 'high',
    ...overrides,
  };
}

function makeMapping(
  overrides: Partial<AttackMappingResult> = {},
): AttackMappingResult {
  const ttp = makeTtp();
  return {
    techniqueId: 'T1059.001',
    techniqueName: 'PowerShell',
    tactic: 'execution',
    confidence: 'high',
    reasoning: 'The threat actor uses PowerShell to execute commands.',
    sourceTtp: ttp,
    suggestedRuleFormats: ['sigma'],
    validated: true,
    ...overrides,
  };
}

function makeTemplate(overrides: Partial<SigmaTemplate> = {}): SigmaTemplate {
  return {
    category: 'process_creation',
    logsource: { product: 'windows', category: 'process_creation' },
    availableFields: [
      'Image',
      'OriginalFileName',
      'CommandLine',
      'ParentImage',
      'ParentCommandLine',
      'User',
      'IntegrityLevel',
      'Hashes',
    ],
    commonFalsePositives: [
      'Legitimate administrative scripts',
      'Software installers',
    ],
    exampleDetection: {
      selection: { Image: ['*\\suspicious.exe'] },
      condition: 'selection',
    },
    ...overrides,
  };
}

function makeIocs(overrides?: Partial<ExtractedIOC>[]): ExtractedIOC[] {
  const defaults: ExtractedIOC[] = [
    {
      value: '198.51.100.42',
      type: 'ipv4',
      context: 'C2 server IP address',
      confidence: 'high',
      defanged: false,
      originalValue: '198.51.100.42',
      relationships: [],
    },
    {
      value: 'evil.example.com',
      type: 'domain',
      context: 'C2 domain',
      confidence: 'high',
      defanged: false,
      originalValue: 'evil[.]example[.]com',
      relationships: [],
    },
    {
      value: 'C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe',
      type: 'filepath_windows',
      context: 'Dropped payload location',
      confidence: 'medium',
      defanged: false,
      originalValue: 'C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe',
      relationships: [],
    },
  ];
  if (overrides) {
    return overrides.map((o, i) => ({ ...defaults[i % defaults.length], ...o }));
  }
  return defaults;
}

function makeValidAIResponse(): Record<string, unknown> {
  return {
    title: 'Suspicious PowerShell Download Cradle Execution',
    description:
      'Detects PowerShell execution with download cradle patterns commonly used to fetch remote payloads.',
    tags: ['attack.execution', 'attack.t1059.001'],
    logsource: { product: 'windows', category: 'process_creation' },
    detection: {
      selection: {
        Image: ['*\\powershell.exe', '*\\pwsh.exe'],
        CommandLine: ['*Invoke-WebRequest*', '*DownloadString*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate administrative download scripts'],
    level: 'high',
  };
}

// ===========================================================================
// buildSigmaGenerationPrompt
// ===========================================================================

describe('buildSigmaGenerationPrompt', () => {
  const ttp = makeTtp();
  const mapping = makeMapping();
  const template = makeTemplate();
  const iocs = makeIocs();

  it('returns an object with system and user string properties', () => {
    const result = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
    expect(result).toHaveProperty('system');
    expect(result).toHaveProperty('user');
    expect(typeof result.system).toBe('string');
    expect(typeof result.user).toBe('string');
  });

  // -----------------------------------------------------------------------
  // System prompt checks
  // -----------------------------------------------------------------------

  describe('system prompt', () => {
    it('contains Sigma specification reference', () => {
      const { system } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(system).toContain('Sigma');
      expect(system).toContain('Sigma Rule Specification');
    });

    it('includes template logsource info', () => {
      const { system } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(system).toContain('product: windows');
      expect(system).toContain('category: process_creation');
    });

    it('includes template logsource service when present', () => {
      const psTemplate = makeTemplate({
        category: 'ps_script',
        logsource: {
          product: 'windows',
          category: 'ps_script',
          service: 'powershell',
        },
      });
      const { system } = buildSigmaGenerationPrompt(
        ttp,
        mapping,
        psTemplate,
        iocs,
      );
      expect(system).toContain('service: powershell');
    });

    it('includes template available fields', () => {
      const { system } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      for (const field of template.availableFields) {
        expect(system).toContain(field);
      }
    });

    it('includes example detection block', () => {
      const { system } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(system).toContain('Example Detection Block');
      expect(system).toContain('suspicious.exe');
    });

    it('instructs model to respond with JSON only', () => {
      const { system } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(system).toContain('JSON');
    });

    it('mentions valid level values', () => {
      const { system } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(system).toContain('informational');
      expect(system).toContain('low');
      expect(system).toContain('medium');
      expect(system).toContain('high');
      expect(system).toContain('critical');
    });

    it('includes detection block rules about condition syntax', () => {
      const { system } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(system).toContain('condition');
      expect(system).toContain('selection');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt checks
  // -----------------------------------------------------------------------

  describe('user prompt', () => {
    it('includes ATT&CK technique info', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(user).toContain('T1059.001');
      expect(user).toContain('PowerShell');
      expect(user).toContain('execution');
    });

    it('includes TTP description', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(user).toContain(ttp.description);
    });

    it('includes tools used', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(user).toContain('PowerShell');
      expect(user).toContain('Invoke-WebRequest');
    });

    it('includes artifacts observed', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(user).toContain('[process]');
      expect(user).toContain('powershell.exe with encoded command line');
      expect(user).toContain('[network]');
    });

    it('includes detection opportunities', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(user).toContain('Monitor for powershell.exe');
    });

    it('includes IOCs when provided', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      // process_creation category filters to filepath/hash/domain/url — ipv4 is excluded
      expect(user).toContain('evil.example.com');
      expect(user).toContain('payload.exe');
    });

    it('handles empty IOCs gracefully', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, []);
      // Should not throw and should contain placeholder text
      expect(user).toContain('None available');
      expect(typeof user).toBe('string');
    });

    it('handles empty tools gracefully', () => {
      const noToolsTtp = makeTtp({ tools: [] });
      const { user } = buildSigmaGenerationPrompt(
        noToolsTtp,
        mapping,
        template,
        iocs,
      );
      expect(user).toContain('None specified');
    });

    it('handles empty artifacts gracefully', () => {
      const noArtifactsTtp = makeTtp({ artifacts: [] });
      const { user } = buildSigmaGenerationPrompt(
        noArtifactsTtp,
        mapping,
        template,
        iocs,
      );
      expect(user).toContain('None specified');
    });

    it('handles empty detection opportunities gracefully', () => {
      const noDetOpsTtp = makeTtp({ detectionOpportunities: [] });
      const { user } = buildSigmaGenerationPrompt(
        noDetOpsTtp,
        mapping,
        template,
        iocs,
      );
      expect(user).toContain('None specified');
    });

    it('includes mapping confidence and reasoning', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(user).toContain('high');
      expect(user).toContain(
        'The threat actor uses PowerShell to execute commands.',
      );
    });

    it('includes template category name', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(user).toContain('process_creation');
    });

    it('includes available fields list', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      for (const field of template.availableFields) {
        expect(user).toContain(field);
      }
    });

    it('includes artifact values when present', () => {
      const { user } = buildSigmaGenerationPrompt(ttp, mapping, template, iocs);
      expect(user).toContain('powershell.exe -enc');
    });
  });

  // -----------------------------------------------------------------------
  // IOC filtering by category
  // -----------------------------------------------------------------------

  describe('IOC filtering by template category', () => {
    const networkTemplate = makeTemplate({
      category: 'network_connection',
      logsource: { product: 'windows', category: 'network_connection' },
      availableFields: ['DestinationIp', 'DestinationHostname', 'DestinationPort'],
    });

    const registryTemplate = makeTemplate({
      category: 'registry_event',
      logsource: { product: 'windows', category: 'registry_set' },
      availableFields: ['TargetObject', 'Details'],
    });

    it('network_connection template includes IP and domain IOCs', () => {
      const { user } = buildSigmaGenerationPrompt(
        ttp,
        mapping,
        networkTemplate,
        iocs,
      );
      expect(user).toContain('198.51.100.42');
      expect(user).toContain('evil.example.com');
    });

    it('network_connection template excludes filepath IOCs', () => {
      const { user } = buildSigmaGenerationPrompt(
        ttp,
        mapping,
        networkTemplate,
        iocs,
      );
      // filepath IOC should be filtered out for network categories
      expect(user).not.toContain('payload.exe');
    });

    it('process_creation template includes filepath IOCs', () => {
      const { user } = buildSigmaGenerationPrompt(
        ttp,
        mapping,
        template, // process_creation
        iocs,
      );
      expect(user).toContain('payload.exe');
    });
  });
});

// ===========================================================================
// parseSigmaAIResponse
// ===========================================================================

describe('parseSigmaAIResponse', () => {
  // -----------------------------------------------------------------------
  // Valid responses
  // -----------------------------------------------------------------------

  describe('valid responses', () => {
    it('parses a valid JSON response', () => {
      const response = makeValidAIResponse();
      const raw = JSON.stringify(response);
      const result = parseSigmaAIResponse(raw);
      expect(result.title).toBe(response.title);
      expect(result.description).toBe(response.description);
      expect(result.tags).toEqual(response.tags);
      expect(result.level).toBe('high');
    });

    it('parses markdown-wrapped JSON response', () => {
      const response = makeValidAIResponse();
      const raw = '```json\n' + JSON.stringify(response, null, 2) + '\n```';
      const result = parseSigmaAIResponse(raw);
      expect(result.title).toBe(response.title);
      expect(result.level).toBe('high');
    });

    it('parses JSON with surrounding text', () => {
      const response = makeValidAIResponse();
      const raw =
        'Here is the generated Sigma rule:\n\n' +
        JSON.stringify(response) +
        '\n\nLet me know if you need changes.';
      const result = parseSigmaAIResponse(raw);
      expect(result.title).toBe(response.title);
    });

    it('accepts all valid level values', () => {
      const levels = [
        'informational',
        'low',
        'medium',
        'high',
        'critical',
      ] as const;
      for (const level of levels) {
        const response = { ...makeValidAIResponse(), level };
        const raw = JSON.stringify(response);
        const result = parseSigmaAIResponse(raw);
        expect(result.level).toBe(level);
      }
    });

    it('provides default empty array for falsepositives when omitted', () => {
      const response = makeValidAIResponse();
      delete (response as any).falsepositives;
      const raw = JSON.stringify(response);
      const result = parseSigmaAIResponse(raw);
      expect(result.falsepositives).toEqual([]);
    });

    it('preserves falsepositives when provided', () => {
      const response = makeValidAIResponse();
      response.falsepositives = ['Admin scripts', 'CI/CD pipelines'];
      const raw = JSON.stringify(response);
      const result = parseSigmaAIResponse(raw);
      expect(result.falsepositives).toEqual(['Admin scripts', 'CI/CD pipelines']);
    });

    it('preserves detection block with multiple selections', () => {
      const response = {
        ...makeValidAIResponse(),
        detection: {
          selection_proc: { Image: ['*\\powershell.exe'] },
          selection_cmd: { CommandLine: ['*-enc*'] },
          filter_admin: { User: ['SYSTEM'] },
          condition: 'selection_proc and selection_cmd and not filter_admin',
        },
      };
      const raw = JSON.stringify(response);
      const result = parseSigmaAIResponse(raw);
      expect(result.detection).toHaveProperty('selection_proc');
      expect(result.detection).toHaveProperty('selection_cmd');
      expect(result.detection).toHaveProperty('filter_admin');
      expect(result.detection.condition).toContain('not filter_admin');
    });
  });

  // -----------------------------------------------------------------------
  // Invalid responses
  // -----------------------------------------------------------------------

  describe('invalid responses', () => {
    it('rejects too-short title (under 10 chars)', () => {
      const response = { ...makeValidAIResponse(), title: 'Short' };
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects too-long title (over 256 chars)', () => {
      const response = { ...makeValidAIResponse(), title: 'A'.repeat(257) };
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects too-short description (under 20 chars)', () => {
      const response = { ...makeValidAIResponse(), description: 'Too short.' };
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects missing tags (empty array)', () => {
      const response = { ...makeValidAIResponse(), tags: [] };
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects missing tags field entirely', () => {
      const response = makeValidAIResponse();
      delete (response as any).tags;
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects missing condition in detection', () => {
      const response = {
        ...makeValidAIResponse(),
        detection: {
          selection: { Image: ['*\\cmd.exe'] },
        },
      };
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects non-string condition in detection', () => {
      const response = {
        ...makeValidAIResponse(),
        detection: {
          selection: { Image: ['*\\cmd.exe'] },
          condition: 123,
        },
      };
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects invalid level value', () => {
      const response = { ...makeValidAIResponse(), level: 'urgent' };
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects missing level', () => {
      const response = makeValidAIResponse();
      delete (response as any).level;
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects missing logsource', () => {
      const response = makeValidAIResponse();
      delete (response as any).logsource;
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects missing logsource product', () => {
      const response = {
        ...makeValidAIResponse(),
        logsource: { category: 'process_creation' },
      };
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('rejects missing detection field entirely', () => {
      const response = makeValidAIResponse();
      delete (response as any).detection;
      const raw = JSON.stringify(response);
      expect(() => parseSigmaAIResponse(raw)).toThrow();
    });

    it('throws with descriptive error message referencing validation failures', () => {
      const response = {
        ...makeValidAIResponse(),
        title: 'Short',
        tags: [],
      };
      const raw = JSON.stringify(response);
      try {
        parseSigmaAIResponse(raw);
        // Should not reach here
        expect.unreachable('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('validation failed');
      }
    });

    it('throws on completely unparseable string', () => {
      expect(() =>
        parseSigmaAIResponse('This is not JSON at all.'),
      ).toThrow();
    });
  });
});

// ===========================================================================
// SigmaAIResponseSchema (direct Zod validation)
// ===========================================================================

describe('SigmaAIResponseSchema', () => {
  it('parses a fully valid object', () => {
    const valid = makeValidAIResponse();
    const result = SigmaAIResponseSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('title minimum length is 10', () => {
    const obj = { ...makeValidAIResponse(), title: '123456789' }; // 9 chars
    const result = SigmaAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('title maximum length is 256', () => {
    const obj = { ...makeValidAIResponse(), title: 'X'.repeat(256) };
    const resultOk = SigmaAIResponseSchema.safeParse(obj);
    expect(resultOk.success).toBe(true);

    const obj2 = { ...makeValidAIResponse(), title: 'X'.repeat(257) };
    const resultBad = SigmaAIResponseSchema.safeParse(obj2);
    expect(resultBad.success).toBe(false);
  });

  it('description minimum length is 20', () => {
    const obj = {
      ...makeValidAIResponse(),
      description: '1234567890123456789', // 19 chars
    };
    const result = SigmaAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('tags must have at least one entry', () => {
    const obj = { ...makeValidAIResponse(), tags: [] };
    const result = SigmaAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('detection must have condition key as string', () => {
    const noCondition = {
      ...makeValidAIResponse(),
      detection: { selection: {} },
    };
    expect(SigmaAIResponseSchema.safeParse(noCondition).success).toBe(false);

    const numCondition = {
      ...makeValidAIResponse(),
      detection: { selection: {}, condition: 42 },
    };
    expect(SigmaAIResponseSchema.safeParse(numCondition).success).toBe(false);
  });

  it('level must be one of the valid enum values', () => {
    const obj = { ...makeValidAIResponse(), level: 'danger' };
    const result = SigmaAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('falsepositives defaults to empty array when not present', () => {
    const obj = makeValidAIResponse();
    delete (obj as any).falsepositives;
    const result = SigmaAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.falsepositives).toEqual([]);
    }
  });

  it('logsource category and service are optional', () => {
    const obj = {
      ...makeValidAIResponse(),
      logsource: { product: 'windows' },
    };
    const result = SigmaAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(true);
  });

  it('logsource product is required', () => {
    const obj = {
      ...makeValidAIResponse(),
      logsource: { category: 'process_creation' },
    };
    const result = SigmaAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });
});
