/**
 * Unit tests for the coverage gap analysis AI prompt builder and response parser.
 *
 * Covers: buildGapAnalysisPrompt, parseGapAnalysisAIResponse, GapAnalysisAIResponseSchema
 */

import { describe, it, expect, vi } from 'vitest';
import {
  buildGapAnalysisPrompt,
  parseGapAnalysisAIResponse,
  GapAnalysisAIResponseSchema,
} from '@/ai/prompts/gap-analysis.js';
import type { GapAnalysisAIResponse } from '@/ai/prompts/gap-analysis.js';
import type { GeneratedRule } from '@/types/detection-rule.js';
import type { ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';

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

function makeTTP(overrides: Partial<ExtractedTTP> = {}): ExtractedTTP {
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
  const ttp = makeTTP();
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

function makeRule(overrides: Partial<GeneratedRule> = {}): GeneratedRule {
  return {
    format: 'sigma',
    sigma: {
      id: 'abc-123',
      title: 'Suspicious PowerShell Download Cradle',
      status: 'experimental',
      description: 'Detects PowerShell execution with download cradle patterns.',
      references: [],
      author: 'DetectForge',
      date: '2026-02-10',
      modified: '2026-02-10',
      tags: ['attack.execution', 'attack.t1059.001'],
      logsource: { product: 'windows', category: 'process_creation' },
      detection: {
        selection: { Image: ['*\\powershell.exe'] },
        condition: 'selection',
      },
      falsepositives: ['Legitimate admin scripts'],
      level: 'high',
      raw: 'title: Suspicious PowerShell Download Cradle',
    },
    sourceReportId: 'report-1',
    sourceTtp: 'ttp-1',
    attackTechniqueId: 'T1059.001',
    attackTactic: 'execution',
    confidence: 'high',
    validation: {
      valid: true,
      syntaxValid: true,
      schemaValid: true,
      errors: [],
      warnings: [],
    },
    ...overrides,
  };
}

function makeYaraRule(overrides: Partial<GeneratedRule> = {}): GeneratedRule {
  return {
    format: 'yara',
    yara: {
      name: 'Cobalt_Strike_Beacon',
      tags: ['malware', 'cobalt_strike'],
      meta: {
        description: 'Detects Cobalt Strike Beacon payload.',
        author: 'DetectForge',
        date: '2026-02-10',
        reference: 'https://example.com',
        mitre_attack: 'T1071.001',
      },
      strings: [
        {
          identifier: '$s1',
          value: '%s as %s\\%s: %d:%d',
          type: 'text',
          modifiers: ['ascii'],
        },
      ],
      condition: '$s1',
      raw: 'rule Cobalt_Strike_Beacon { ... }',
    },
    sourceReportId: 'report-1',
    sourceTtp: 'ttp-2',
    attackTechniqueId: 'T1071.001',
    attackTactic: 'command-and-control',
    confidence: 'high',
    validation: {
      valid: true,
      syntaxValid: true,
      schemaValid: true,
      errors: [],
      warnings: [],
    },
    ...overrides,
  };
}

function makeSuricataRule(
  overrides: Partial<GeneratedRule> = {},
): GeneratedRule {
  return {
    format: 'suricata',
    suricata: {
      action: 'alert',
      protocol: 'http',
      sourceIp: '$HOME_NET',
      sourcePort: 'any',
      direction: '->',
      destIp: '$EXTERNAL_NET',
      destPort: 'any',
      options: [
        { keyword: 'msg', value: 'ET MALWARE Cobalt Strike C2 Beacon' },
        { keyword: 'content', value: '/pixel.gif' },
        { keyword: 'sid', value: '9000001' },
        { keyword: 'rev', value: '1' },
      ],
      sid: 9000001,
      rev: 1,
      raw: 'alert http $HOME_NET any -> $EXTERNAL_NET any (...)',
    },
    sourceReportId: 'report-1',
    sourceTtp: 'ttp-3',
    attackTechniqueId: 'T1071.001',
    attackTactic: 'command-and-control',
    confidence: 'medium',
    validation: {
      valid: true,
      syntaxValid: true,
      schemaValid: true,
      errors: [],
      warnings: [],
    },
    ...overrides,
  };
}

function makeValidGapResponse(): GapAnalysisAIResponse {
  return {
    uncoveredTTPs: [
      {
        ttpDescription: 'Credential dumping via LSASS memory access',
        techniqueId: 'T1003.001',
        reason:
          'No Sysmon or EDR telemetry available to observe process access to lsass.exe',
        alternativeDetection:
          'Enable Sysmon Event ID 10 (ProcessAccess) targeting lsass.exe',
        requiredLogSources: ['Sysmon', 'EDR'],
      },
    ],
    evasionVectors: [
      {
        ruleAffected: 'Suspicious PowerShell Download Cradle',
        evasionTechnique:
          'Base64 encoding of Invoke-WebRequest or use of aliases like iwr',
        mitigationSuggestion:
          'Add decoded command line monitoring via PowerShell ScriptBlock logging',
      },
    ],
    logSourceGaps: [
      {
        logSource: 'Sysmon',
        requiredFor: ['T1003.001', 'T1055'],
        currentlyAvailable: false,
        recommendation:
          'Deploy Sysmon with SwiftOnSecurity configuration baseline',
      },
    ],
    overallCoverage: {
      coveredTechniqueCount: 3,
      totalTechniqueCount: 5,
      coveragePercentage: 60.0,
      strongestTactic: 'Execution',
      weakestTactic: 'Defense Evasion',
    },
    recommendations: [
      'Deploy Sysmon to enable process-level visibility',
      'Enable PowerShell ScriptBlock logging for deobfuscation',
      'Add network detection rules for encrypted C2 channels',
    ],
  };
}

// ===========================================================================
// buildGapAnalysisPrompt
// ===========================================================================

describe('buildGapAnalysisPrompt', () => {
  const rules = [makeRule()];
  const ttps = [makeTTP()];
  const mappings = [makeMapping()];

  it('returns an object with system and user string properties', () => {
    const result = buildGapAnalysisPrompt(rules, ttps, mappings);
    expect(result).toHaveProperty('system');
    expect(result).toHaveProperty('user');
    expect(typeof result.system).toBe('string');
    expect(typeof result.user).toBe('string');
  });

  it('returns non-empty system and user strings', () => {
    const result = buildGapAnalysisPrompt(rules, ttps, mappings);
    expect(result.system.length).toBeGreaterThan(0);
    expect(result.user.length).toBeGreaterThan(0);
  });

  // -----------------------------------------------------------------------
  // System prompt checks
  // -----------------------------------------------------------------------

  describe('system prompt', () => {
    it('contains detection engineering manager persona', () => {
      const { system } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(system).toContain('detection engineering manager');
    });

    it('mentions evasion vectors', () => {
      const { system } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(system).toContain('evasion');
    });

    it('mentions log source gaps', () => {
      const { system } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(system).toContain('log source');
    });

    it('mentions coverage computation', () => {
      const { system } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(system).toContain('coverage');
    });

    it('mentions LOLBins', () => {
      const { system } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(system).toContain('LOLBins');
    });

    it('mentions obfuscation', () => {
      const { system } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(system).toContain('Obfuscation');
    });

    it('instructs model to respond with JSON only', () => {
      const { system } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(system).toContain('JSON');
    });

    it('describes the output schema structure', () => {
      const { system } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(system).toContain('uncoveredTTPs');
      expect(system).toContain('evasionVectors');
      expect(system).toContain('logSourceGaps');
      expect(system).toContain('overallCoverage');
      expect(system).toContain('recommendations');
    });

    it('mentions process injection and fileless techniques', () => {
      const { system } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(system).toContain('Process injection');
      expect(system).toContain('Fileless');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt — multiple rules
  // -----------------------------------------------------------------------

  describe('user prompt with multiple rules', () => {
    it('includes rule summaries with [Sigma] format tag', () => {
      const sigmaRule = makeRule();
      const { user } = buildGapAnalysisPrompt([sigmaRule], ttps, mappings);
      expect(user).toContain('[Sigma]');
    });

    it('includes rule summaries with [YARA] format tag', () => {
      const yaraRule = makeYaraRule();
      const { user } = buildGapAnalysisPrompt([yaraRule], ttps, mappings);
      expect(user).toContain('[YARA]');
    });

    it('includes rule summaries with [Suricata] format tag', () => {
      const suricataRule = makeSuricataRule();
      const { user } = buildGapAnalysisPrompt(
        [suricataRule],
        ttps,
        mappings,
      );
      expect(user).toContain('[Suricata]');
    });

    it('includes technique IDs in rule summaries', () => {
      const { user } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(user).toContain('T1059.001');
    });

    it('shows all three format tags when given mixed rules', () => {
      const mixed = [makeRule(), makeYaraRule(), makeSuricataRule()];
      const { user } = buildGapAnalysisPrompt(mixed, ttps, mappings);
      expect(user).toContain('[Sigma]');
      expect(user).toContain('[YARA]');
      expect(user).toContain('[Suricata]');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt — individual rule formats
  // -----------------------------------------------------------------------

  describe('user prompt with Sigma rule', () => {
    it('shows title from sigma.title', () => {
      const sigmaRule = makeRule();
      const { user } = buildGapAnalysisPrompt([sigmaRule], ttps, mappings);
      expect(user).toContain('Suspicious PowerShell Download Cradle');
    });
  });

  describe('user prompt with YARA rule', () => {
    it('shows name from yara.name', () => {
      const yaraRule = makeYaraRule();
      const { user } = buildGapAnalysisPrompt([yaraRule], ttps, mappings);
      expect(user).toContain('Cobalt_Strike_Beacon');
    });
  });

  describe('user prompt with Suricata rule', () => {
    it('shows msg from options', () => {
      const suricataRule = makeSuricataRule();
      const { user } = buildGapAnalysisPrompt(
        [suricataRule],
        ttps,
        mappings,
      );
      expect(user).toContain('ET MALWARE Cobalt Strike C2 Beacon');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt — TTPs section
  // -----------------------------------------------------------------------

  describe('user prompt with TTPs', () => {
    it('includes TTP descriptions', () => {
      const ttp = makeTTP();
      const { user } = buildGapAnalysisPrompt(rules, [ttp], mappings);
      expect(user).toContain(ttp.description);
    });

    it('includes tools', () => {
      const ttp = makeTTP();
      const { user } = buildGapAnalysisPrompt(rules, [ttp], mappings);
      expect(user).toContain('PowerShell');
      expect(user).toContain('Invoke-WebRequest');
    });

    it('includes platforms', () => {
      const ttp = makeTTP();
      const { user } = buildGapAnalysisPrompt(rules, [ttp], mappings);
      expect(user).toContain('windows');
    });

    it('includes artifacts with type and description', () => {
      const ttp = makeTTP();
      const { user } = buildGapAnalysisPrompt(rules, [ttp], mappings);
      expect(user).toContain('[process]');
      expect(user).toContain('powershell.exe with encoded command line');
      expect(user).toContain('[network]');
    });

    it('includes detection opportunities', () => {
      const ttp = makeTTP();
      const { user } = buildGapAnalysisPrompt(rules, [ttp], mappings);
      expect(user).toContain(
        'Monitor for powershell.exe with download cradle arguments',
      );
    });

    it('includes confidence level', () => {
      const ttp = makeTTP({ confidence: 'medium' });
      const { user } = buildGapAnalysisPrompt(rules, [ttp], mappings);
      expect(user).toContain('medium');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt — ATT&CK mappings section
  // -----------------------------------------------------------------------

  describe('user prompt with mappings', () => {
    it('includes technique IDs', () => {
      const mapping = makeMapping();
      const { user } = buildGapAnalysisPrompt(rules, ttps, [mapping]);
      expect(user).toContain('T1059.001');
    });

    it('includes technique names', () => {
      const mapping = makeMapping();
      const { user } = buildGapAnalysisPrompt(rules, ttps, [mapping]);
      expect(user).toContain('PowerShell');
    });

    it('includes tactics', () => {
      const mapping = makeMapping();
      const { user } = buildGapAnalysisPrompt(rules, ttps, [mapping]);
      expect(user).toContain('execution');
    });

    it('includes reasoning', () => {
      const mapping = makeMapping();
      const { user } = buildGapAnalysisPrompt(rules, ttps, [mapping]);
      expect(user).toContain(
        'The threat actor uses PowerShell to execute commands.',
      );
    });

    it('includes suggested formats', () => {
      const mapping = makeMapping({
        suggestedRuleFormats: ['sigma', 'yara'],
      });
      const { user } = buildGapAnalysisPrompt(rules, ttps, [mapping]);
      expect(user).toContain('sigma');
      expect(user).toContain('yara');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt — quick stats
  // -----------------------------------------------------------------------

  describe('user prompt includes quick stats', () => {
    it('shows unique techniques count', () => {
      const { user } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(user).toContain('Unique ATT&CK techniques identified');
    });

    it('shows covered count', () => {
      const { user } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(user).toContain('Techniques with at least one rule');
    });

    it('shows formats generated', () => {
      const { user } = buildGapAnalysisPrompt(rules, ttps, mappings);
      expect(user).toContain('Rule formats generated');
    });

    it('reflects accurate unique technique count from mappings', () => {
      const m1 = makeMapping({ techniqueId: 'T1059.001' });
      const m2 = makeMapping({ techniqueId: 'T1071.001' });
      const { user } = buildGapAnalysisPrompt(rules, ttps, [m1, m2]);
      // 2 unique techniques
      expect(user).toContain('Unique ATT&CK techniques identified: 2');
    });

    it('reflects accurate covered count from rules', () => {
      const r1 = makeRule({ attackTechniqueId: 'T1059.001' });
      const r2 = makeYaraRule({ attackTechniqueId: 'T1071.001' });
      const { user } = buildGapAnalysisPrompt([r1, r2], ttps, mappings);
      expect(user).toContain('Techniques with at least one rule: 2');
    });

    it('shows multiple formats when mixed', () => {
      const mixed = [makeRule(), makeYaraRule(), makeSuricataRule()];
      const { user } = buildGapAnalysisPrompt(mixed, ttps, mappings);
      expect(user).toContain('sigma');
      expect(user).toContain('yara');
      expect(user).toContain('suricata');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt — empty input edge cases
  // -----------------------------------------------------------------------

  describe('user prompt with empty inputs', () => {
    it('shows "_No rules were generated._" when rules are empty', () => {
      const { user } = buildGapAnalysisPrompt([], ttps, mappings);
      expect(user).toContain('_No rules were generated._');
    });

    it('shows "_No TTPs were extracted._" when TTPs are empty', () => {
      const { user } = buildGapAnalysisPrompt(rules, [], mappings);
      expect(user).toContain('_No TTPs were extracted._');
    });

    it('shows "_No ATT&CK mappings were produced._" when mappings are empty', () => {
      const { user } = buildGapAnalysisPrompt(rules, ttps, []);
      expect(user).toContain('_No ATT&CK mappings were produced._');
    });

    it('handles all empty inputs gracefully', () => {
      const { user } = buildGapAnalysisPrompt([], [], []);
      expect(user).toContain('_No rules were generated._');
      expect(user).toContain('_No TTPs were extracted._');
      expect(user).toContain('_No ATT&CK mappings were produced._');
    });

    it('shows "none" for formats when rules are empty', () => {
      const { user } = buildGapAnalysisPrompt([], ttps, mappings);
      expect(user).toContain('Rule formats generated: none');
    });
  });
});

// ===========================================================================
// parseGapAnalysisAIResponse
// ===========================================================================

describe('parseGapAnalysisAIResponse', () => {
  // -----------------------------------------------------------------------
  // Valid responses
  // -----------------------------------------------------------------------

  describe('valid responses', () => {
    it('parses a valid JSON response', () => {
      const response = makeValidGapResponse();
      const raw = JSON.stringify(response);
      const result = parseGapAnalysisAIResponse(raw);
      expect(result.uncoveredTTPs).toHaveLength(1);
      expect(result.evasionVectors).toHaveLength(1);
      expect(result.logSourceGaps).toHaveLength(1);
      expect(result.overallCoverage.coveredTechniqueCount).toBe(3);
      expect(result.recommendations).toHaveLength(3);
    });

    it('parses markdown-wrapped JSON response', () => {
      const response = makeValidGapResponse();
      const raw = '```json\n' + JSON.stringify(response, null, 2) + '\n```';
      const result = parseGapAnalysisAIResponse(raw);
      expect(result.overallCoverage.coveragePercentage).toBe(60.0);
      expect(result.overallCoverage.strongestTactic).toBe('Execution');
    });

    it('parses JSON with surrounding text', () => {
      const response = makeValidGapResponse();
      const raw =
        'Here is the gap analysis:\n\n' +
        JSON.stringify(response) +
        '\n\nLet me know if you need more detail.';
      const result = parseGapAnalysisAIResponse(raw);
      expect(result.uncoveredTTPs[0].ttpDescription).toBe(
        'Credential dumping via LSASS memory access',
      );
    });

    it('accepts empty arrays for uncoveredTTPs', () => {
      const response = {
        ...makeValidGapResponse(),
        uncoveredTTPs: [],
      };
      const raw = JSON.stringify(response);
      const result = parseGapAnalysisAIResponse(raw);
      expect(result.uncoveredTTPs).toEqual([]);
    });

    it('accepts empty arrays for evasionVectors', () => {
      const response = {
        ...makeValidGapResponse(),
        evasionVectors: [],
      };
      const raw = JSON.stringify(response);
      const result = parseGapAnalysisAIResponse(raw);
      expect(result.evasionVectors).toEqual([]);
    });

    it('accepts empty arrays for logSourceGaps', () => {
      const response = {
        ...makeValidGapResponse(),
        logSourceGaps: [],
      };
      const raw = JSON.stringify(response);
      const result = parseGapAnalysisAIResponse(raw);
      expect(result.logSourceGaps).toEqual([]);
    });

    it('accepts optional techniqueId on uncoveredTTP', () => {
      const response = makeValidGapResponse();
      response.uncoveredTTPs = [
        {
          ttpDescription: 'Credential access via keylogging',
          reason: 'No kernel-level hook visibility',
          alternativeDetection: 'Use EDR behavioral analytics',
          requiredLogSources: ['EDR'],
          // techniqueId intentionally omitted
        },
      ];
      const raw = JSON.stringify(response);
      const result = parseGapAnalysisAIResponse(raw);
      expect(result.uncoveredTTPs[0].techniqueId).toBeUndefined();
    });

    it('preserves all fields when all data is present', () => {
      const response = makeValidGapResponse();
      const raw = JSON.stringify(response);
      const result = parseGapAnalysisAIResponse(raw);
      expect(result.uncoveredTTPs[0].techniqueId).toBe('T1003.001');
      expect(result.uncoveredTTPs[0].requiredLogSources).toEqual([
        'Sysmon',
        'EDR',
      ]);
      expect(result.evasionVectors[0].ruleAffected).toBe(
        'Suspicious PowerShell Download Cradle',
      );
      expect(result.logSourceGaps[0].currentlyAvailable).toBe(false);
      expect(result.overallCoverage.weakestTactic).toBe('Defense Evasion');
    });
  });

  // -----------------------------------------------------------------------
  // Invalid responses
  // -----------------------------------------------------------------------

  describe('invalid responses', () => {
    it('rejects missing overallCoverage', () => {
      const response = makeValidGapResponse();
      delete (response as any).overallCoverage;
      const raw = JSON.stringify(response);
      expect(() => parseGapAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects missing coveredTechniqueCount (not a number)', () => {
      const response = makeValidGapResponse();
      (response as any).overallCoverage.coveredTechniqueCount = 'three';
      const raw = JSON.stringify(response);
      expect(() => parseGapAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects missing strongestTactic', () => {
      const response = makeValidGapResponse();
      delete (response as any).overallCoverage.strongestTactic;
      const raw = JSON.stringify(response);
      expect(() => parseGapAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects coveragePercentage that is not a number', () => {
      const response = makeValidGapResponse();
      (response as any).overallCoverage.coveragePercentage = 'sixty';
      const raw = JSON.stringify(response);
      expect(() => parseGapAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects logSourceGap missing currentlyAvailable boolean', () => {
      const response = makeValidGapResponse();
      (response as any).logSourceGaps[0].currentlyAvailable = 'yes';
      const raw = JSON.stringify(response);
      expect(() => parseGapAnalysisAIResponse(raw)).toThrow();
    });

    it('throws on completely invalid JSON', () => {
      expect(() =>
        parseGapAnalysisAIResponse('This is not JSON at all.'),
      ).toThrow();
    });

    it('error message contains "validation failed" for schema errors', () => {
      const response = makeValidGapResponse();
      delete (response as any).overallCoverage.strongestTactic;
      const raw = JSON.stringify(response);
      try {
        parseGapAnalysisAIResponse(raw);
        expect.unreachable('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('validation failed');
      }
    });

    it('rejects missing recommendations field', () => {
      const response = makeValidGapResponse();
      delete (response as any).recommendations;
      const raw = JSON.stringify(response);
      expect(() => parseGapAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects evasionVector missing mitigationSuggestion', () => {
      const response = makeValidGapResponse();
      delete (response as any).evasionVectors[0].mitigationSuggestion;
      const raw = JSON.stringify(response);
      expect(() => parseGapAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects uncoveredTTP missing reason', () => {
      const response = makeValidGapResponse();
      delete (response as any).uncoveredTTPs[0].reason;
      const raw = JSON.stringify(response);
      expect(() => parseGapAnalysisAIResponse(raw)).toThrow();
    });
  });
});

// ===========================================================================
// GapAnalysisAIResponseSchema (direct Zod validation)
// ===========================================================================

describe('GapAnalysisAIResponseSchema', () => {
  it('parses a fully valid object', () => {
    const valid = makeValidGapResponse();
    const result = GapAnalysisAIResponseSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('fails when overallCoverage is missing', () => {
    const obj = { ...makeValidGapResponse() };
    delete (obj as any).overallCoverage;
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('fails when coveredTechniqueCount is a string', () => {
    const obj = makeValidGapResponse();
    (obj as any).overallCoverage.coveredTechniqueCount = 'abc';
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('fails when totalTechniqueCount is missing', () => {
    const obj = makeValidGapResponse();
    delete (obj as any).overallCoverage.totalTechniqueCount;
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('fails when coveragePercentage is a string', () => {
    const obj = makeValidGapResponse();
    (obj as any).overallCoverage.coveragePercentage = 'sixty';
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('fails when strongestTactic is missing', () => {
    const obj = makeValidGapResponse();
    delete (obj as any).overallCoverage.strongestTactic;
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('fails when weakestTactic is missing', () => {
    const obj = makeValidGapResponse();
    delete (obj as any).overallCoverage.weakestTactic;
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('allows empty uncoveredTTPs array', () => {
    const obj = { ...makeValidGapResponse(), uncoveredTTPs: [] };
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(true);
  });

  it('allows empty evasionVectors array', () => {
    const obj = { ...makeValidGapResponse(), evasionVectors: [] };
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(true);
  });

  it('allows empty logSourceGaps array', () => {
    const obj = { ...makeValidGapResponse(), logSourceGaps: [] };
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(true);
  });

  it('allows empty recommendations array', () => {
    const obj = { ...makeValidGapResponse(), recommendations: [] };
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(true);
  });

  it('fails when logSourceGap.currentlyAvailable is not a boolean', () => {
    const obj = makeValidGapResponse();
    (obj as any).logSourceGaps[0].currentlyAvailable = 'yes';
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('fails when evasionVector is missing evasionTechnique', () => {
    const obj = makeValidGapResponse();
    delete (obj as any).evasionVectors[0].evasionTechnique;
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('allows techniqueId to be omitted from uncoveredTTP', () => {
    const obj = makeValidGapResponse();
    delete (obj as any).uncoveredTTPs[0].techniqueId;
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(true);
  });

  it('fails when logSourceGap.requiredFor is not an array', () => {
    const obj = makeValidGapResponse();
    (obj as any).logSourceGaps[0].requiredFor = 'T1003.001';
    const result = GapAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });
});
