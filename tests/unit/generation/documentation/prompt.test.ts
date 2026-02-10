/**
 * Unit tests for the Documentation AI prompt builder and response parser.
 *
 * Covers: buildDocumentationPrompt, parseDocumentationAIResponse,
 *         DocumentationAIResponseSchema
 */

import { describe, it, expect, vi } from 'vitest';
import {
  buildDocumentationPrompt,
  parseDocumentationAIResponse,
  DocumentationAIResponseSchema,
} from '@/ai/prompts/documentation.js';
import type { DocumentationAIResponse } from '@/ai/prompts/documentation.js';
import type {
  GeneratedRule,
  SigmaRule,
  YaraRule,
  SuricataRule,
  ValidationResult,
} from '@/types/detection-rule.js';

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

function makeValidation(overrides?: Partial<ValidationResult>): ValidationResult {
  return {
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
    ...overrides,
  };
}

function makeSigmaData(overrides?: Partial<SigmaRule>): SigmaRule {
  return {
    id: 'abc123-def456',
    title: 'Suspicious PowerShell Download Cradle',
    status: 'experimental',
    description:
      'Detects PowerShell execution with download cradle patterns commonly used by threat actors to fetch remote payloads.',
    references: ['https://attack.mitre.org/techniques/T1059/001/'],
    author: 'DetectForge',
    date: '2025-01-15',
    modified: '2025-01-15',
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
    raw: 'title: Suspicious PowerShell Download Cradle\nstatus: experimental\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image:\n      - "*\\\\powershell.exe"\n    CommandLine:\n      - "*Invoke-WebRequest*"\n  condition: selection\nlevel: high',
    ...overrides,
  };
}

function makeYaraData(overrides?: Partial<YaraRule>): YaraRule {
  return {
    name: 'APT_Backdoor_CobaltStrike_Beacon',
    tags: ['apt', 'backdoor', 'cobaltstrike'],
    meta: {
      description:
        'Detects CobaltStrike Beacon payloads based on characteristic strings and byte patterns.',
      author: 'DetectForge',
      date: '2025-01-15',
      reference: 'https://attack.mitre.org/software/S0154/',
      mitre_attack: 'T1071.001',
    },
    strings: [
      {
        identifier: '$s1',
        value: '%c%c%c%c%c%c%c%c%cMSSE-%d-server',
        type: 'text',
        modifiers: ['ascii'],
      },
    ],
    condition: 'uint16(0) == 0x5A4D and any of ($s*)',
    raw: 'rule APT_Backdoor_CobaltStrike_Beacon { strings: $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" condition: uint16(0) == 0x5A4D and any of ($s*) }',
    ...overrides,
  };
}

function makeSuricataData(overrides?: Partial<SuricataRule>): SuricataRule {
  return {
    action: 'alert',
    protocol: 'http',
    sourceIp: '$HOME_NET',
    sourcePort: 'any',
    direction: '->',
    destIp: '$EXTERNAL_NET',
    destPort: 'any',
    options: [
      { keyword: 'msg', value: 'ET MALWARE CobaltStrike Beacon C2 Activity' },
      { keyword: 'content', value: '/submit.php?id=' },
      { keyword: 'http_uri' },
      { keyword: 'sid', value: '2025001' },
      { keyword: 'rev', value: '1' },
    ],
    sid: 2025001,
    rev: 1,
    raw: 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE CobaltStrike Beacon C2 Activity"; content:"/submit.php?id="; http_uri; sid:2025001; rev:1;)',
    ...overrides,
  };
}

function makeRule(overrides?: Partial<GeneratedRule>): GeneratedRule {
  return {
    format: 'sigma',
    sigma: makeSigmaData(),
    sourceReportId: 'report-001',
    sourceTtp: 'PowerShell download cradle execution',
    attackTechniqueId: 'T1059.001',
    attackTactic: 'execution',
    confidence: 'high',
    validation: makeValidation(),
    ...overrides,
  };
}

function makeSigmaRule(overrides?: Partial<GeneratedRule>): GeneratedRule {
  return makeRule(overrides);
}

function makeYaraRule(overrides?: Partial<GeneratedRule>): GeneratedRule {
  return makeRule({
    format: 'yara',
    sigma: undefined,
    yara: makeYaraData(),
    attackTechniqueId: 'T1071.001',
    attackTactic: 'command-and-control',
    ...overrides,
  });
}

function makeSuricataRule(overrides?: Partial<GeneratedRule>): GeneratedRule {
  return makeRule({
    format: 'suricata',
    sigma: undefined,
    suricata: makeSuricataData(),
    attackTechniqueId: 'T1071.001',
    attackTactic: 'command-and-control',
    ...overrides,
  });
}

function makeValidAIResponse(): Record<string, unknown> {
  return {
    whatItDetects:
      'This rule detects PowerShell processes that use download cradle techniques to fetch and execute remote payloads from command-and-control servers.',
    howItWorks:
      'The rule monitors process creation events for powershell.exe or pwsh.exe with command-line arguments containing Invoke-WebRequest or DownloadString patterns, which are commonly used download cradle techniques.',
    attackMapping: {
      techniqueId: 'T1059.001',
      techniqueName: 'PowerShell',
      tactic: 'Execution',
      platform: 'Windows',
    },
    falsePositives: [
      {
        scenario:
          'System administrators running legitimate PowerShell download scripts for software deployment.',
        likelihood: 'medium',
        tuningAdvice:
          'Add allowlist entries for known admin user accounts and approved download URLs.',
      },
    ],
    coverageGaps: [
      'Does not detect PowerShell download cradles that use encoded commands or obfuscated cmdlet names.',
    ],
    recommendedLogSources: [
      'Windows Security Event Log (Event ID 4688) with command-line auditing enabled.',
    ],
    tuningRecommendations: [
      'Add exclusions for known IT automation service accounts that regularly use Invoke-WebRequest.',
    ],
  };
}

// ===========================================================================
// buildDocumentationPrompt
// ===========================================================================

describe('buildDocumentationPrompt', () => {
  it('returns an object with system and user string properties', () => {
    const rule = makeSigmaRule();
    const result = buildDocumentationPrompt(rule);
    expect(result).toHaveProperty('system');
    expect(result).toHaveProperty('user');
    expect(typeof result.system).toBe('string');
    expect(typeof result.user).toBe('string');
  });

  it('returns non-empty system and user strings', () => {
    const rule = makeSigmaRule();
    const { system, user } = buildDocumentationPrompt(rule);
    expect(system.length).toBeGreaterThan(0);
    expect(user.length).toBeGreaterThan(0);
  });

  // -----------------------------------------------------------------------
  // System prompt checks
  // -----------------------------------------------------------------------

  describe('system prompt', () => {
    it('contains documentation quality principles', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('Documentation Quality Principles');
    });

    it('contains output format instructions with JSON schema example', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('Output Format');
      expect(system).toContain('JSON');
      expect(system).toContain('whatItDetects');
      expect(system).toContain('howItWorks');
      expect(system).toContain('attackMapping');
      expect(system).toContain('falsePositives');
      expect(system).toContain('coverageGaps');
      expect(system).toContain('recommendedLogSources');
      expect(system).toContain('tuningRecommendations');
    });

    it('mentions Sigma format', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('Sigma');
    });

    it('mentions YARA format', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('YARA');
    });

    it('mentions Suricata format', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('Suricata');
    });

    it('instructs model to respond with valid JSON only', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('ONLY valid JSON');
    });

    it('contains ATT&CK technique ID format requirement', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('TNNNN');
    });

    it('contains the expert persona description', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('expert detection engineering documentation specialist');
    });

    it('describes false positive guidance', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('false positive');
    });

    it('describes coverage gap guidance', () => {
      const { system } = buildDocumentationPrompt(makeSigmaRule());
      expect(system).toContain('coverage gap');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt with Sigma rule
  // -----------------------------------------------------------------------

  describe('user prompt with Sigma rule', () => {
    const rule = makeSigmaRule();

    it('includes SIGMA format label', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('SIGMA');
    });

    it('includes rule title from sigma.title', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('Suspicious PowerShell Download Cradle');
    });

    it('includes rule description from sigma.description', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain(
        'Detects PowerShell execution with download cradle patterns',
      );
    });

    it('includes ATT&CK technique ID', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('T1059.001');
    });

    it('includes ATT&CK tactic', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('execution');
    });

    it('includes confidence level', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('high');
    });

    it('includes raw rule text', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('process_creation');
      expect(user).toContain('powershell.exe');
      expect(user).toContain('Invoke-WebRequest');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt with YARA rule
  // -----------------------------------------------------------------------

  describe('user prompt with YARA rule', () => {
    const rule = makeYaraRule();

    it('includes YARA format label', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('YARA');
    });

    it('includes rule name from yara.name', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('APT_Backdoor_CobaltStrike_Beacon');
    });

    it('includes description from yara.meta.description', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('Detects CobaltStrike Beacon payloads');
    });

    it('includes raw YARA rule text', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('uint16(0)');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt with Suricata rule
  // -----------------------------------------------------------------------

  describe('user prompt with Suricata rule', () => {
    const rule = makeSuricataRule();

    it('includes SURICATA format label', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('SURICATA');
    });

    it('includes msg from options as title', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('ET MALWARE CobaltStrike Beacon C2 Activity');
    });

    it('includes SID in title or rule text', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('2025001');
    });

    it('includes raw Suricata rule text', () => {
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('/submit.php?id=');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt without ATT&CK info
  // -----------------------------------------------------------------------

  describe('user prompt without ATT&CK info', () => {
    it('handles missing attackTechniqueId gracefully', () => {
      const rule = makeSigmaRule({ attackTechniqueId: undefined });
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('Not specified');
      expect(typeof user).toBe('string');
    });

    it('handles missing attackTactic gracefully', () => {
      const rule = makeSigmaRule({ attackTactic: undefined });
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('Not specified');
      expect(typeof user).toBe('string');
    });

    it('handles both ATT&CK fields missing without throwing', () => {
      const rule = makeSigmaRule({
        attackTechniqueId: undefined,
        attackTactic: undefined,
      });
      expect(() => buildDocumentationPrompt(rule)).not.toThrow();
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toBeDefined();
    });
  });

  // -----------------------------------------------------------------------
  // User prompt without raw text
  // -----------------------------------------------------------------------

  describe('user prompt without raw text', () => {
    it('falls back to Sigma summary when raw is empty', () => {
      const rule = makeSigmaRule({
        sigma: makeSigmaData({ raw: '' }),
      });
      const { user } = buildDocumentationPrompt(rule);
      // Should contain the title from the summary fallback
      expect(user).toContain('Suspicious PowerShell Download Cradle');
      // Should contain logsource info from the summary
      expect(user).toContain('process_creation');
    });

    it('falls back for YARA rule when raw is empty', () => {
      const rule = makeYaraRule({
        yara: makeYaraData({ raw: '' }),
      });
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('APT_Backdoor_CobaltStrike_Beacon');
    });

    it('falls back for Suricata rule when raw is empty', () => {
      const rule = makeSuricataRule({
        suricata: makeSuricataData({ raw: '' }),
      });
      const { user } = buildDocumentationPrompt(rule);
      expect(user).toContain('2025001');
    });

    it('handles rule with no format-specific data', () => {
      const rule = makeRule({
        format: 'sigma',
        sigma: undefined,
      });
      const { user } = buildDocumentationPrompt(rule);
      // Should produce fallback text without crashing
      expect(user).toContain('sigma');
    });
  });
});

// ===========================================================================
// parseDocumentationAIResponse
// ===========================================================================

describe('parseDocumentationAIResponse', () => {
  // -----------------------------------------------------------------------
  // Valid responses
  // -----------------------------------------------------------------------

  describe('valid responses', () => {
    it('parses a valid JSON response correctly', () => {
      const response = makeValidAIResponse();
      const raw = JSON.stringify(response);
      const result = parseDocumentationAIResponse(raw);
      expect(result.whatItDetects).toBe(response.whatItDetects);
      expect(result.howItWorks).toBe(response.howItWorks);
      expect(result.attackMapping).toEqual(response.attackMapping);
      expect(result.falsePositives).toHaveLength(1);
      expect(result.coverageGaps).toHaveLength(1);
      expect(result.recommendedLogSources).toHaveLength(1);
      expect(result.tuningRecommendations).toHaveLength(1);
    });

    it('parses markdown-wrapped JSON response', () => {
      const response = makeValidAIResponse();
      const raw = '```json\n' + JSON.stringify(response, null, 2) + '\n```';
      const result = parseDocumentationAIResponse(raw);
      expect(result.whatItDetects).toBe(response.whatItDetects);
      expect(result.attackMapping).toEqual(response.attackMapping);
    });

    it('parses JSON with surrounding text', () => {
      const response = makeValidAIResponse();
      const raw =
        'Here is the documentation for the rule:\n\n' +
        JSON.stringify(response) +
        '\n\nLet me know if you need changes.';
      const result = parseDocumentationAIResponse(raw);
      expect(result.whatItDetects).toBe(response.whatItDetects);
    });

    it('preserves all false positive fields', () => {
      const response = makeValidAIResponse();
      const raw = JSON.stringify(response);
      const result = parseDocumentationAIResponse(raw);
      const fp = result.falsePositives[0];
      expect(fp.scenario).toContain('System administrators');
      expect(fp.likelihood).toBe('medium');
      expect(fp.tuningAdvice).toContain('allowlist');
    });

    it('accepts multiple false-positive entries', () => {
      const response = {
        ...makeValidAIResponse(),
        falsePositives: [
          {
            scenario: 'Admin scripts running downloads during patching cycles.',
            likelihood: 'high',
            tuningAdvice: 'Exclude the patch management service account from this rule.',
          },
          {
            scenario: 'CI/CD pipeline downloading build dependencies via PowerShell.',
            likelihood: 'medium',
            tuningAdvice: 'Allowlist known CI runner hostnames or IP addresses.',
          },
        ],
      };
      const raw = JSON.stringify(response);
      const result = parseDocumentationAIResponse(raw);
      expect(result.falsePositives).toHaveLength(2);
    });

    it('accepts sub-technique IDs like T1059.001', () => {
      const response = makeValidAIResponse();
      const raw = JSON.stringify(response);
      const result = parseDocumentationAIResponse(raw);
      expect(result.attackMapping.techniqueId).toBe('T1059.001');
    });

    it('accepts base technique IDs like T1059', () => {
      const response = {
        ...makeValidAIResponse(),
        attackMapping: {
          techniqueId: 'T1059',
          techniqueName: 'Command and Scripting Interpreter',
          tactic: 'Execution',
          platform: 'Windows',
        },
      };
      const raw = JSON.stringify(response);
      const result = parseDocumentationAIResponse(raw);
      expect(result.attackMapping.techniqueId).toBe('T1059');
    });

    it('accepts all valid likelihood enum values', () => {
      const likelihoods = ['high', 'medium', 'low'] as const;
      for (const likelihood of likelihoods) {
        const response = {
          ...makeValidAIResponse(),
          falsePositives: [
            {
              scenario: 'Some realistic false positive scenario.',
              likelihood,
              tuningAdvice: 'Some concrete tuning advice for this scenario.',
            },
          ],
        };
        const raw = JSON.stringify(response);
        const result = parseDocumentationAIResponse(raw);
        expect(result.falsePositives[0].likelihood).toBe(likelihood);
      }
    });
  });

  // -----------------------------------------------------------------------
  // Invalid responses
  // -----------------------------------------------------------------------

  describe('invalid responses', () => {
    it('rejects whatItDetects too short (< 20 chars)', () => {
      const response = { ...makeValidAIResponse(), whatItDetects: 'Too short.' };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects howItWorks too short (< 20 chars)', () => {
      const response = { ...makeValidAIResponse(), howItWorks: 'Too short.' };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects invalid technique ID (not TNNNN format)', () => {
      const response = {
        ...makeValidAIResponse(),
        attackMapping: {
          ...makeValidAIResponse().attackMapping as Record<string, unknown>,
          techniqueId: 'INVALID',
        },
      };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects technique ID missing T prefix', () => {
      const response = {
        ...makeValidAIResponse(),
        attackMapping: {
          ...makeValidAIResponse().attackMapping as Record<string, unknown>,
          techniqueId: '1059.001',
        },
      };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects empty techniqueName', () => {
      const response = {
        ...makeValidAIResponse(),
        attackMapping: {
          ...makeValidAIResponse().attackMapping as Record<string, unknown>,
          techniqueName: '',
        },
      };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects empty falsePositives array', () => {
      const response = { ...makeValidAIResponse(), falsePositives: [] };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects falsePositive scenario too short (< 5 chars)', () => {
      const response = {
        ...makeValidAIResponse(),
        falsePositives: [
          {
            scenario: 'Hi',
            likelihood: 'low',
            tuningAdvice: 'Some reasonable tuning advice for the team.',
          },
        ],
      };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects falsePositive tuningAdvice too short (< 5 chars)', () => {
      const response = {
        ...makeValidAIResponse(),
        falsePositives: [
          {
            scenario: 'A reasonable false positive scenario for testing.',
            likelihood: 'low',
            tuningAdvice: 'Fix',
          },
        ],
      };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects invalid likelihood enum value', () => {
      const response = {
        ...makeValidAIResponse(),
        falsePositives: [
          {
            scenario: 'Some reasonable false positive scenario for testing.',
            likelihood: 'critical',
            tuningAdvice: 'Some reasonable tuning advice for the team.',
          },
        ],
      };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects empty coverageGaps array', () => {
      const response = { ...makeValidAIResponse(), coverageGaps: [] };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects coverageGaps with empty strings', () => {
      const response = { ...makeValidAIResponse(), coverageGaps: [''] };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects empty recommendedLogSources array', () => {
      const response = { ...makeValidAIResponse(), recommendedLogSources: [] };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects recommendedLogSources with empty strings', () => {
      const response = { ...makeValidAIResponse(), recommendedLogSources: [''] };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects empty tuningRecommendations array', () => {
      const response = { ...makeValidAIResponse(), tuningRecommendations: [] };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects tuningRecommendations with empty strings', () => {
      const response = { ...makeValidAIResponse(), tuningRecommendations: [''] };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('throws on completely unparseable string', () => {
      expect(() =>
        parseDocumentationAIResponse('This is not JSON at all.'),
      ).toThrow();
    });

    it('error message contains "validation failed" for schema errors', () => {
      const response = {
        ...makeValidAIResponse(),
        whatItDetects: 'Short',
        coverageGaps: [],
      };
      const raw = JSON.stringify(response);
      try {
        parseDocumentationAIResponse(raw);
        expect.unreachable('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('validation failed');
      }
    });

    it('rejects missing attackMapping entirely', () => {
      const response = makeValidAIResponse();
      delete (response as any).attackMapping;
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects empty tactic string', () => {
      const response = {
        ...makeValidAIResponse(),
        attackMapping: {
          ...makeValidAIResponse().attackMapping as Record<string, unknown>,
          tactic: '',
        },
      };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });

    it('rejects empty platform string', () => {
      const response = {
        ...makeValidAIResponse(),
        attackMapping: {
          ...makeValidAIResponse().attackMapping as Record<string, unknown>,
          platform: '',
        },
      };
      const raw = JSON.stringify(response);
      expect(() => parseDocumentationAIResponse(raw)).toThrow();
    });
  });
});

// ===========================================================================
// DocumentationAIResponseSchema (direct Zod validation)
// ===========================================================================

describe('DocumentationAIResponseSchema', () => {
  it('parses a fully valid object', () => {
    const valid = makeValidAIResponse();
    const result = DocumentationAIResponseSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('whatItDetects minimum length is 20', () => {
    const obj = { ...makeValidAIResponse(), whatItDetects: 'Only 19 chars here.' }; // 19 chars
    const result = DocumentationAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('howItWorks minimum length is 20', () => {
    const obj = { ...makeValidAIResponse(), howItWorks: 'Only 19 chars here.' }; // 19 chars
    const result = DocumentationAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('technique ID must match T followed by 4 digits', () => {
    const obj = {
      ...makeValidAIResponse(),
      attackMapping: {
        ...makeValidAIResponse().attackMapping as Record<string, unknown>,
        techniqueId: 'TA0001',
      },
    };
    const result = DocumentationAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('technique ID accepts sub-technique format TNNNN.NNN', () => {
    const obj = {
      ...makeValidAIResponse(),
      attackMapping: {
        ...makeValidAIResponse().attackMapping as Record<string, unknown>,
        techniqueId: 'T1059.001',
      },
    };
    const result = DocumentationAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(true);
  });

  it('technique ID accepts base technique format TNNNN', () => {
    const obj = {
      ...makeValidAIResponse(),
      attackMapping: {
        ...makeValidAIResponse().attackMapping as Record<string, unknown>,
        techniqueId: 'T1059',
      },
    };
    const result = DocumentationAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(true);
  });

  it('falsePositives must have at least one entry', () => {
    const obj = { ...makeValidAIResponse(), falsePositives: [] };
    const result = DocumentationAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('coverageGaps must have at least one entry', () => {
    const obj = { ...makeValidAIResponse(), coverageGaps: [] };
    const result = DocumentationAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('recommendedLogSources must have at least one entry', () => {
    const obj = { ...makeValidAIResponse(), recommendedLogSources: [] };
    const result = DocumentationAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('tuningRecommendations must have at least one entry', () => {
    const obj = { ...makeValidAIResponse(), tuningRecommendations: [] };
    const result = DocumentationAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('rejects missing required fields', () => {
    const fieldsToTest = [
      'whatItDetects',
      'howItWorks',
      'attackMapping',
      'falsePositives',
      'coverageGaps',
      'recommendedLogSources',
      'tuningRecommendations',
    ];
    for (const field of fieldsToTest) {
      const obj = { ...makeValidAIResponse() };
      delete (obj as any)[field];
      const result = DocumentationAIResponseSchema.safeParse(obj);
      expect(result.success).toBe(false);
    }
  });

  it('likelihood enum only accepts high, medium, low', () => {
    const invalidLikelihoods = ['critical', 'info', 'none', 'unknown'];
    for (const likelihood of invalidLikelihoods) {
      const obj = {
        ...makeValidAIResponse(),
        falsePositives: [
          {
            scenario: 'Some false positive scenario for validation testing.',
            likelihood,
            tuningAdvice: 'Some tuning advice for validation testing.',
          },
        ],
      };
      const result = DocumentationAIResponseSchema.safeParse(obj);
      expect(result.success).toBe(false);
    }
  });
});
