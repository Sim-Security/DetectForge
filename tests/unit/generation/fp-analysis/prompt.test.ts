/**
 * Unit tests for the FP analysis AI prompt builder and response parser.
 *
 * Covers: buildFPAnalysisPrompt, parseFPAnalysisAIResponse, FPAnalysisAIResponseSchema
 */

import { describe, it, expect, vi } from 'vitest';
import {
  buildFPAnalysisPrompt,
  parseFPAnalysisAIResponse,
  FPAnalysisAIResponseSchema,
} from '@/ai/prompts/fp-analysis.js';
import type { FPAnalysisAIResponse } from '@/ai/prompts/fp-analysis.js';
import type {
  GeneratedRule,
  RuleFormat,
  SigmaRule,
  YaraRule,
  SuricataRule,
  RuleDocumentation,
  FalsePositiveScenario,
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

function makeValidation(
  overrides?: Partial<ValidationResult>,
): ValidationResult {
  return {
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
    ...overrides,
  };
}

function makeSigmaRule(overrides?: Partial<SigmaRule>): SigmaRule {
  return {
    id: '12345678-abcd-1234-abcd-123456789abc',
    title: 'Suspicious PowerShell Download Cradle',
    status: 'experimental',
    description:
      'Detects PowerShell execution with download cradle patterns commonly used to fetch remote payloads.',
    references: ['https://attack.mitre.org/techniques/T1059/001/'],
    author: 'DetectForge',
    date: '2026-02-10',
    modified: '2026-02-10',
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
    raw: `title: Suspicious PowerShell Download Cradle
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'DownloadString'
    condition: selection
level: high`,
    ...overrides,
  };
}

function makeYaraRule(overrides?: Partial<YaraRule>): YaraRule {
  return {
    name: 'APT_Backdoor_Win_Cobalt',
    tags: ['apt', 'backdoor', 'cobaltstrike'],
    meta: {
      description: 'Detects Cobalt Strike beacon in memory',
      author: 'DetectForge',
      date: '2026-02-10',
      reference: 'https://attack.mitre.org/software/S0154/',
      mitre_attack: 'T1071.001',
    },
    strings: [
      {
        identifier: '$beacon_config',
        value: '{ 00 01 00 01 00 02 ?? ?? 00 02 }',
        type: 'hex',
        modifiers: [],
      },
    ],
    condition: '$beacon_config and filesize < 1MB',
    raw: `rule APT_Backdoor_Win_Cobalt {
    meta:
        description = "Detects Cobalt Strike beacon in memory"
        author = "DetectForge"
    strings:
        $beacon_config = { 00 01 00 01 00 02 ?? ?? 00 02 }
    condition:
        $beacon_config and filesize < 1MB
}`,
    ...overrides,
  };
}

function makeSuricataRule(overrides?: Partial<SuricataRule>): SuricataRule {
  return {
    action: 'alert',
    protocol: 'http',
    sourceIp: '$HOME_NET',
    sourcePort: 'any',
    direction: '->',
    destIp: '$EXTERNAL_NET',
    destPort: 'any',
    options: [
      { keyword: 'msg', value: '"ET MALWARE CobaltStrike Beacon C2 Activity"' },
      { keyword: 'content', value: '"/submit.php?id="' },
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
  const sigma = makeSigmaRule();
  return {
    format: 'sigma',
    sigma,
    sourceReportId: 'report-001',
    sourceTtp: 'Threat actor uses PowerShell to download and execute payloads',
    attackTechniqueId: 'T1059.001',
    attackTactic: 'execution',
    confidence: 'high',
    validation: makeValidation(),
    ...overrides,
  };
}

function makeYaraGeneratedRule(
  overrides?: Partial<GeneratedRule>,
): GeneratedRule {
  const yara = makeYaraRule();
  return {
    format: 'yara',
    yara,
    sourceReportId: 'report-002',
    sourceTtp: 'Cobalt Strike beacon deployed via phishing attachment',
    attackTechniqueId: 'T1071.001',
    attackTactic: 'command-and-control',
    confidence: 'high',
    validation: makeValidation(),
    ...overrides,
  };
}

function makeSuricataGeneratedRule(
  overrides?: Partial<GeneratedRule>,
): GeneratedRule {
  const suricata = makeSuricataRule();
  return {
    format: 'suricata',
    suricata,
    sourceReportId: 'report-003',
    sourceTtp: 'C2 beacon callback over HTTP to staging server',
    attackTechniqueId: 'T1071.001',
    attackTactic: 'command-and-control',
    confidence: 'medium',
    validation: makeValidation(),
    ...overrides,
  };
}

function makeDocumentation(
  overrides?: Partial<RuleDocumentation>,
): RuleDocumentation {
  return {
    whatItDetects:
      'PowerShell download cradle execution patterns used for initial payload delivery.',
    howItWorks:
      'Monitors process creation events for PowerShell with command-line arguments containing download functions.',
    attackMapping: {
      techniqueId: 'T1059.001',
      techniqueName: 'PowerShell',
      tactic: 'execution',
      platform: 'windows',
    },
    falsePositives: [
      {
        scenario:
          'System administrators using PowerShell download cradles for software deployment.',
        likelihood: 'medium',
        tuningAdvice:
          'Exclude known admin accounts and scheduled maintenance windows.',
      },
    ],
    coverageGaps: [
      'Does not detect obfuscated PowerShell using alternative download methods.',
    ],
    recommendedLogSources: ['Sysmon EventID 1', 'Windows Security EventID 4688'],
    tuningRecommendations: [
      'Add parent process filtering for common admin tools.',
    ],
    ...overrides,
  };
}

function makeValidFPResponse(): FPAnalysisAIResponse {
  return {
    falsePositives: [
      {
        scenario:
          'SCCM client (CcmExec.exe) executing PowerShell scripts from C:\\Windows\\ccmcache\\ during software deployment cycles in enterprise environments.',
        likelihood: 'high',
        tuningAdvice:
          'Add a filter_sccm selection block with ParentImage containing CcmExec.exe and CommandLine containing ccmcache to exclude SCCM deployments.',
        parentProcess: 'C:\\Windows\\CCM\\CcmExec.exe',
        environment: 'Corporate workstations with SCCM',
      },
      {
        scenario:
          'Visual Studio Code integrated terminal spawning PowerShell with Invoke-WebRequest for extension installation and package management operations.',
        likelihood: 'medium',
        tuningAdvice:
          'Add a filter_vscode selection block with ParentImage containing Code.exe and exclude known VS Code extension installation paths.',
      },
      {
        scenario:
          'Azure DevOps build agents executing PowerShell deployment scripts that download artifacts from Azure Artifacts feed using Invoke-WebRequest.',
        likelihood: 'medium',
        tuningAdvice:
          'Add a filter_cicd selection block with ParentImage containing Agent.Worker.exe and User matching the build service account SID.',
        environment: 'CI/CD infrastructure',
      },
    ],
    overallFPRisk: 'medium',
    recommendations: [
      'Add parent process chain filters for known enterprise management tools.',
      'Consider adding a time-based threshold to reduce noise during maintenance windows.',
    ],
  };
}

// ===========================================================================
// buildFPAnalysisPrompt
// ===========================================================================

describe('buildFPAnalysisPrompt', () => {
  it('returns an object with system and user string properties', () => {
    const rule = makeRule();
    const result = buildFPAnalysisPrompt(rule);
    expect(result).toHaveProperty('system');
    expect(result).toHaveProperty('user');
    expect(typeof result.system).toBe('string');
    expect(typeof result.user).toBe('string');
  });

  it('returns non-empty system and user strings', () => {
    const rule = makeRule();
    const { system, user } = buildFPAnalysisPrompt(rule);
    expect(system.length).toBeGreaterThan(0);
    expect(user.length).toBeGreaterThan(0);
  });

  // -----------------------------------------------------------------------
  // System prompt checks
  // -----------------------------------------------------------------------

  describe('system prompt', () => {
    it('contains SOC analyst persona', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      expect(system).toContain('SOC analyst');
    });

    it('mentions specific FP scenarios and tuning advice', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      expect(system).toContain('false positive');
      expect(system).toContain('tuning');
    });

    it('mentions enterprise environments', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      expect(system).toContain('enterprise');
    });

    it('specifies JSON output format requirements', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      expect(system).toContain('JSON');
      expect(system).toContain('falsePositives');
      expect(system).toContain('overallFPRisk');
      expect(system).toContain('recommendations');
    });

    it('mentions specific FP scenario examples like SCCM or wuauclt', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      // The system prompt includes concrete good/bad examples
      expect(system).toContain('SCCM');
    });

    it('mentions corporate workstations and CI/CD environments', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      expect(system).toContain('Corporate workstations');
      expect(system).toContain('CI/CD');
    });

    it('mentions developer machines', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      expect(system).toContain('Developer machines');
    });

    it('mentions likelihood levels: high, medium, low', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      expect(system).toContain('high');
      expect(system).toContain('medium');
      expect(system).toContain('low');
    });

    it('instructs between 3 and 7 false positive scenarios', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      expect(system).toContain('3');
      expect(system).toContain('7');
    });

    it('mentions Sigma, YARA, and Suricata formats', () => {
      const { system } = buildFPAnalysisPrompt(makeRule());
      expect(system).toContain('Sigma');
      expect(system).toContain('YARA');
      expect(system).toContain('Suricata');
    });
  });

  // -----------------------------------------------------------------------
  // User prompt with Sigma rule
  // -----------------------------------------------------------------------

  describe('user prompt with Sigma rule', () => {
    it('includes "Sigma (SIEM)" format label', () => {
      const { user } = buildFPAnalysisPrompt(makeRule());
      expect(user).toContain('Sigma (SIEM)');
    });

    it('includes ATT&CK technique ID', () => {
      const { user } = buildFPAnalysisPrompt(makeRule());
      expect(user).toContain('T1059.001');
    });

    it('includes ATT&CK tactic', () => {
      const { user } = buildFPAnalysisPrompt(makeRule());
      expect(user).toContain('execution');
    });

    it('includes rule confidence', () => {
      const { user } = buildFPAnalysisPrompt(makeRule());
      expect(user).toContain('high');
    });

    it('includes raw rule text in code block', () => {
      const rule = makeRule();
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).toContain('```');
      expect(user).toContain(rule.sigma!.raw);
    });
  });

  // -----------------------------------------------------------------------
  // User prompt with YARA rule
  // -----------------------------------------------------------------------

  describe('user prompt with YARA rule', () => {
    it('includes "YARA (file/malware)" format label', () => {
      const { user } = buildFPAnalysisPrompt(makeYaraGeneratedRule());
      expect(user).toContain('YARA (file/malware)');
    });

    it('includes raw YARA rule text', () => {
      const rule = makeYaraGeneratedRule();
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).toContain(rule.yara!.raw);
    });
  });

  // -----------------------------------------------------------------------
  // User prompt with Suricata rule
  // -----------------------------------------------------------------------

  describe('user prompt with Suricata rule', () => {
    it('includes "Suricata (network IDS)" format label', () => {
      const { user } = buildFPAnalysisPrompt(makeSuricataGeneratedRule());
      expect(user).toContain('Suricata (network IDS)');
    });

    it('includes raw Suricata rule text', () => {
      const rule = makeSuricataGeneratedRule();
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).toContain(rule.suricata!.raw);
    });
  });

  // -----------------------------------------------------------------------
  // User prompt edge cases
  // -----------------------------------------------------------------------

  describe('user prompt edge cases', () => {
    it('handles missing ATT&CK technique gracefully', () => {
      const rule = makeRule({
        attackTechniqueId: undefined,
      });
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).toContain('Not specified');
      expect(typeof user).toBe('string');
    });

    it('handles missing ATT&CK tactic gracefully', () => {
      const rule = makeRule({
        attackTactic: undefined,
      });
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).toContain('Not specified');
    });

    it('handles missing both technique and tactic', () => {
      const rule = makeRule({
        attackTechniqueId: undefined,
        attackTactic: undefined,
      });
      const { user } = buildFPAnalysisPrompt(rule);
      // Should mention "Not specified" for both
      const notSpecifiedCount = (
        user.match(/Not specified/g) || []
      ).length;
      expect(notSpecifiedCount).toBeGreaterThanOrEqual(2);
    });

    it('handles missing sourceTtp', () => {
      const rule = makeRule({ sourceTtp: undefined });
      const { user } = buildFPAnalysisPrompt(rule);
      // The sourceTtp section should be omitted rather than crash
      expect(typeof user).toBe('string');
      expect(user.length).toBeGreaterThan(0);
    });

    it('includes sourceTtp when present', () => {
      const rule = makeRule({
        sourceTtp: 'Threat actor uses PowerShell to download and execute payloads',
      });
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).toContain(
        'Threat actor uses PowerShell to download and execute payloads',
      );
    });

    it('includes documentation context when rule.documentation is present', () => {
      const doc = makeDocumentation();
      const rule = makeRule({ documentation: doc });
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).toContain('Rule Documentation Context');
      expect(user).toContain(doc.whatItDetects);
      expect(user).toContain(doc.howItWorks);
    });

    it('includes known FP hints from documentation', () => {
      const doc = makeDocumentation();
      const rule = makeRule({ documentation: doc });
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).toContain('Known FP hints');
      expect(user).toContain(
        'System administrators using PowerShell download cradles',
      );
    });

    it('includes coverage gaps from documentation', () => {
      const doc = makeDocumentation();
      const rule = makeRule({ documentation: doc });
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).toContain('Coverage gaps');
      expect(user).toContain(
        'Does not detect obfuscated PowerShell',
      );
    });

    it('omits documentation section when rule.documentation is undefined', () => {
      const rule = makeRule({ documentation: undefined });
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).not.toContain('Rule Documentation Context');
    });

    it('omits FP hints when documentation has no falsePositives', () => {
      const doc = makeDocumentation({ falsePositives: [] });
      const rule = makeRule({ documentation: doc });
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).not.toContain('Known FP hints');
    });

    it('omits coverage gaps when documentation has no gaps', () => {
      const doc = makeDocumentation({ coverageGaps: [] });
      const rule = makeRule({ documentation: doc });
      const { user } = buildFPAnalysisPrompt(rule);
      expect(user).not.toContain('Coverage gaps');
    });
  });
});

// ===========================================================================
// parseFPAnalysisAIResponse
// ===========================================================================

describe('parseFPAnalysisAIResponse', () => {
  // -----------------------------------------------------------------------
  // Valid responses
  // -----------------------------------------------------------------------

  describe('valid responses', () => {
    it('parses valid JSON with 3 FP scenarios (minimum)', () => {
      const response = makeValidFPResponse();
      const raw = JSON.stringify(response);
      const result = parseFPAnalysisAIResponse(raw);
      expect(result.falsePositives).toHaveLength(3);
      expect(result.overallFPRisk).toBe('medium');
      expect(result.recommendations).toHaveLength(2);
    });

    it('parses valid JSON with 7 FP scenarios (maximum)', () => {
      const response = makeValidFPResponse();
      // Add 4 more scenarios to reach 7
      for (let i = 0; i < 4; i++) {
        response.falsePositives.push({
          scenario: `Additional false positive scenario number ${i + 4} with sufficient detail for validation.`,
          likelihood: 'low',
          tuningAdvice: `Add specific filter conditions to exclude this scenario from triggering the rule.`,
        });
      }
      const raw = JSON.stringify(response);
      const result = parseFPAnalysisAIResponse(raw);
      expect(result.falsePositives).toHaveLength(7);
    });

    it('parses markdown-wrapped JSON response', () => {
      const response = makeValidFPResponse();
      const raw =
        '```json\n' + JSON.stringify(response, null, 2) + '\n```';
      const result = parseFPAnalysisAIResponse(raw);
      expect(result.falsePositives).toHaveLength(3);
      expect(result.overallFPRisk).toBe('medium');
    });

    it('parses JSON with surrounding text', () => {
      const response = makeValidFPResponse();
      const raw =
        'Here is my analysis of the false positive scenarios:\n\n' +
        JSON.stringify(response) +
        '\n\nLet me know if you need more detail.';
      const result = parseFPAnalysisAIResponse(raw);
      expect(result.falsePositives).toHaveLength(3);
    });

    it('preserves optional parentProcess and environment fields', () => {
      const response = makeValidFPResponse();
      const raw = JSON.stringify(response);
      const result = parseFPAnalysisAIResponse(raw);
      // First scenario has both optional fields
      expect(result.falsePositives[0].parentProcess).toBe(
        'C:\\Windows\\CCM\\CcmExec.exe',
      );
      expect(result.falsePositives[0].environment).toBe(
        'Corporate workstations with SCCM',
      );
      // Second scenario has neither optional field
      expect(result.falsePositives[1].parentProcess).toBeUndefined();
      expect(result.falsePositives[1].environment).toBeUndefined();
    });

    it('accepts all valid likelihood values', () => {
      const likelihoods = ['high', 'medium', 'low'] as const;
      for (const likelihood of likelihoods) {
        const response = makeValidFPResponse();
        response.falsePositives[0].likelihood = likelihood;
        const raw = JSON.stringify(response);
        const result = parseFPAnalysisAIResponse(raw);
        expect(result.falsePositives[0].likelihood).toBe(likelihood);
      }
    });

    it('accepts all valid overallFPRisk values', () => {
      const risks = ['high', 'medium', 'low'] as const;
      for (const risk of risks) {
        const response = makeValidFPResponse();
        response.overallFPRisk = risk;
        const raw = JSON.stringify(response);
        const result = parseFPAnalysisAIResponse(raw);
        expect(result.overallFPRisk).toBe(risk);
      }
    });

    it('accepts an empty recommendations array', () => {
      const response = makeValidFPResponse();
      response.recommendations = [];
      const raw = JSON.stringify(response);
      const result = parseFPAnalysisAIResponse(raw);
      expect(result.recommendations).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // Invalid responses
  // -----------------------------------------------------------------------

  describe('invalid responses', () => {
    it('rejects fewer than 3 FP scenarios', () => {
      const response = makeValidFPResponse();
      response.falsePositives = response.falsePositives.slice(0, 2);
      const raw = JSON.stringify(response);
      expect(() => parseFPAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects more than 7 FP scenarios', () => {
      const response = makeValidFPResponse();
      // Add scenarios until we have 8
      while (response.falsePositives.length < 8) {
        response.falsePositives.push({
          scenario: `Extra false positive scenario with enough detail to pass the minimum character check here.`,
          likelihood: 'low',
          tuningAdvice:
            'Add specific filter conditions to exclude this scenario from triggering the detection rule.',
        });
      }
      const raw = JSON.stringify(response);
      expect(() => parseFPAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects scenario too short (< 20 chars)', () => {
      const response = makeValidFPResponse();
      response.falsePositives[0].scenario = 'Too short.';
      const raw = JSON.stringify(response);
      expect(() => parseFPAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects tuningAdvice too short (< 20 chars)', () => {
      const response = makeValidFPResponse();
      response.falsePositives[0].tuningAdvice = 'Short advice.';
      const raw = JSON.stringify(response);
      expect(() => parseFPAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects invalid likelihood value', () => {
      const response = makeValidFPResponse() as any;
      response.falsePositives[0].likelihood = 'critical';
      const raw = JSON.stringify(response);
      expect(() => parseFPAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects missing overallFPRisk', () => {
      const response = makeValidFPResponse() as any;
      delete response.overallFPRisk;
      const raw = JSON.stringify(response);
      expect(() => parseFPAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects invalid overallFPRisk value', () => {
      const response = makeValidFPResponse() as any;
      response.overallFPRisk = 'critical';
      const raw = JSON.stringify(response);
      expect(() => parseFPAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects completely invalid JSON', () => {
      expect(() =>
        parseFPAnalysisAIResponse('This is not JSON at all.'),
      ).toThrow();
    });

    it('rejects empty falsePositives array', () => {
      const response = makeValidFPResponse() as any;
      response.falsePositives = [];
      const raw = JSON.stringify(response);
      expect(() => parseFPAnalysisAIResponse(raw)).toThrow();
    });

    it('rejects missing falsePositives field', () => {
      const response = makeValidFPResponse() as any;
      delete response.falsePositives;
      const raw = JSON.stringify(response);
      expect(() => parseFPAnalysisAIResponse(raw)).toThrow();
    });

    it('error message contains "validation failed"', () => {
      const response = makeValidFPResponse();
      response.falsePositives[0].scenario = 'Short';
      const raw = JSON.stringify(response);
      try {
        parseFPAnalysisAIResponse(raw);
        expect.unreachable('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('validation failed');
      }
    });
  });
});

// ===========================================================================
// FPAnalysisAIResponseSchema (direct Zod validation)
// ===========================================================================

describe('FPAnalysisAIResponseSchema', () => {
  it('parses a fully valid object', () => {
    const valid = makeValidFPResponse();
    const result = FPAnalysisAIResponseSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('allows optional parentProcess field', () => {
    const valid = makeValidFPResponse();
    delete (valid.falsePositives[0] as any).parentProcess;
    const result = FPAnalysisAIResponseSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('allows optional environment field', () => {
    const valid = makeValidFPResponse();
    delete (valid.falsePositives[0] as any).environment;
    const result = FPAnalysisAIResponseSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('allows both optional fields to be absent', () => {
    const valid = makeValidFPResponse();
    valid.falsePositives = valid.falsePositives.map((fp) => ({
      scenario: fp.scenario,
      likelihood: fp.likelihood,
      tuningAdvice: fp.tuningAdvice,
    }));
    const result = FPAnalysisAIResponseSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('rejects missing scenario field', () => {
    const obj = makeValidFPResponse() as any;
    delete obj.falsePositives[0].scenario;
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('rejects missing likelihood field', () => {
    const obj = makeValidFPResponse() as any;
    delete obj.falsePositives[0].likelihood;
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('rejects missing tuningAdvice field', () => {
    const obj = makeValidFPResponse() as any;
    delete obj.falsePositives[0].tuningAdvice;
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('rejects missing overallFPRisk field', () => {
    const obj = makeValidFPResponse() as any;
    delete obj.overallFPRisk;
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('rejects missing recommendations field', () => {
    const obj = makeValidFPResponse() as any;
    delete obj.recommendations;
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('scenario minimum length is 20', () => {
    const obj = makeValidFPResponse();
    obj.falsePositives[0].scenario = '1234567890123456789'; // 19 chars
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);

    obj.falsePositives[0].scenario = '12345678901234567890'; // 20 chars
    const resultOk = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(resultOk.success).toBe(true);
  });

  it('tuningAdvice minimum length is 20', () => {
    const obj = makeValidFPResponse();
    obj.falsePositives[0].tuningAdvice = '1234567890123456789'; // 19 chars
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);

    obj.falsePositives[0].tuningAdvice = '12345678901234567890'; // 20 chars
    const resultOk = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(resultOk.success).toBe(true);
  });

  it('falsePositives array minimum is 3', () => {
    const obj = makeValidFPResponse();
    obj.falsePositives = obj.falsePositives.slice(0, 2);
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('falsePositives array maximum is 7', () => {
    const obj = makeValidFPResponse();
    while (obj.falsePositives.length < 8) {
      obj.falsePositives.push({
        scenario:
          'Additional FP scenario with enough length to pass validation requirements.',
        likelihood: 'low',
        tuningAdvice:
          'Additional tuning advice with enough length to pass validation requirements.',
      });
    }
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('likelihood must be one of high, medium, low', () => {
    const obj = makeValidFPResponse() as any;
    obj.falsePositives[0].likelihood = 'critical';
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });

  it('overallFPRisk must be one of high, medium, low', () => {
    const obj = makeValidFPResponse() as any;
    obj.overallFPRisk = 'very-high';
    const result = FPAnalysisAIResponseSchema.safeParse(obj);
    expect(result.success).toBe(false);
  });
});
