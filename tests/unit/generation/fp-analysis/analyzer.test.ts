/**
 * Unit tests for the false positive analyzer.
 *
 * Covers: analyzeFalsePositives function behavior including prompt building,
 * AI client interaction, response parsing, FP scenario mapping, and defaults.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { analyzeFalsePositives } from '@/generation/false-positive-analyzer.js';
import type { FPAnalysisResult } from '@/generation/false-positive-analyzer.js';
import type {
  GeneratedRule,
  SigmaRule,
  ValidationResult,
} from '@/types/detection-rule.js';
import type { AIClient, InferenceResult } from '@/ai/client.js';
import type { APIUsage } from '@/types/config.js';

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

const mockBuildFPAnalysisPrompt = vi.fn();
const mockParseFPAnalysisAIResponse = vi.fn();
const mockWithRetry = vi.fn();

vi.mock('@/ai/prompts/fp-analysis.js', () => ({
  buildFPAnalysisPrompt: (...args: unknown[]) =>
    mockBuildFPAnalysisPrompt(...args),
  parseFPAnalysisAIResponse: (...args: unknown[]) =>
    mockParseFPAnalysisAIResponse(...args),
}));

vi.mock('@/ai/retry.js', () => ({
  withRetry: (...args: unknown[]) => mockWithRetry(...args),
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
      'Detects PowerShell execution with download cradle patterns.',
    references: ['https://attack.mitre.org/techniques/T1059/001/'],
    author: 'DetectForge',
    date: '2026-02-10',
    modified: '2026-02-10',
    tags: ['attack.execution', 'attack.t1059.001'],
    logsource: { product: 'windows', category: 'process_creation' },
    detection: {
      selection: {
        Image: ['*\\powershell.exe'],
        CommandLine: ['*Invoke-WebRequest*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate administrative download scripts'],
    level: 'high',
    raw: 'title: Suspicious PowerShell Download Cradle\nstatus: experimental\nlevel: high',
    ...overrides,
  };
}

function makeRule(overrides?: Partial<GeneratedRule>): GeneratedRule {
  return {
    format: 'sigma',
    sigma: makeSigmaRule(),
    sourceReportId: 'report-001',
    sourceTtp: 'Threat actor uses PowerShell to download and execute payloads',
    attackTechniqueId: 'T1059.001',
    attackTactic: 'execution',
    confidence: 'high',
    validation: makeValidation(),
    ...overrides,
  };
}

function makeUsage(overrides?: Partial<APIUsage>): APIUsage {
  return {
    operation: 'inference',
    model: 'anthropic/claude-3.5-haiku',
    inputTokens: 1500,
    outputTokens: 800,
    costUsd: 0.0044,
    durationMs: 2300,
    timestamp: '2026-02-10T12:00:00.000Z',
    ...overrides,
  };
}

function makeParsedAIResponse() {
  return {
    falsePositives: [
      {
        scenario:
          'SCCM client (CcmExec.exe) executing PowerShell scripts from C:\\Windows\\ccmcache\\ during software deployment cycles.',
        likelihood: 'high' as const,
        tuningAdvice:
          'Add a filter_sccm selection block with ParentImage containing CcmExec.exe and CommandLine containing ccmcache.',
        parentProcess: 'C:\\Windows\\CCM\\CcmExec.exe',
        environment: 'Corporate workstations with SCCM',
      },
      {
        scenario:
          'Visual Studio Code integrated terminal spawning PowerShell with Invoke-WebRequest for extension installation.',
        likelihood: 'medium' as const,
        tuningAdvice:
          'Add a filter_vscode selection block with ParentImage containing Code.exe to exclude VS Code terminals.',
      },
      {
        scenario:
          'Azure DevOps build agents executing PowerShell deployment scripts that download artifacts from Azure feeds.',
        likelihood: 'medium' as const,
        tuningAdvice:
          'Add a filter_cicd selection block with ParentImage containing Agent.Worker.exe and build service account.',
        environment: 'CI/CD infrastructure',
      },
    ],
    overallFPRisk: 'medium' as const,
    recommendations: [
      'Add parent process chain filters for known enterprise management tools.',
      'Consider adding a time-based threshold to reduce noise during maintenance windows.',
    ],
  };
}

function makeMockClient(): AIClient {
  return {
    prompt: vi.fn(),
    infer: vi.fn(),
    promptJson: vi.fn(),
    getUsageLog: vi.fn(),
    getCostSummary: vi.fn(),
    resetUsage: vi.fn(),
  } as unknown as AIClient;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();

  // Default mock behavior: buildFPAnalysisPrompt returns system/user strings
  mockBuildFPAnalysisPrompt.mockReturnValue({
    system: 'You are a senior SOC analyst...',
    user: 'Analyze the following detection rule...',
  });

  // Default mock behavior: parseFPAnalysisAIResponse returns valid parsed result
  mockParseFPAnalysisAIResponse.mockReturnValue(makeParsedAIResponse());

  // Default mock behavior: withRetry calls the function immediately and returns
  const usage = makeUsage();
  mockWithRetry.mockImplementation(async (fn: () => Promise<unknown>) => {
    return fn();
  });
});

// ===========================================================================
// analyzeFalsePositives
// ===========================================================================

describe('analyzeFalsePositives', () => {
  // -----------------------------------------------------------------------
  // Happy path
  // -----------------------------------------------------------------------

  it('returns FPAnalysisResult with falsePositives, overallFPRisk, recommendations, and usage', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw AI response content',
      usage,
    });

    const result = await analyzeFalsePositives(rule, { client });

    expect(result).toHaveProperty('falsePositives');
    expect(result).toHaveProperty('overallFPRisk');
    expect(result).toHaveProperty('recommendations');
    expect(result).toHaveProperty('usage');
    expect(result.overallFPRisk).toBe('medium');
    expect(result.recommendations).toHaveLength(2);
    expect(result.usage).toEqual(usage);
  });

  // -----------------------------------------------------------------------
  // FalsePositiveScenario mapping
  // -----------------------------------------------------------------------

  it('maps AI response to FalsePositiveScenario with only scenario, likelihood, tuningAdvice', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw AI response content',
      usage,
    });

    const result = await analyzeFalsePositives(rule, { client });

    // Each mapped FP should only have scenario, likelihood, tuningAdvice (no parentProcess/environment)
    for (const fp of result.falsePositives) {
      expect(fp).toHaveProperty('scenario');
      expect(fp).toHaveProperty('likelihood');
      expect(fp).toHaveProperty('tuningAdvice');
      expect(fp).not.toHaveProperty('parentProcess');
      expect(fp).not.toHaveProperty('environment');
    }

    expect(result.falsePositives).toHaveLength(3);
    expect(result.falsePositives[0].scenario).toContain('SCCM');
    expect(result.falsePositives[0].likelihood).toBe('high');
  });

  // -----------------------------------------------------------------------
  // Default options
  // -----------------------------------------------------------------------

  it('uses "standard" model tier by default', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw AI response content',
      usage,
    });

    await analyzeFalsePositives(rule, { client });

    // The withRetry mock calls the fn, which calls client.prompt
    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.objectContaining({ model: 'standard' }),
    );
  });

  it('uses default maxTokens of 2048', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw response',
      usage,
    });

    await analyzeFalsePositives(rule, { client });

    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.objectContaining({ maxTokens: 2048 }),
    );
  });

  it('uses default temperature of 0.3', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw response',
      usage,
    });

    await analyzeFalsePositives(rule, { client });

    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.objectContaining({ temperature: 0.3 }),
    );
  });

  // -----------------------------------------------------------------------
  // Custom options
  // -----------------------------------------------------------------------

  it('respects custom modelTier', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw response',
      usage,
    });

    await analyzeFalsePositives(rule, { client, modelTier: 'quality' });

    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.objectContaining({ model: 'quality' }),
    );
  });

  it('respects custom maxTokens', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw response',
      usage,
    });

    await analyzeFalsePositives(rule, { client, maxTokens: 4096 });

    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.objectContaining({ maxTokens: 4096 }),
    );
  });

  it('respects custom temperature', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw response',
      usage,
    });

    await analyzeFalsePositives(rule, { client, temperature: 0.7 });

    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.objectContaining({ temperature: 0.7 }),
    );
  });

  // -----------------------------------------------------------------------
  // Retry behavior
  // -----------------------------------------------------------------------

  it('passes maxRetries to withRetry (default 3)', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw response',
      usage,
    });

    await analyzeFalsePositives(rule, { client });

    expect(mockWithRetry).toHaveBeenCalledWith(
      expect.any(Function),
      expect.objectContaining({ maxRetries: 3 }),
    );
  });

  it('passes custom maxRetries to withRetry', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw response',
      usage,
    });

    await analyzeFalsePositives(rule, { client, maxRetries: 5 });

    expect(mockWithRetry).toHaveBeenCalledWith(
      expect.any(Function),
      expect.objectContaining({ maxRetries: 5 }),
    );
  });

  // -----------------------------------------------------------------------
  // Error handling
  // -----------------------------------------------------------------------

  it('throws when AI response is invalid (parseFPAnalysisAIResponse throws)', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'invalid response',
      usage,
    });

    mockParseFPAnalysisAIResponse.mockImplementation(() => {
      throw new Error('FP analysis AI response validation failed: bad data');
    });

    await expect(
      analyzeFalsePositives(rule, { client }),
    ).rejects.toThrow('validation failed');
  });

  it('calls buildFPAnalysisPrompt with the rule', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const usage = makeUsage();

    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: 'raw response',
      usage,
    });

    await analyzeFalsePositives(rule, { client });

    expect(mockBuildFPAnalysisPrompt).toHaveBeenCalledWith(rule);
  });
});
