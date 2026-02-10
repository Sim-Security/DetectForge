/**
 * Unit tests for the coverage gap analyzer module.
 *
 * Covers: analyzeCoverageGaps (mocking AI client, prompt builder, and retry)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { GeneratedRule } from '@/types/detection-rule.js';
import type { ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';
import type { GapAnalysisAIResponse } from '@/ai/prompts/gap-analysis.js';
import type { APIUsage } from '@/types/config.js';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockBuildGapAnalysisPrompt = vi.fn();
const mockParseGapAnalysisAIResponse = vi.fn();
const mockWithRetry = vi.fn();

vi.mock('@/ai/prompts/gap-analysis.js', () => ({
  buildGapAnalysisPrompt: (...args: unknown[]) =>
    mockBuildGapAnalysisPrompt(...args),
  parseGapAnalysisAIResponse: (...args: unknown[]) =>
    mockParseGapAnalysisAIResponse(...args),
}));

vi.mock('@/ai/retry.js', () => ({
  withRetry: (...args: unknown[]) => mockWithRetry(...args),
}));

// Import after mocks are established
const { analyzeCoverageGaps } = await import(
  '@/generation/coverage-gap-analyzer.js'
);

// ---------------------------------------------------------------------------
// Fixture Builders
// ---------------------------------------------------------------------------

function makeTTP(overrides: Partial<ExtractedTTP> = {}): ExtractedTTP {
  return {
    description:
      'Threat actor uses PowerShell to download and execute a payload.',
    tools: ['PowerShell'],
    targetPlatforms: ['windows'],
    artifacts: [
      {
        type: 'process',
        description: 'powershell.exe spawned',
        value: 'powershell.exe',
      },
    ],
    detectionOpportunities: ['Monitor PowerShell process creation'],
    confidence: 'high',
    ...overrides,
  };
}

function makeMapping(
  overrides: Partial<AttackMappingResult> = {},
): AttackMappingResult {
  return {
    techniqueId: 'T1059.001',
    techniqueName: 'PowerShell',
    tactic: 'execution',
    confidence: 'high',
    reasoning: 'Uses PowerShell for execution.',
    sourceTtp: makeTTP(),
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
      description: 'Detects PowerShell download cradle patterns.',
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
      falsepositives: ['Admin scripts'],
      level: 'high',
      raw: 'title: Suspicious PowerShell Download Cradle',
    },
    sourceReportId: 'report-1',
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

function makeValidGapResponse(): GapAnalysisAIResponse {
  return {
    uncoveredTTPs: [
      {
        ttpDescription: 'Credential dumping via LSASS',
        techniqueId: 'T1003.001',
        reason: 'No Sysmon telemetry',
        alternativeDetection: 'Enable Sysmon Event ID 10',
        requiredLogSources: ['Sysmon'],
      },
    ],
    evasionVectors: [
      {
        ruleAffected: 'Suspicious PowerShell Download Cradle',
        evasionTechnique: 'Base64 encoding of cmdlet names',
        mitigationSuggestion: 'Add ScriptBlock logging',
      },
    ],
    logSourceGaps: [
      {
        logSource: 'Sysmon',
        requiredFor: ['T1003.001'],
        currentlyAvailable: false,
        recommendation: 'Deploy Sysmon',
      },
    ],
    overallCoverage: {
      coveredTechniqueCount: 1,
      totalTechniqueCount: 2,
      coveragePercentage: 50.0,
      strongestTactic: 'Execution',
      weakestTactic: 'Credential Access',
    },
    recommendations: [
      'Deploy Sysmon',
      'Enable PowerShell ScriptBlock logging',
      'Add network detection rules',
    ],
  };
}

function makeUsage(): APIUsage {
  return {
    operation: 'inference',
    model: 'anthropic/claude-sonnet-4',
    inputTokens: 5000,
    outputTokens: 2000,
    costUsd: 0.045,
    durationMs: 3200,
    timestamp: '2026-02-10T12:00:00.000Z',
  };
}

function makeMockClient() {
  return {
    prompt: vi.fn(),
    infer: vi.fn(),
    promptJson: vi.fn(),
    getUsageLog: vi.fn().mockReturnValue([]),
    getCostSummary: vi.fn(),
    resetUsage: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();

  // Default mock implementations
  mockBuildGapAnalysisPrompt.mockReturnValue({
    system: 'You are a detection engineering manager...',
    user: 'Analyze the following...',
  });

  const parsedResponse = makeValidGapResponse();
  mockParseGapAnalysisAIResponse.mockReturnValue(parsedResponse);

  const usage = makeUsage();
  mockWithRetry.mockImplementation(async (fn: () => Promise<unknown>) => {
    return fn();
  });
});

// ===========================================================================
// analyzeCoverageGaps
// ===========================================================================

describe('analyzeCoverageGaps', () => {
  it('returns a CoverageGapResult with all expected fields', async () => {
    const client = makeMockClient();
    const usage = makeUsage();
    client.prompt.mockResolvedValue({
      content: JSON.stringify(makeValidGapResponse()),
      usage,
    });

    const rules = [makeRule()];
    const ttps = [makeTTP()];
    const mappings = [makeMapping()];

    const result = await analyzeCoverageGaps(rules, ttps, mappings, {
      client: client as any,
    });

    expect(result).toHaveProperty('uncoveredTTPs');
    expect(result).toHaveProperty('evasionVectors');
    expect(result).toHaveProperty('logSourceGaps');
    expect(result).toHaveProperty('overallCoverage');
    expect(result).toHaveProperty('recommendations');
    expect(result).toHaveProperty('usage');
  });

  it('uses "quality" model tier by default (NOT "standard")', async () => {
    const client = makeMockClient();
    const usage = makeUsage();
    client.prompt.mockResolvedValue({
      content: JSON.stringify(makeValidGapResponse()),
      usage,
    });

    const rules = [makeRule()];
    const ttps = [makeTTP()];
    const mappings = [makeMapping()];

    await analyzeCoverageGaps(rules, ttps, mappings, {
      client: client as any,
    });

    // The client.prompt call receives the model tier in options
    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      { model: 'quality' },
    );
  });

  it('respects custom modelTier', async () => {
    const client = makeMockClient();
    const usage = makeUsage();
    client.prompt.mockResolvedValue({
      content: JSON.stringify(makeValidGapResponse()),
      usage,
    });

    await analyzeCoverageGaps([makeRule()], [makeTTP()], [makeMapping()], {
      client: client as any,
      modelTier: 'fast',
    });

    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      { model: 'fast' },
    );
  });

  it('passes correct arguments to buildGapAnalysisPrompt', async () => {
    const client = makeMockClient();
    const usage = makeUsage();
    client.prompt.mockResolvedValue({
      content: JSON.stringify(makeValidGapResponse()),
      usage,
    });

    const rules = [makeRule()];
    const ttps = [makeTTP()];
    const mappings = [makeMapping()];

    await analyzeCoverageGaps(rules, ttps, mappings, {
      client: client as any,
    });

    expect(mockBuildGapAnalysisPrompt).toHaveBeenCalledWith(
      rules,
      ttps,
      mappings,
    );
  });

  it('calls withRetry with maxRetries: 3', async () => {
    const client = makeMockClient();
    const usage = makeUsage();
    client.prompt.mockResolvedValue({
      content: JSON.stringify(makeValidGapResponse()),
      usage,
    });

    await analyzeCoverageGaps([makeRule()], [makeTTP()], [makeMapping()], {
      client: client as any,
    });

    expect(mockWithRetry).toHaveBeenCalledWith(
      expect.any(Function),
      { maxRetries: 3 },
    );
  });

  it('returns all parsed fields in the result', async () => {
    const client = makeMockClient();
    const usage = makeUsage();
    const parsed = makeValidGapResponse();

    client.prompt.mockResolvedValue({
      content: JSON.stringify(parsed),
      usage,
    });

    const result = await analyzeCoverageGaps(
      [makeRule()],
      [makeTTP()],
      [makeMapping()],
      { client: client as any },
    );

    expect(result.uncoveredTTPs).toEqual(parsed.uncoveredTTPs);
    expect(result.evasionVectors).toEqual(parsed.evasionVectors);
    expect(result.logSourceGaps).toEqual(parsed.logSourceGaps);
    expect(result.overallCoverage).toEqual(parsed.overallCoverage);
    expect(result.recommendations).toEqual(parsed.recommendations);
    expect(result.usage).toEqual(usage);
  });

  it('returns the usage from the AI client response', async () => {
    const client = makeMockClient();
    const usage = makeUsage();
    client.prompt.mockResolvedValue({
      content: JSON.stringify(makeValidGapResponse()),
      usage,
    });

    const result = await analyzeCoverageGaps(
      [makeRule()],
      [makeTTP()],
      [makeMapping()],
      { client: client as any },
    );

    expect(result.usage).toBe(usage);
    expect(result.usage.model).toBe('anthropic/claude-sonnet-4');
    expect(result.usage.inputTokens).toBe(5000);
    expect(result.usage.outputTokens).toBe(2000);
  });

  it('throws when AI response fails parsing', async () => {
    const client = makeMockClient();
    const usage = makeUsage();
    client.prompt.mockResolvedValue({
      content: 'not valid json',
      usage,
    });

    mockParseGapAnalysisAIResponse.mockImplementation(() => {
      throw new Error('Gap analysis AI response validation failed: invalid');
    });

    await expect(
      analyzeCoverageGaps([makeRule()], [makeTTP()], [makeMapping()], {
        client: client as any,
      }),
    ).rejects.toThrow('validation failed');
  });

  it('propagates errors from withRetry (e.g., API failures)', async () => {
    const client = makeMockClient();

    mockWithRetry.mockRejectedValue(
      new Error('OpenRouter API error (500): Internal Server Error'),
    );

    await expect(
      analyzeCoverageGaps([makeRule()], [makeTTP()], [makeMapping()], {
        client: client as any,
      }),
    ).rejects.toThrow('OpenRouter API error');
  });

  it('passes the AI response content to parseGapAnalysisAIResponse', async () => {
    const client = makeMockClient();
    const usage = makeUsage();
    const rawContent = JSON.stringify(makeValidGapResponse());
    client.prompt.mockResolvedValue({
      content: rawContent,
      usage,
    });

    await analyzeCoverageGaps([makeRule()], [makeTTP()], [makeMapping()], {
      client: client as any,
    });

    expect(mockParseGapAnalysisAIResponse).toHaveBeenCalledWith(rawContent);
  });

  it('calls the prompt builder before invoking the AI client', async () => {
    const callOrder: string[] = [];

    mockBuildGapAnalysisPrompt.mockImplementation(() => {
      callOrder.push('buildPrompt');
      return {
        system: 'system prompt',
        user: 'user prompt',
      };
    });

    const client = makeMockClient();
    const usage = makeUsage();
    client.prompt.mockImplementation(async () => {
      callOrder.push('clientPrompt');
      return {
        content: JSON.stringify(makeValidGapResponse()),
        usage,
      };
    });

    await analyzeCoverageGaps([makeRule()], [makeTTP()], [makeMapping()], {
      client: client as any,
    });

    expect(callOrder.indexOf('buildPrompt')).toBeLessThan(
      callOrder.indexOf('clientPrompt'),
    );
  });
});
