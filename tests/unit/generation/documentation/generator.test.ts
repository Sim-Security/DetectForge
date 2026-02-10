/**
 * Unit tests for the Documentation generator.
 *
 * Covers: generateDocumentation, DocumentationOptions, DocumentationResult
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { GeneratedRule, SigmaRule, ValidationResult } from '@/types/detection-rule.js';
import type { AIClient, InferenceResult } from '@/ai/client.js';
import type { APIUsage } from '@/types/config.js';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockBuildDocumentationPrompt = vi.fn();
const mockParseDocumentationAIResponse = vi.fn();
const mockWithRetry = vi.fn();

vi.mock('@/ai/prompts/documentation.js', () => ({
  buildDocumentationPrompt: (...args: unknown[]) =>
    mockBuildDocumentationPrompt(...args),
  parseDocumentationAIResponse: (...args: unknown[]) =>
    mockParseDocumentationAIResponse(...args),
}));

vi.mock('@/ai/retry.js', () => ({
  withRetry: (...args: unknown[]) => mockWithRetry(...args),
}));

// ---------------------------------------------------------------------------
// Import under test (after mocks are registered)
// ---------------------------------------------------------------------------

import { generateDocumentation } from '@/generation/documentation.js';
import type {
  DocumentationOptions,
  DocumentationResult,
} from '@/generation/documentation.js';

// ---------------------------------------------------------------------------
// Fixture Builders
// ---------------------------------------------------------------------------

function makeValidation(): ValidationResult {
  return {
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
  };
}

function makeSigmaData(): SigmaRule {
  return {
    id: 'abc123-def456',
    title: 'Suspicious PowerShell Download Cradle',
    status: 'experimental',
    description:
      'Detects PowerShell execution with download cradle patterns commonly used by threat actors.',
    references: ['https://attack.mitre.org/techniques/T1059/001/'],
    author: 'DetectForge',
    date: '2025-01-15',
    modified: '2025-01-15',
    tags: ['attack.execution', 'attack.t1059.001'],
    logsource: { product: 'windows', category: 'process_creation' },
    detection: {
      selection: {
        Image: ['*\\powershell.exe'],
        CommandLine: ['*Invoke-WebRequest*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Admin scripts'],
    level: 'high',
    raw: 'title: Suspicious PowerShell Download Cradle\nstatus: experimental\nlevel: high',
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

function makeUsage(): APIUsage {
  return {
    operation: 'inference',
    model: 'anthropic/claude-3.5-haiku',
    inputTokens: 1200,
    outputTokens: 800,
    costUsd: 0.0042,
    durationMs: 2500,
    timestamp: '2025-01-15T10:30:00.000Z',
  };
}

function makeDocumentationResponse() {
  return {
    whatItDetects:
      'This rule detects PowerShell processes that use download cradle techniques to fetch remote payloads.',
    howItWorks:
      'The rule monitors process creation events for powershell.exe with command-line arguments containing Invoke-WebRequest patterns.',
    attackMapping: {
      techniqueId: 'T1059.001',
      techniqueName: 'PowerShell',
      tactic: 'Execution',
      platform: 'Windows',
    },
    falsePositives: [
      {
        scenario: 'Admins using PowerShell for legitimate downloads.',
        likelihood: 'medium' as const,
        tuningAdvice: 'Allowlist known admin accounts.',
      },
    ],
    coverageGaps: ['Does not detect encoded PowerShell commands.'],
    recommendedLogSources: ['Windows Security Event Log 4688.'],
    tuningRecommendations: ['Exclude IT automation service accounts.'],
  };
}

function makeAIResult(): InferenceResult {
  return {
    content: JSON.stringify(makeDocumentationResponse()),
    usage: makeUsage(),
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

  // Default: withRetry passes through to the function it wraps
  mockWithRetry.mockImplementation(async (fn: () => Promise<unknown>) => fn());

  // Default: buildDocumentationPrompt returns dummy prompts
  mockBuildDocumentationPrompt.mockReturnValue({
    system: 'You are an expert documentation specialist.',
    user: 'Generate documentation for this rule.',
  });

  // Default: parseDocumentationAIResponse returns a valid response
  mockParseDocumentationAIResponse.mockReturnValue(makeDocumentationResponse());
});

// ===========================================================================
// generateDocumentation
// ===========================================================================

describe('generateDocumentation', () => {
  it('returns a DocumentationResult with documentation and usage', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(makeAIResult());

    const result = await generateDocumentation(rule, { client });

    expect(result).toHaveProperty('documentation');
    expect(result).toHaveProperty('usage');
    expect(result.documentation.whatItDetects).toBeDefined();
    expect(result.documentation.howItWorks).toBeDefined();
    expect(result.documentation.attackMapping).toBeDefined();
    expect(result.documentation.falsePositives).toBeDefined();
    expect(result.documentation.coverageGaps).toBeDefined();
    expect(result.documentation.recommendedLogSources).toBeDefined();
    expect(result.documentation.tuningRecommendations).toBeDefined();
    expect(result.usage).toEqual(makeUsage());
  });

  it('uses "standard" model tier by default', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(makeAIResult());

    await generateDocumentation(rule, { client });

    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      { model: 'standard' },
    );
  });

  it('respects custom modelTier option', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(makeAIResult());

    await generateDocumentation(rule, { client, modelTier: 'quality' });

    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      { model: 'quality' },
    );
  });

  it('calls withRetry for resilience', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(makeAIResult());

    await generateDocumentation(rule, { client });

    expect(mockWithRetry).toHaveBeenCalledTimes(1);
    expect(mockWithRetry).toHaveBeenCalledWith(expect.any(Function));
  });

  it('calls buildDocumentationPrompt with the rule', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(makeAIResult());

    await generateDocumentation(rule, { client });

    expect(mockBuildDocumentationPrompt).toHaveBeenCalledTimes(1);
    expect(mockBuildDocumentationPrompt).toHaveBeenCalledWith(rule);
  });

  it('passes system and user prompts to client.prompt', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(makeAIResult());

    mockBuildDocumentationPrompt.mockReturnValue({
      system: 'test-system-prompt',
      user: 'test-user-prompt',
    });

    await generateDocumentation(rule, { client });

    expect(client.prompt).toHaveBeenCalledWith(
      'test-system-prompt',
      'test-user-prompt',
      expect.any(Object),
    );
  });

  it('calls parseDocumentationAIResponse with the AI content', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    const aiResult = makeAIResult();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(aiResult);

    await generateDocumentation(rule, { client });

    expect(mockParseDocumentationAIResponse).toHaveBeenCalledTimes(1);
    expect(mockParseDocumentationAIResponse).toHaveBeenCalledWith(
      aiResult.content,
    );
  });

  it('throws when AI response parsing fails', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(makeAIResult());

    mockParseDocumentationAIResponse.mockImplementation(() => {
      throw new Error('Documentation AI response validation failed: invalid data');
    });

    await expect(
      generateDocumentation(rule, { client }),
    ).rejects.toThrow('validation failed');
  });

  it('throws when client.prompt rejects', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error('OpenRouter API error (500): Internal Server Error'),
    );
    // Make withRetry propagate the error (simulate non-retryable or exhausted retries)
    mockWithRetry.mockImplementation(async (fn: () => Promise<unknown>) => fn());

    await expect(
      generateDocumentation(rule, { client }),
    ).rejects.toThrow('OpenRouter API error');
  });

  it('returns properly shaped DocumentationResult', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(makeAIResult());

    const result: DocumentationResult = await generateDocumentation(rule, {
      client,
    });

    // Verify the documentation matches the expected shape
    expect(typeof result.documentation.whatItDetects).toBe('string');
    expect(typeof result.documentation.howItWorks).toBe('string');
    expect(typeof result.documentation.attackMapping.techniqueId).toBe('string');
    expect(typeof result.documentation.attackMapping.techniqueName).toBe('string');
    expect(typeof result.documentation.attackMapping.tactic).toBe('string');
    expect(typeof result.documentation.attackMapping.platform).toBe('string');
    expect(Array.isArray(result.documentation.falsePositives)).toBe(true);
    expect(Array.isArray(result.documentation.coverageGaps)).toBe(true);
    expect(Array.isArray(result.documentation.recommendedLogSources)).toBe(true);
    expect(Array.isArray(result.documentation.tuningRecommendations)).toBe(true);

    // Verify usage fields
    expect(typeof result.usage.model).toBe('string');
    expect(typeof result.usage.inputTokens).toBe('number');
    expect(typeof result.usage.outputTokens).toBe('number');
    expect(typeof result.usage.costUsd).toBe('number');
    expect(typeof result.usage.durationMs).toBe('number');
  });

  it('uses fast model tier when specified', async () => {
    const rule = makeRule();
    const client = makeMockClient();
    (client.prompt as ReturnType<typeof vi.fn>).mockResolvedValue(makeAIResult());

    await generateDocumentation(rule, { client, modelTier: 'fast' });

    expect(client.prompt).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      { model: 'fast' },
    );
  });
});
