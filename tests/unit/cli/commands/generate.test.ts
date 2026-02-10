/**
 * Unit tests for the generate command.
 *
 * Tests: registerGenerateCommand (smoke tests only).
 *
 * The generate command is heavily integration-oriented, so these tests
 * focus on verifying the module exports and that the command can be
 * registered without errors. Full pipeline tests belong in integration.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Command } from 'commander';

// ---------------------------------------------------------------------------
// Mocks — all heavy dependencies
// ---------------------------------------------------------------------------

vi.mock('@/ingestion/index.js', () => ({
  normalizeReport: vi.fn(),
}));

vi.mock('@/extraction/index.js', () => ({
  extractIocs: vi.fn().mockReturnValue([]),
  extractTtps: vi.fn().mockResolvedValue({ ttps: [] }),
  mapToAttack: vi.fn().mockResolvedValue({ mappings: [] }),
}));

vi.mock('@/generation/index.js', () => ({
  generateSigmaRules: vi.fn().mockResolvedValue({ rules: [] }),
  generateYaraRules: vi.fn().mockResolvedValue({ rules: [] }),
  generateSuricataRules: vi.fn().mockResolvedValue({ rules: [] }),
  validateSigmaRule: vi.fn().mockReturnValue({ valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] }),
  validateYaraRule: vi.fn().mockReturnValue({ valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] }),
  validateSuricataRule: vi.fn().mockReturnValue({ valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] }),
}));

vi.mock('@/generation/documentation.js', () => ({
  generateDocumentation: vi.fn().mockResolvedValue({ documentation: {} }),
}));

vi.mock('@/generation/false-positive-analyzer.js', () => ({
  analyzeFalsePositives: vi.fn().mockResolvedValue({ falsePositives: [] }),
}));

vi.mock('@/generation/coverage-gap-analyzer.js', () => ({
  analyzeCoverageGaps: vi.fn().mockResolvedValue({
    overallCoverage: { coveredTechniques: 0, totalTechniques: 0 },
    recommendations: [],
  }),
}));

vi.mock('@/testing/sigma-tester.js', () => ({
  evaluateSigmaRuleSuite: vi.fn().mockReturnValue({ tpRate: 0, fpRate: 0 }),
}));

vi.mock('@/testing/quality-scorer.js', () => ({
  scoreRuleQuality: vi.fn(),
  generateQualityReport: vi.fn(),
}));

vi.mock('@/ai/client.js', () => ({
  AIClient: vi.fn().mockImplementation(() => ({
    prompt: vi.fn(),
    infer: vi.fn(),
    getUsageLog: vi.fn().mockReturnValue([]),
    getCostSummary: vi.fn().mockReturnValue({
      totalCostUsd: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      totalTokens: 0,
      byOperation: {},
      byModel: {},
    }),
    fromEnv: vi.fn(),
  })),
}));

vi.mock('chalk', () => ({
  default: {
    red: (s: string) => s,
    green: (s: string) => s,
    yellow: (s: string) => s,
    cyan: (s: string) => s,
    gray: (s: string) => s,
    bold: { cyan: (s: string) => s },
  },
}));

vi.mock('ora', () => ({
  default: () => ({
    start: vi.fn().mockReturnThis(),
    succeed: vi.fn().mockReturnThis(),
    fail: vi.fn().mockReturnThis(),
    info: vi.fn().mockReturnThis(),
  }),
}));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

describe('registerGenerateCommand', () => {
  it('exports a registerGenerateCommand function', async () => {
    const mod = await import('@/cli/commands/generate.js');
    expect(mod.registerGenerateCommand).toBeDefined();
    expect(typeof mod.registerGenerateCommand).toBe('function');
  });

  it('registers the generate command on a Commander program without error', async () => {
    const mod = await import('@/cli/commands/generate.js');
    const program = new Command();

    // Should not throw
    expect(() => mod.registerGenerateCommand(program)).not.toThrow();

    // The program should now have a "generate" subcommand
    const commands = program.commands.map(c => c.name());
    expect(commands).toContain('generate');
  });

  it('registered command has expected options', async () => {
    const mod = await import('@/cli/commands/generate.js');
    const program = new Command();
    mod.registerGenerateCommand(program);

    const generateCmd = program.commands.find(c => c.name() === 'generate');
    expect(generateCmd).toBeDefined();

    // Check that key options are registered
    const optionNames = generateCmd!.options.map(o => o.long);
    expect(optionNames).toContain('--input');
    expect(optionNames).toContain('--output');
    expect(optionNames).toContain('--format');
    expect(optionNames).toContain('--model');
  });
});
