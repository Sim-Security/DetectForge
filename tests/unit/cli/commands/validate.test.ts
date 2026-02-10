/**
 * Unit tests for the validate command.
 *
 * Tests: registerValidateCommand (smoke tests).
 *
 * Note: The source file (src/cli/commands/validate.ts) is being written
 * concurrently by another agent. These tests target the expected interface.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Command } from 'commander';

// ---------------------------------------------------------------------------
// Mocks — validators and filesystem
// ---------------------------------------------------------------------------

vi.mock('@/generation/index.js', () => ({
  validateSigmaRule: vi.fn().mockReturnValue({
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
  }),
  validateSigmaYaml: vi.fn().mockReturnValue({
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
  }),
  validateYaraRule: vi.fn().mockReturnValue({
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
  }),
  validateYaraRaw: vi.fn().mockReturnValue({
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
  }),
  validateSuricataRule: vi.fn().mockReturnValue({
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
  }),
  validateSuricataRaw: vi.fn().mockReturnValue({
    valid: true,
    syntaxValid: true,
    schemaValid: true,
    errors: [],
    warnings: [],
  }),
  validateSuricataRuleSet: vi.fn().mockReturnValue([]),
}));

vi.mock('fs', async () => {
  const actual = await vi.importActual('fs');
  return {
    ...actual,
    existsSync: vi.fn().mockReturnValue(true),
    readFileSync: vi.fn().mockReturnValue('title: Test Rule'),
    readdirSync: vi.fn().mockReturnValue([]),
    statSync: vi.fn().mockReturnValue({ isDirectory: () => false, isFile: () => true }),
  };
});

vi.mock('chalk', () => ({
  default: {
    red: (s: string) => s,
    green: (s: string) => s,
    yellow: (s: string) => s,
    cyan: (s: string) => s,
    gray: (s: string) => s,
    bold: { cyan: (s: string) => s, green: (s: string) => s, red: (s: string) => s },
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

describe('registerValidateCommand', () => {
  it('exports a registerValidateCommand function', async () => {
    const mod = await import('@/cli/commands/validate.js');
    expect(mod.registerValidateCommand).toBeDefined();
    expect(typeof mod.registerValidateCommand).toBe('function');
  });

  it('registers the validate command on a Commander program without error', async () => {
    const mod = await import('@/cli/commands/validate.js');
    const program = new Command();

    expect(() => mod.registerValidateCommand(program)).not.toThrow();

    const commands = program.commands.map(c => c.name());
    expect(commands).toContain('validate');
  });

  it('registered command has expected options', async () => {
    const mod = await import('@/cli/commands/validate.js');
    const program = new Command();
    mod.registerValidateCommand(program);

    const validateCmd = program.commands.find(c => c.name() === 'validate');
    expect(validateCmd).toBeDefined();

    const optionNames = validateCmd!.options.map(o => o.long);
    expect(optionNames).toContain('--input');
    expect(optionNames).toContain('--format');
  });
});
