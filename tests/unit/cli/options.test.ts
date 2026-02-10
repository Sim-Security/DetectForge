/**
 * Unit tests for shared CLI options.
 *
 * Tests: resolveInputPath, resolveOutputDir, parseFormats
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { existsSync, mkdirSync, statSync } from 'fs';
import { resolve } from 'path';
import {
  resolveInputPath,
  resolveOutputDir,
  parseFormats,
} from '@/cli/options.js';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('fs', async () => {
  const actual = await vi.importActual('fs');
  return {
    ...actual,
    existsSync: vi.fn(),
    mkdirSync: vi.fn(),
    statSync: vi.fn(),
  };
});

// Mock chalk so we do not get ANSI codes in error assertions and so the
// module loads correctly in tests.
vi.mock('chalk', () => ({
  default: {
    red: (s: string) => s,
    green: (s: string) => s,
    yellow: (s: string) => s,
    cyan: (s: string) => s,
    gray: (s: string) => s,
    bold: {
      cyan: (s: string) => s,
    },
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Mock process.exit so it throws instead of terminating the test runner.
 * We use this to assert that certain functions call process.exit(1).
 */
function mockProcessExit(): void {
  vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
    throw new Error(`process.exit(${code})`);
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe('resolveInputPath', () => {
  it('returns resolved absolute path for a valid file', () => {
    (existsSync as ReturnType<typeof vi.fn>).mockReturnValue(true);

    const result = resolveInputPath('reports/apt29.pdf');
    expect(result).toBe(resolve('reports/apt29.pdf'));
  });

  it('throws (exits) for a non-existent file', () => {
    (existsSync as ReturnType<typeof vi.fn>).mockReturnValue(false);
    mockProcessExit();
    vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => resolveInputPath('nonexistent-file.pdf')).toThrow('process.exit(1)');
  });
});

describe('resolveOutputDir', () => {
  it('creates directory if it does not exist', () => {
    (existsSync as ReturnType<typeof vi.fn>).mockReturnValue(false);

    resolveOutputDir('/tmp/test-output');

    expect(mkdirSync).toHaveBeenCalledWith(resolve('/tmp/test-output'), { recursive: true });
  });

  it('returns resolved path when directory already exists', () => {
    (existsSync as ReturnType<typeof vi.fn>).mockReturnValue(true);
    (statSync as ReturnType<typeof vi.fn>).mockReturnValue({ isDirectory: () => true });

    const result = resolveOutputDir('/tmp/existing-output');
    expect(result).toBe(resolve('/tmp/existing-output'));
  });

  it('exits when the path exists but is not a directory', () => {
    (existsSync as ReturnType<typeof vi.fn>).mockReturnValue(true);
    (statSync as ReturnType<typeof vi.fn>).mockReturnValue({ isDirectory: () => false });
    mockProcessExit();
    vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => resolveOutputDir('/tmp/some-file')).toThrow('process.exit(1)');
  });
});

describe('parseFormats', () => {
  it('parses "sigma,yara,suricata" into an array of three formats', () => {
    const result = parseFormats('sigma,yara,suricata');
    expect(result).toEqual(['sigma', 'yara', 'suricata']);
  });

  it('handles a single format "sigma"', () => {
    const result = parseFormats('sigma');
    expect(result).toEqual(['sigma']);
  });

  it('trims whitespace around format names', () => {
    const result = parseFormats('  sigma , yara  , suricata ');
    expect(result).toEqual(['sigma', 'yara', 'suricata']);
  });

  it('exits for an input with no valid formats', () => {
    mockProcessExit();
    vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => parseFormats('invalid,bogus')).toThrow('process.exit(1)');
  });

  it('filters out invalid format names while keeping valid ones', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const result = parseFormats('sigma,invalidformat,yara');
    expect(result).toEqual(['sigma', 'yara']);
  });

  it('normalizes format names to lowercase', () => {
    const result = parseFormats('Sigma,YARA,Suricata');
    expect(result).toEqual(['sigma', 'yara', 'suricata']);
  });

  it('handles empty segments from trailing commas', () => {
    const result = parseFormats('sigma,,yara,');
    expect(result).toEqual(['sigma', 'yara']);
  });
});
