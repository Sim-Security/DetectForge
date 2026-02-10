/**
 * Shared CLI option helpers for DetectForge commands.
 *
 * Provides reusable option registration functions, path resolution
 * utilities, and format parsing helpers used across all commands.
 */

import { existsSync, mkdirSync, statSync } from 'fs';
import { resolve } from 'path';
import type { Command } from 'commander';
import chalk from 'chalk';

// ---------------------------------------------------------------------------
// Option registration helpers
// ---------------------------------------------------------------------------

/**
 * Add the --model option to a command.
 * Accepts 'fast', 'standard', or 'quality' with default 'standard'.
 */
export function addModelOption(cmd: Command): Command {
  return cmd.option(
    '--model <tier>',
    'AI model tier: fast, standard, quality',
    'standard',
  );
}

/**
 * Add the -o/--output option to a command.
 */
export function addOutputOption(cmd: Command, defaultValue = './rules'): Command {
  return cmd.option(
    '-o, --output <dir>',
    'Output directory for generated files',
    defaultValue,
  );
}

/**
 * Add the --verbose flag to a command.
 */
export function addVerboseOption(cmd: Command): Command {
  return cmd.option('--verbose', 'Verbose output');
}

// ---------------------------------------------------------------------------
// Path resolution utilities
// ---------------------------------------------------------------------------

/**
 * Resolve and validate that an input file/directory exists.
 * Prints a chalk-colored error and exits if not found.
 */
export function resolveInputPath(input: string): string {
  const resolved = resolve(input);

  if (!existsSync(resolved)) {
    console.error(
      chalk.red(`Error: Input path does not exist: ${resolved}`),
    );
    process.exit(1);
  }

  return resolved;
}

/**
 * Resolve an output directory path, creating it (and parents) if missing.
 */
export function resolveOutputDir(dir: string): string {
  const resolved = resolve(dir);

  if (!existsSync(resolved)) {
    try {
      mkdirSync(resolved, { recursive: true });
    } catch (err) {
      console.error(
        chalk.red(`Error: Could not create output directory: ${resolved}`),
      );
      console.error(
        chalk.red(`  ${err instanceof Error ? err.message : String(err)}`),
      );
      process.exit(1);
    }
  } else {
    const stat = statSync(resolved);
    if (!stat.isDirectory()) {
      console.error(
        chalk.red(`Error: Output path exists but is not a directory: ${resolved}`),
      );
      process.exit(1);
    }
  }

  return resolved;
}

// ---------------------------------------------------------------------------
// Format parsing
// ---------------------------------------------------------------------------

/** Valid rule output formats. */
export type RuleFormatOption = 'sigma' | 'yara' | 'suricata';

const VALID_FORMATS = new Set<RuleFormatOption>(['sigma', 'yara', 'suricata']);

/**
 * Parse a comma-separated format string into an array of validated formats.
 *
 * @example parseFormats('sigma,yara') => ['sigma', 'yara']
 */
export function parseFormats(formatStr: string): RuleFormatOption[] {
  const raw = formatStr
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const formats: RuleFormatOption[] = [];

  for (const f of raw) {
    if (VALID_FORMATS.has(f as RuleFormatOption)) {
      formats.push(f as RuleFormatOption);
    } else {
      console.error(
        chalk.yellow(`Warning: Unknown format "${f}" — skipping. Valid formats: sigma, yara, suricata`),
      );
    }
  }

  if (formats.length === 0) {
    console.error(
      chalk.red('Error: No valid formats specified. Use: sigma, yara, suricata'),
    );
    process.exit(1);
  }

  return formats;
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

/**
 * Print a user-friendly error message with optional details.
 */
export function printError(message: string, detail?: string): void {
  console.error(chalk.red(`\nError: ${message}`));
  if (detail) {
    console.error(chalk.gray(`  ${detail}`));
  }
  console.error('');
}

/**
 * Print an informational message.
 */
export function printInfo(message: string): void {
  console.log(chalk.cyan(`  ${message}`));
}

/**
 * Print a success message.
 */
export function printSuccess(message: string): void {
  console.log(chalk.green(`  ${message}`));
}

/**
 * Print a warning message.
 */
export function printWarning(message: string): void {
  console.log(chalk.yellow(`  ${message}`));
}
