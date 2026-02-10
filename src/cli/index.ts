#!/usr/bin/env node

/**
 * DetectForge CLI — AI-Powered Detection Rule Generation
 *
 * Usage:
 *   detectforge generate --input report.pdf --output ./rules/
 *   detectforge extract --input report.pdf --output extracted.json
 *   detectforge validate --input ./rules/ --format sigma
 *   detectforge benchmark --input ./rules/
 *   detectforge coverage --input ./rules/ --navigator-layer
 */

import 'dotenv/config';

import { Command } from 'commander';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import chalk from 'chalk';

import { registerGenerateCommand } from './commands/generate.js';
import { registerExtractCommand } from './commands/extract.js';
import { registerValidateCommand } from './commands/validate.js';
import { registerBenchmarkCommand } from './commands/benchmark.js';
import { registerCoverageCommand } from './commands/coverage.js';

const pkg = JSON.parse(
  readFileSync(resolve(import.meta.dirname, '../../package.json'), 'utf-8')
);

const program = new Command();

program
  .name('detectforge')
  .description('AI-Powered Detection Rule Generation from Threat Intelligence Reports')
  .version(pkg.version);

// Register all commands
registerGenerateCommand(program);
registerExtractCommand(program);
registerValidateCommand(program);
registerBenchmarkCommand(program);
registerCoverageCommand(program);

// Global error handling
program.exitOverride();

async function main(): Promise<void> {
  try {
    await program.parseAsync();
  } catch (err) {
    // CommanderError for help/version is expected — don't treat as error
    if (err instanceof Error && 'code' in err) {
      const code = (err as { code: string }).code;
      if (code === 'commander.helpDisplayed' || code === 'commander.version') {
        return;
      }
    }

    console.error('');
    console.error(chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
    console.error('');
    console.error(chalk.gray('Run "detectforge --help" for usage information.'));
    console.error('');
    process.exit(1);
  }
}

main();
