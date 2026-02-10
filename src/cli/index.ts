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

import { Command } from 'commander';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const pkg = JSON.parse(
  readFileSync(resolve(import.meta.dirname, '../../package.json'), 'utf-8')
);

const program = new Command();

program
  .name('detectforge')
  .description('AI-Powered Detection Rule Generation from Threat Intelligence Reports')
  .version(pkg.version);

// Generate command — main entry point
program
  .command('generate')
  .description('Generate detection rules from a threat intelligence report')
  .requiredOption('-i, --input <path>', 'Path to threat report (PDF, HTML, Markdown, text, STIX JSON)')
  .option('-o, --output <dir>', 'Output directory for generated rules', './rules')
  .option('-f, --format <formats>', 'Rule formats to generate (comma-separated: sigma,yara,suricata)', 'sigma,yara,suricata')
  .option('--sigma-only', 'Generate only Sigma rules')
  .option('--test', 'Run tests on generated rules')
  .option('--benchmark', 'Benchmark against SigmaHQ rules')
  .option('--verbose', 'Verbose output')
  .option('--model <tier>', 'AI model tier: fast, standard, quality', 'standard')
  .action(async (options) => {
    console.log('DetectForge: generate command');
    console.log('  Input:', options.input);
    console.log('  Output:', options.output);
    console.log('  Formats:', options.sigmaOnly ? 'sigma' : options.format);
    console.log('\n  [Not yet implemented — coming in Sprint 2-5]');
  });

// Extract command — IOC/TTP extraction only
program
  .command('extract')
  .description('Extract IOCs and TTPs from a threat report (no rule generation)')
  .requiredOption('-i, --input <path>', 'Path to threat report')
  .option('-o, --output <file>', 'Output JSON file', 'extracted.json')
  .option('--model <tier>', 'AI model tier: fast, standard, quality', 'standard')
  .action(async (options) => {
    console.log('DetectForge: extract command');
    console.log('  Input:', options.input);
    console.log('  Output:', options.output);
    console.log('\n  [Not yet implemented — coming in Sprint 3]');
  });

// Validate command
program
  .command('validate')
  .description('Validate existing detection rules')
  .requiredOption('-i, --input <path>', 'Path to rules file or directory')
  .option('-f, --format <format>', 'Rule format: sigma, yara, suricata')
  .action(async (options) => {
    console.log('DetectForge: validate command');
    console.log('  Input:', options.input);
    console.log('  Format:', options.format || 'auto-detect');
    console.log('\n  [Not yet implemented — coming in Sprint 4-5]');
  });

// Benchmark command
program
  .command('benchmark')
  .description('Benchmark generated rules against SigmaHQ reference corpus')
  .requiredOption('-i, --input <path>', 'Path to generated rules')
  .option('--sigmahq-path <dir>', 'Path to SigmaHQ rules', './data/sigmahq-rules')
  .action(async (options) => {
    console.log('DetectForge: benchmark command');
    console.log('  Input:', options.input);
    console.log('  SigmaHQ path:', options.sigmahqPath);
    console.log('\n  [Not yet implemented — coming in Sprint 7]');
  });

// Coverage command
program
  .command('coverage')
  .description('Analyze ATT&CK technique coverage of detection rules')
  .requiredOption('-i, --input <path>', 'Path to rules')
  .option('-o, --output <file>', 'Output coverage report', 'coverage.json')
  .option('--navigator-layer', 'Export ATT&CK Navigator layer JSON')
  .action(async (options) => {
    console.log('DetectForge: coverage command');
    console.log('  Input:', options.input);
    console.log('  Output:', options.output);
    console.log('\n  [Not yet implemented — coming in Sprint 7]');
  });

program.parse();
