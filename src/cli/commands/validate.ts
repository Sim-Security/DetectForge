/**
 * Validate command — validate existing detection rules.
 *
 * Reads rule files from the input path (single file or directory),
 * auto-detects or uses the specified format, and runs the appropriate
 * validator. Prints color-coded pass/fail results and exits with
 * code 1 if any rules fail validation.
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { extname, join, basename } from 'path';
import type { Command } from 'commander';
import chalk from 'chalk';
import YAML from 'yaml';

import {
  validateSigmaRule,
  validateYaraRule,
  validateSuricataRule,
} from '@/generation/index.js';
import type { SigmaRule, YaraRule, SuricataRule, ValidationResult } from '@/types/index.js';
import {
  resolveInputPath,
  printError,
  printInfo,
  printSuccess,
  printWarning,
} from '../options.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type RuleFormat = 'sigma' | 'yara' | 'suricata';

interface ValidateOptions {
  input: string;
  format?: string;
}

interface FileValidationResult {
  file: string;
  format: RuleFormat;
  validation: ValidationResult;
}

// ---------------------------------------------------------------------------
// Command Registration
// ---------------------------------------------------------------------------

export function registerValidateCommand(program: Command): void {
  program
    .command('validate')
    .description('Validate existing detection rules')
    .requiredOption('-i, --input <path>', 'Path to rules file or directory')
    .option('-f, --format <format>', 'Rule format: sigma, yara, suricata')
    .action(async (options: ValidateOptions) => {
      await runValidate(options);
    });
}

// ---------------------------------------------------------------------------
// Main Logic
// ---------------------------------------------------------------------------

async function runValidate(options: ValidateOptions): Promise<void> {
  console.log('');
  console.log(chalk.bold.cyan('  DetectForge — Rule Validator'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));
  console.log('');

  const inputPath = resolveInputPath(options.input);
  const explicitFormat = options.format as RuleFormat | undefined;

  printInfo(`Input:  ${inputPath}`);
  printInfo(`Format: ${explicitFormat || 'auto-detect'}`);
  console.log('');

  // --- Collect files ---
  const files = collectRuleFiles(inputPath);

  if (files.length === 0) {
    printWarning('No rule files found at the specified path.');
    printInfo('Supported extensions: .yml, .yaml (Sigma), .yar, .yara (YARA), .rules (Suricata)');
    process.exit(1);
  }

  printInfo(`Found ${files.length} rule file(s) to validate`);
  console.log('');

  // --- Validate each file ---
  const results: FileValidationResult[] = [];
  let passCount = 0;
  let failCount = 0;

  for (const filePath of files) {
    const format = explicitFormat || detectFormatFromExtension(filePath);

    if (!format) {
      console.log(
        `  ${chalk.gray('SKIP')}  ${basename(filePath)} ${chalk.gray('(unknown format)')}`,
      );
      continue;
    }

    let content: string;
    try {
      content = readFileSync(filePath, 'utf-8');
    } catch (err) {
      console.log(
        `  ${chalk.red('ERR ')}  ${basename(filePath)} ${chalk.gray(`— Could not read file: ${err instanceof Error ? err.message : String(err)}`)}`,
      );
      failCount++;
      continue;
    }

    const validation = validateRuleContent(content, format);

    results.push({
      file: filePath,
      format,
      validation,
    });

    if (validation.valid) {
      passCount++;
      console.log(
        `  ${chalk.green('PASS')}  ${basename(filePath)} ${chalk.gray(`(${format})`)}`,
      );

      // Show warnings even for passing rules
      for (const warning of validation.warnings) {
        console.log(`        ${chalk.yellow(`warning: ${warning}`)}`);
      }
    } else {
      failCount++;
      console.log(
        `  ${chalk.red('FAIL')}  ${basename(filePath)} ${chalk.gray(`(${format})`)}`,
      );

      for (const error of validation.errors) {
        console.log(`        ${chalk.red(`error: ${error}`)}`);
      }
      for (const warning of validation.warnings) {
        console.log(`        ${chalk.yellow(`warning: ${warning}`)}`);
      }
    }
  }

  // --- Summary ---
  console.log('');
  console.log(chalk.bold('  Validation Summary'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));
  console.log(`  ${chalk.cyan('Total files:')}  ${results.length}`);
  console.log(`  ${chalk.green('Passed:')}       ${passCount}`);
  console.log(`  ${chalk.red('Failed:')}       ${failCount}`);

  if (results.length > 0) {
    console.log(
      `  ${chalk.cyan('Pass rate:')}    ${Math.round((passCount / results.length) * 100)}%`,
    );
  }

  console.log('');

  if (failCount > 0) {
    printError(`${failCount} rule(s) failed validation`);
    process.exit(1);
  } else {
    printSuccess('All rules passed validation');
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Collect rule files from a path (file or directory).
 */
function collectRuleFiles(inputPath: string): string[] {
  const stat = statSync(inputPath);

  if (stat.isFile()) {
    return [inputPath];
  }

  if (stat.isDirectory()) {
    const files: string[] = [];
    collectFilesRecursive(inputPath, files);
    return files.sort();
  }

  return [];
}

/**
 * Recursively collect rule files from a directory.
 */
function collectFilesRecursive(dirPath: string, files: string[]): void {
  const entries = readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);

    if (entry.isDirectory()) {
      collectFilesRecursive(fullPath, files);
    } else if (entry.isFile() && isRuleFile(entry.name)) {
      files.push(fullPath);
    }
  }
}

/**
 * Check if a file has a recognized rule extension.
 */
function isRuleFile(filename: string): boolean {
  const ext = extname(filename).toLowerCase();
  return ['.yml', '.yaml', '.yar', '.yara', '.rules'].includes(ext);
}

/**
 * Auto-detect rule format from file extension.
 */
function detectFormatFromExtension(filePath: string): RuleFormat | null {
  const ext = extname(filePath).toLowerCase();

  switch (ext) {
    case '.yml':
    case '.yaml':
      return 'sigma';
    case '.yar':
    case '.yara':
      return 'yara';
    case '.rules':
      return 'suricata';
    default:
      return null;
  }
}

/**
 * Validate rule content based on format.
 */
function validateRuleContent(content: string, format: RuleFormat): ValidationResult {
  switch (format) {
    case 'sigma':
      return validateSigmaContent(content);
    case 'yara':
      return validateYaraContent(content);
    case 'suricata':
      return validateSuricataContent(content);
  }
}

/**
 * Parse and validate Sigma YAML content.
 */
function validateSigmaContent(content: string): ValidationResult {
  try {
    const parsed = YAML.parse(content);
    if (!parsed || typeof parsed !== 'object') {
      return {
        valid: false,
        syntaxValid: false,
        schemaValid: false,
        errors: ['Failed to parse YAML: not a valid object'],
        warnings: [],
      };
    }

    // Build a minimal SigmaRule for the validator
    const rule: SigmaRule = {
      id: parsed.id || '',
      title: parsed.title || '',
      status: parsed.status || 'experimental',
      description: parsed.description || '',
      references: parsed.references || [],
      author: parsed.author || '',
      date: parsed.date || '',
      modified: parsed.modified || '',
      tags: parsed.tags || [],
      logsource: parsed.logsource || {},
      detection: parsed.detection || { condition: '' },
      falsepositives: parsed.falsepositives || [],
      level: parsed.level || 'medium',
      fields: parsed.fields,
      raw: content,
    };

    return validateSigmaRule(rule);
  } catch (err) {
    return {
      valid: false,
      syntaxValid: false,
      schemaValid: false,
      errors: [`YAML parse error: ${err instanceof Error ? err.message : String(err)}`],
      warnings: [],
    };
  }
}

/**
 * Parse and validate YARA content.
 */
function validateYaraContent(content: string): ValidationResult {
  // Build a minimal YaraRule from the raw content for validation
  const rule: YaraRule = {
    name: extractYaraRuleName(content) || 'unknown',
    tags: [],
    meta: {
      description: '',
      author: '',
      date: '',
      reference: '',
      mitre_attack: '',
    },
    strings: [],
    condition: '',
    raw: content,
  };

  return validateYaraRule(rule);
}

/**
 * Parse and validate Suricata content. Handles multiple rules per file.
 */
function validateSuricataContent(content: string): ValidationResult {
  const lines = content.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));

  if (lines.length === 0) {
    return {
      valid: false,
      syntaxValid: false,
      schemaValid: false,
      errors: ['No rules found in file'],
      warnings: [],
    };
  }

  const allErrors: string[] = [];
  const allWarnings: string[] = [];
  let allValid = true;

  for (let i = 0; i < lines.length; i++) {
    const rule: SuricataRule = {
      action: 'alert',
      protocol: 'tcp',
      sourceIp: 'any',
      sourcePort: 'any',
      direction: '->',
      destIp: 'any',
      destPort: 'any',
      options: [],
      sid: 0,
      rev: 1,
      raw: lines[i],
    };

    const result = validateSuricataRule(rule);
    if (!result.valid) {
      allValid = false;
      for (const error of result.errors) {
        allErrors.push(`Line ${i + 1}: ${error}`);
      }
    }
    for (const warning of result.warnings) {
      allWarnings.push(`Line ${i + 1}: ${warning}`);
    }
  }

  return {
    valid: allValid,
    syntaxValid: allValid,
    schemaValid: allValid,
    errors: allErrors,
    warnings: allWarnings,
  };
}

/**
 * Extract YARA rule name from raw content.
 */
function extractYaraRuleName(content: string): string | null {
  const match = content.match(/^\s*rule\s+(\w+)/m);
  return match ? match[1] : null;
}
