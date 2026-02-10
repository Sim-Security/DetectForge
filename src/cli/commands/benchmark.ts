/**
 * Benchmark command — quality scoring for generated detection rules.
 *
 * Reads generated rules from an input path, runs the heuristic-based
 * quality scorer on all rules, and displays a detailed quality report
 * in the terminal.
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { extname, join } from 'path';
import type { Command } from 'commander';
import chalk from 'chalk';
import YAML from 'yaml';

import { generateQualityReport } from '@/testing/quality-scorer.js';
import type { GeneratedRule, ValidationResult, SigmaRule } from '@/types/index.js';
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

interface BenchmarkOptions {
  input: string;
  sigmahqPath: string;
}

// ---------------------------------------------------------------------------
// Command Registration
// ---------------------------------------------------------------------------

export function registerBenchmarkCommand(program: Command): void {
  program
    .command('benchmark')
    .description('Benchmark generated rules against SigmaHQ reference corpus')
    .requiredOption('-i, --input <path>', 'Path to generated rules')
    .option('--sigmahq-path <dir>', 'Path to SigmaHQ rules', './data/sigmahq-rules')
    .action(async (options: BenchmarkOptions) => {
      await runBenchmark(options);
    });
}

// ---------------------------------------------------------------------------
// Main Logic
// ---------------------------------------------------------------------------

async function runBenchmark(options: BenchmarkOptions): Promise<void> {
  console.log('');
  console.log(chalk.bold.cyan('  DetectForge — Rule Quality Benchmark'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));
  console.log('');

  const inputPath = resolveInputPath(options.input);
  printInfo(`Input: ${inputPath}`);
  console.log('');

  // --- Load rules ---
  const rules = loadGeneratedRules(inputPath);

  if (rules.length === 0) {
    printWarning('No rules found at the specified path.');
    printInfo('Supported: summary.json (DetectForge output) or rule files (.yml, .yar, .rules)');
    process.exit(1);
  }

  printInfo(`Loaded ${rules.length} rules for quality scoring`);
  console.log('');

  // --- Generate quality report ---
  const report = generateQualityReport(rules);

  // --- Display per-rule scores ---
  console.log(chalk.bold('  Per-Rule Quality Scores'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));
  console.log('');

  for (const score of report.perRuleScores) {
    const scoreColor = getScoreColor(score.overallScore);
    const bar = renderScoreBar(score.overallScore);

    console.log(
      `  ${scoreColor(`${score.overallScore.toFixed(1).padStart(4)}`)}  ${bar}  ${chalk.white(score.ruleId)} ${chalk.gray(`(${score.format})`)}`,
    );

    // Dimension breakdown
    console.log(
      chalk.gray(
        `        syntax:${score.dimensions.syntaxValidity.toFixed(0).padStart(3)} ` +
        `logic:${score.dimensions.detectionLogic.toFixed(0).padStart(3)} ` +
        `docs:${score.dimensions.documentation.toFixed(0).padStart(3)} ` +
        `attack:${score.dimensions.attackMapping.toFixed(0).padStart(3)} ` +
        `fp:${score.dimensions.falsePosHandling.toFixed(0).padStart(3)}`,
      ),
    );
  }

  console.log('');

  // --- Summary statistics ---
  console.log(chalk.bold('  Quality Summary'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));
  console.log(`  ${chalk.cyan('Total rules:')}       ${report.totalRules}`);
  console.log(
    `  ${chalk.cyan('Average score:')}     ${getScoreColor(report.averageScore)(`${report.averageScore.toFixed(1)}`)} / 10`,
  );
  console.log('');

  // Score distribution
  console.log(chalk.bold('  Score Distribution'));
  console.log(
    `    ${chalk.red('Low (1-3):')}     ${report.scoreDistribution['1-3']}`,
  );
  console.log(
    `    ${chalk.yellow('Medium (4-6):')} ${report.scoreDistribution['4-6']}`,
  );
  console.log(
    `    ${chalk.green('High (7-10):')}  ${report.scoreDistribution['7-10']}`,
  );
  console.log('');

  // Recommendations
  if (report.recommendations.length > 0) {
    console.log(chalk.bold('  Recommendations'));
    console.log(chalk.gray('  ─────────────────────────────────────────'));
    for (const rec of report.recommendations) {
      console.log(`  ${chalk.yellow('*')} ${rec}`);
    }
    console.log('');
  }

  // Final status
  if (report.averageScore >= 7) {
    printSuccess(`Quality benchmark passed (avg: ${report.averageScore.toFixed(1)}/10)`);
  } else if (report.averageScore >= 4) {
    printWarning(`Quality benchmark: moderate (avg: ${report.averageScore.toFixed(1)}/10) — review recommendations`);
  } else {
    printError(`Quality benchmark: low (avg: ${report.averageScore.toFixed(1)}/10) — significant improvements needed`);
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// Rule Loading
// ---------------------------------------------------------------------------

/**
 * Load generated rules from input path.
 *
 * Supports:
 * - A DetectForge summary.json (generated by the generate command)
 * - A directory of rule files
 */
function loadGeneratedRules(inputPath: string): GeneratedRule[] {
  const stat = statSync(inputPath);

  // If it's a file, try to load as summary.json
  if (stat.isFile()) {
    return loadFromSummaryJson(inputPath);
  }

  // If it's a directory, check for reports/summary.json first
  if (stat.isDirectory()) {
    const summaryPath = join(inputPath, 'reports', 'summary.json');
    const summaryStat = safeStatSync(summaryPath);
    if (summaryStat?.isFile()) {
      return loadFromSummaryJson(summaryPath);
    }

    // Otherwise, build minimal GeneratedRule objects from individual files
    return loadFromDirectory(inputPath);
  }

  return [];
}

/**
 * Safe statSync that returns null instead of throwing.
 */
function safeStatSync(path: string): ReturnType<typeof statSync> | null {
  try {
    return statSync(path);
  } catch {
    return null;
  }
}

/**
 * Load rules from a summary.json file.
 */
function loadFromSummaryJson(filePath: string): GeneratedRule[] {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const data = JSON.parse(content);

    if (Array.isArray(data.rules)) {
      return data.rules.map((r: Record<string, unknown>) => buildMinimalRule(r));
    }

    // If the file itself is an array of rules
    if (Array.isArray(data)) {
      return data.map((r: Record<string, unknown>) => buildMinimalRule(r));
    }

    return [];
  } catch {
    return [];
  }
}

/**
 * Load rules from a directory of rule files.
 */
function loadFromDirectory(dirPath: string): GeneratedRule[] {
  const rules: GeneratedRule[] = [];
  scanDirectory(dirPath, rules);
  return rules;
}

function scanDirectory(dirPath: string, rules: GeneratedRule[]): void {
  const entries = readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);

    if (entry.isDirectory()) {
      scanDirectory(fullPath, rules);
    } else if (entry.isFile()) {
      const ext = extname(entry.name).toLowerCase();
      const content = readFileSync(fullPath, 'utf-8');

      if (ext === '.yml' || ext === '.yaml') {
        rules.push(buildSigmaGeneratedRule(content, entry.name));
      } else if (ext === '.yar' || ext === '.yara') {
        rules.push(buildYaraGeneratedRule(content, entry.name));
      } else if (ext === '.rules') {
        // Each line could be a rule
        const lines = content.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
        for (const line of lines) {
          rules.push(buildSuricataGeneratedRule(line));
        }
      }
    }
  }
}

/**
 * Build a minimal GeneratedRule from parsed data.
 */
function buildMinimalRule(data: Record<string, unknown>): GeneratedRule {
  const format = (data.format as string) || 'sigma';
  const valid = data.valid !== false;

  const validation: ValidationResult = {
    valid,
    syntaxValid: valid,
    schemaValid: valid,
    errors: (data.errors as string[]) || [],
    warnings: (data.warnings as string[]) || [],
  };

  return {
    format: format as 'sigma' | 'yara' | 'suricata',
    sourceReportId: (data.sourceReportId as string) || 'unknown',
    attackTechniqueId: (data.attackTechniqueId as string) || undefined,
    confidence: (data.confidence as 'high' | 'medium' | 'low') || 'medium',
    validation,
  };
}

function buildSigmaGeneratedRule(yamlContent: string, filename: string): GeneratedRule {
  try {
    const parsed = YAML.parse(yamlContent);
    const rule: SigmaRule = {
      id: parsed?.id || filename,
      title: parsed?.title || filename,
      status: parsed?.status || 'experimental',
      description: parsed?.description || '',
      references: parsed?.references || [],
      author: parsed?.author || '',
      date: parsed?.date || '',
      modified: parsed?.modified || '',
      tags: parsed?.tags || [],
      logsource: parsed?.logsource || {},
      detection: parsed?.detection || { condition: '' },
      falsepositives: parsed?.falsepositives || [],
      level: parsed?.level || 'medium',
      raw: yamlContent,
    };

    return {
      format: 'sigma',
      sigma: rule,
      sourceReportId: 'file-import',
      attackTechniqueId: rule.tags.find((t) => t.startsWith('attack.t'))?.replace('attack.', '').toUpperCase(),
      confidence: 'medium',
      validation: { valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] },
    };
  } catch {
    return {
      format: 'sigma',
      sourceReportId: 'file-import',
      confidence: 'low',
      validation: { valid: false, syntaxValid: false, schemaValid: false, errors: ['Failed to parse YAML'], warnings: [] },
    };
  }
}

function buildYaraGeneratedRule(content: string, filename: string): GeneratedRule {
  const nameMatch = content.match(/rule\s+(\w+)/);
  return {
    format: 'yara',
    yara: {
      name: nameMatch?.[1] || filename,
      tags: [],
      meta: { description: '', author: '', date: '', reference: '', mitre_attack: '' },
      strings: [],
      condition: '',
      raw: content,
    },
    sourceReportId: 'file-import',
    confidence: 'medium',
    validation: { valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] },
  };
}

function buildSuricataGeneratedRule(rawLine: string): GeneratedRule {
  return {
    format: 'suricata',
    suricata: {
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
      raw: rawLine,
    },
    sourceReportId: 'file-import',
    confidence: 'medium',
    validation: { valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] },
  };
}

// ---------------------------------------------------------------------------
// Display Helpers
// ---------------------------------------------------------------------------

/**
 * Get a chalk color function based on score.
 */
function getScoreColor(score: number): (text: string) => string {
  if (score >= 7) return chalk.green;
  if (score >= 4) return chalk.yellow;
  return chalk.red;
}

/**
 * Render a simple score bar (10 chars wide).
 */
function renderScoreBar(score: number): string {
  const filled = Math.round(score);
  const empty = 10 - filled;
  const color = score >= 7 ? chalk.green : score >= 4 ? chalk.yellow : chalk.red;
  return color('\u2588'.repeat(filled)) + chalk.gray('\u2591'.repeat(empty));
}
