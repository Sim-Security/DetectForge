/**
 * Coverage command — ATT&CK technique coverage analysis.
 *
 * Reads detection rules from an input path, calculates coverage metrics
 * against MITRE ATT&CK techniques, optionally exports an ATT&CK
 * Navigator layer, and displays a coverage summary in the terminal.
 */

import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync, existsSync } from 'fs';
import { resolve, extname, join, dirname } from 'path';
import type { Command } from 'commander';
import chalk from 'chalk';
import YAML from 'yaml';

import {
  calculateCoverageMetrics,
  exportNavigatorLayer,
} from '@/testing/coverage-metrics.js';
import type { GeneratedRule, SigmaRule, ValidationResult } from '@/types/index.js';
import type { AttackMappingResult } from '@/types/index.js';
import {
  resolveInputPath,
  printInfo,
  printSuccess,
  printWarning,
} from '../options.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CoverageOptions {
  input: string;
  output: string;
  navigatorLayer?: boolean;
}

// ---------------------------------------------------------------------------
// Command Registration
// ---------------------------------------------------------------------------

export function registerCoverageCommand(program: Command): void {
  program
    .command('coverage')
    .description('Analyze ATT&CK technique coverage of detection rules')
    .requiredOption('-i, --input <path>', 'Path to rules')
    .option('-o, --output <file>', 'Output coverage report', 'coverage.json')
    .option('--navigator-layer', 'Export ATT&CK Navigator layer JSON')
    .action(async (options: CoverageOptions) => {
      await runCoverage(options);
    });
}

// ---------------------------------------------------------------------------
// Main Logic
// ---------------------------------------------------------------------------

async function runCoverage(options: CoverageOptions): Promise<void> {
  console.log('');
  console.log(chalk.bold.cyan('  DetectForge — ATT&CK Coverage Analysis'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));
  console.log('');

  const inputPath = resolveInputPath(options.input);
  const outputPath = resolve(options.output);

  printInfo(`Input:  ${inputPath}`);
  printInfo(`Output: ${outputPath}`);
  console.log('');

  // --- Load rules and mappings ---
  const { rules, mappings } = loadRulesAndMappings(inputPath);

  if (rules.length === 0) {
    printWarning('No rules found at the specified path.');
    printInfo('Supported: DetectForge output directory, summary.json, or individual rule files');
    process.exit(1);
  }

  printInfo(`Loaded ${rules.length} rules with ${mappings.length} ATT&CK mappings`);
  console.log('');

  // --- Calculate coverage metrics ---
  const metrics = calculateCoverageMetrics(rules, mappings);

  // --- Display coverage summary ---
  console.log(chalk.bold('  Coverage Summary'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));

  const coveragePct = metrics.coveragePercentage;
  const coverageColor = coveragePct >= 60 ? chalk.green : coveragePct >= 30 ? chalk.yellow : chalk.red;

  console.log(`  ${chalk.cyan('Total techniques:')}    ${metrics.totalTechniques}`);
  console.log(`  ${chalk.cyan('Covered techniques:')} ${metrics.coveredTechniques}`);
  console.log(
    `  ${chalk.cyan('Coverage:')}           ${coverageColor(`${coveragePct.toFixed(1)}%`)}`,
  );
  console.log('');

  // Tactic breakdown
  console.log(chalk.bold('  Per-Tactic Coverage'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));

  const tacticEntries = Object.entries(metrics.tacticBreakdown).sort(
    (a, b) => b[1].percentage - a[1].percentage,
  );

  for (const [tactic, data] of tacticEntries) {
    const pct = data.percentage;
    const bar = renderCoverageBar(pct);
    const pctColor = pct >= 60 ? chalk.green : pct >= 30 ? chalk.yellow : chalk.red;

    console.log(
      `  ${tactic.padEnd(25)} ${bar} ${pctColor(`${pct.toFixed(0).padStart(3)}%`)} (${data.covered}/${data.total})`,
    );
  }
  console.log('');

  // Covered techniques
  if (metrics.coveredTechniqueIds.length > 0) {
    console.log(chalk.bold('  Covered Techniques'));
    console.log(chalk.gray('  ─────────────────────────────────────────'));
    const techniqueList = metrics.coveredTechniqueIds.slice(0, 20);
    for (const techId of techniqueList) {
      console.log(`    ${chalk.green('+')} ${techId}`);
    }
    if (metrics.coveredTechniqueIds.length > 20) {
      printInfo(`... and ${metrics.coveredTechniqueIds.length - 20} more`);
    }
    console.log('');
  }

  // Uncovered techniques (top 10)
  if (metrics.uncoveredTechniqueIds.length > 0) {
    console.log(chalk.bold('  Uncovered Techniques (top gaps)'));
    console.log(chalk.gray('  ─────────────────────────────────────────'));
    const gapList = metrics.uncoveredTechniqueIds.slice(0, 10);
    for (const techId of gapList) {
      console.log(`    ${chalk.red('-')} ${techId}`);
    }
    if (metrics.uncoveredTechniqueIds.length > 10) {
      printInfo(`... and ${metrics.uncoveredTechniqueIds.length - 10} more gaps`);
    }
    console.log('');
  }

  // --- Write coverage report ---
  try {
    const outDir = dirname(outputPath);
    if (!existsSync(outDir)) {
      mkdirSync(outDir, { recursive: true });
    }

    const reportData = {
      generatedAt: new Date().toISOString(),
      totalTechniques: metrics.totalTechniques,
      coveredTechniques: metrics.coveredTechniques,
      coveragePercentage: metrics.coveragePercentage,
      tacticBreakdown: metrics.tacticBreakdown,
      coveredTechniqueIds: metrics.coveredTechniqueIds,
      uncoveredTechniqueIds: metrics.uncoveredTechniqueIds,
    };

    writeFileSync(outputPath, JSON.stringify(reportData, null, 2), 'utf-8');
    printSuccess(`Coverage report written to ${outputPath}`);
  } catch (err) {
    printWarning(`Failed to write coverage report: ${err instanceof Error ? err.message : String(err)}`);
  }

  // --- Optional: Export Navigator layer ---
  if (options.navigatorLayer) {
    const layerPath = outputPath.replace(/\.json$/, '-navigator.json');
    try {
      const layerJson = exportNavigatorLayer(metrics);

      const layerDir = dirname(layerPath);
      if (!existsSync(layerDir)) {
        mkdirSync(layerDir, { recursive: true });
      }

      writeFileSync(layerPath, layerJson, 'utf-8');
      printSuccess(`ATT&CK Navigator layer written to ${layerPath}`);
      printInfo('Open this file at https://mitre-attack.github.io/attack-navigator/');
    } catch (err) {
      printWarning(`Failed to write Navigator layer: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  console.log('');
}

// ---------------------------------------------------------------------------
// Rule & Mapping Loading
// ---------------------------------------------------------------------------

interface LoadResult {
  rules: GeneratedRule[];
  mappings: AttackMappingResult[];
}

/**
 * Load rules and ATT&CK mappings from the input path.
 */
function loadRulesAndMappings(inputPath: string): LoadResult {
  const stat = statSync(inputPath);
  const rules: GeneratedRule[] = [];
  const mappings: AttackMappingResult[] = [];

  if (stat.isFile()) {
    // Try loading as a summary.json or extracted.json
    loadFromJsonFile(inputPath, rules, mappings);
  } else if (stat.isDirectory()) {
    // Check for DetectForge summary.json
    const summaryPath = join(inputPath, 'reports', 'summary.json');
    const summaryStat = safeStatSync(summaryPath);

    if (summaryStat?.isFile()) {
      loadFromJsonFile(summaryPath, rules, mappings);
    }

    // Also scan for individual rule files
    scanDirectoryForRules(inputPath, rules);
  }

  // Build mappings from rule data if we don't have explicit mappings
  if (mappings.length === 0) {
    for (const rule of rules) {
      if (rule.attackTechniqueId) {
        mappings.push({
          techniqueId: rule.attackTechniqueId,
          techniqueName: rule.attackTechniqueId,
          tactic: rule.attackTactic || 'unknown',
          confidence: rule.confidence,
          reasoning: 'Derived from generated rule',
          sourceTtp: {
            description: '',
            tools: [],
            targetPlatforms: [],
            artifacts: [],
            detectionOpportunities: [],
            confidence: rule.confidence,
          },
          suggestedRuleFormats: [rule.format],
          validated: false,
        });
      }
    }
  }

  return { rules, mappings };
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
 * Load rules/mappings from a JSON file.
 */
function loadFromJsonFile(
  filePath: string,
  rules: GeneratedRule[],
  mappings: AttackMappingResult[],
): void {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const data = JSON.parse(content);

    // Handle DetectForge summary.json format
    if (Array.isArray(data.rules)) {
      for (const r of data.rules) {
        rules.push(buildMinimalRule(r));
      }
    }

    // Handle extraction result format
    if (Array.isArray(data.attackMappings)) {
      for (const m of data.attackMappings) {
        mappings.push(m as AttackMappingResult);
      }
    }
  } catch {
    // Not valid JSON, ignore
  }
}

/**
 * Recursively scan a directory for rule files and build GeneratedRule objects.
 */
function scanDirectoryForRules(dirPath: string, rules: GeneratedRule[]): void {
  let entries;
  try {
    entries = readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);

    if (entry.isDirectory()) {
      scanDirectoryForRules(fullPath, rules);
    } else if (entry.isFile()) {
      const ext = extname(entry.name).toLowerCase();
      try {
        const content = readFileSync(fullPath, 'utf-8');

        if (ext === '.yml' || ext === '.yaml') {
          rules.push(buildSigmaGeneratedRule(content, entry.name));
        } else if (ext === '.yar' || ext === '.yara') {
          rules.push(buildYaraGeneratedRule(content, entry.name));
        } else if (ext === '.rules') {
          const lines = content.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
          for (const line of lines) {
            rules.push(buildSuricataGeneratedRule(line));
          }
        }
      } catch {
        // Skip files that can't be read
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Rule Builders
// ---------------------------------------------------------------------------

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
    attackTactic: (data.attackTactic as string) || undefined,
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

    const techniqueTag = rule.tags.find((t) => t.startsWith('attack.t'));
    const tacticTag = rule.tags.find(
      (t) => t.startsWith('attack.') && !t.startsWith('attack.t') && !t.startsWith('attack.g'),
    );

    return {
      format: 'sigma',
      sigma: rule,
      sourceReportId: 'file-import',
      attackTechniqueId: techniqueTag?.replace('attack.', '').toUpperCase(),
      attackTactic: tacticTag?.replace('attack.', ''),
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
  const attackMatch = content.match(/mitre_attack\s*=\s*"([^"]+)"/);

  return {
    format: 'yara',
    yara: {
      name: nameMatch?.[1] || filename,
      tags: [],
      meta: { description: '', author: '', date: '', reference: '', mitre_attack: attackMatch?.[1] || '' },
      strings: [],
      condition: '',
      raw: content,
    },
    sourceReportId: 'file-import',
    attackTechniqueId: attackMatch?.[1],
    confidence: 'medium',
    validation: { valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] },
  };
}

function buildSuricataGeneratedRule(rawLine: string): GeneratedRule {
  // Try to extract SID and any ATT&CK reference from the rule
  const sidMatch = rawLine.match(/sid\s*:\s*(\d+)/);
  const attackMatch = rawLine.match(/mitre_attack\s+(T\d{4}(?:\.\d{3})?)/i);

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
      sid: sidMatch ? parseInt(sidMatch[1], 10) : 0,
      rev: 1,
      raw: rawLine,
    },
    sourceReportId: 'file-import',
    attackTechniqueId: attackMatch?.[1],
    confidence: 'medium',
    validation: { valid: true, syntaxValid: true, schemaValid: true, errors: [], warnings: [] },
  };
}

// ---------------------------------------------------------------------------
// Display Helpers
// ---------------------------------------------------------------------------

/**
 * Render a simple coverage bar (20 chars wide).
 */
function renderCoverageBar(percentage: number): string {
  const width = 20;
  const filled = Math.round((percentage / 100) * width);
  const empty = width - filled;
  const color = percentage >= 60 ? chalk.green : percentage >= 30 ? chalk.yellow : chalk.red;
  return color('\u2588'.repeat(filled)) + chalk.gray('\u2591'.repeat(empty));
}
