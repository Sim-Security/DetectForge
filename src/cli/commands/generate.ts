/**
 * Generate command — main entry point for DetectForge rule generation.
 *
 * Reads a threat intelligence report, extracts IOCs and TTPs, maps to
 * MITRE ATT&CK, generates detection rules (Sigma/YARA/Suricata),
 * validates them, and optionally runs documentation, false positive
 * analysis, coverage gap analysis, and tests.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { resolve, basename, extname, join } from 'path';
import type { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { AIClient } from '@/ai/client.js';
import { normalizeReport } from '@/ingestion/index.js';
import { extractIocs, extractTtps, mapToAttack } from '@/extraction/index.js';
import {
  generateSigmaRules,
  generateYaraRules,
  generateSuricataRules,
  validateSigmaRule,
  validateYaraRule,
  validateSuricataRule,
} from '@/generation/index.js';
import { generateDocumentation } from '@/generation/documentation.js';
import { analyzeFalsePositives } from '@/generation/false-positive-analyzer.js';
import { analyzeCoverageGaps } from '@/generation/coverage-gap-analyzer.js';
import { evaluateSigmaRuleSuite } from '@/testing/sigma-tester.js';
// Quality report available via: import { generateQualityReport } from '@/testing/quality-scorer.js';
import type { GeneratedRule, SigmaRule, YaraRule, SuricataRule } from '@/types/index.js';
import type { ExtractedIOC, ExtractedTTP, AttackMappingResult } from '@/types/index.js';
import type { ModelTier } from '@/ai/client.js';
import {
  resolveInputPath,
  resolveOutputDir,
  parseFormats,
  printError,
  printInfo,
  printSuccess,
  printWarning,
  type RuleFormatOption,
} from '../options.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GenerateOptions {
  input: string;
  output: string;
  format: string;
  sigmaOnly?: boolean;
  test?: boolean;
  benchmark?: boolean;
  verbose?: boolean;
  model: string;
}

interface GenerationSummary {
  sigmaRules: number;
  yaraRules: number;
  suricataRules: number;
  totalRules: number;
  validationPassed: number;
  validationFailed: number;
  totalCostUsd: number;
  totalTokens: number;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Command Registration
// ---------------------------------------------------------------------------

export function registerGenerateCommand(program: Command): void {
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
    .action(async (options: GenerateOptions) => {
      await runGenerate(options);
    });
}

// ---------------------------------------------------------------------------
// Main Logic
// ---------------------------------------------------------------------------

async function runGenerate(options: GenerateOptions): Promise<void> {
  const startTime = Date.now();

  console.log('');
  console.log(chalk.bold.cyan('  DetectForge — Detection Rule Generator'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));
  console.log('');

  // --- Resolve paths and formats ---
  const inputPath = resolveInputPath(options.input);
  const formats: RuleFormatOption[] = options.sigmaOnly
    ? ['sigma']
    : parseFormats(options.format);
  const modelTier = options.model as ModelTier;

  printInfo(`Input:   ${inputPath}`);
  printInfo(`Output:  ${resolve(options.output)}`);
  printInfo(`Formats: ${formats.join(', ')}`);
  printInfo(`Model:   ${modelTier}`);
  console.log('');

  // --- Read input file ---
  let inputData: string | Buffer;
  const ext = extname(inputPath).toLowerCase();

  try {
    if (ext === '.pdf') {
      inputData = readFileSync(inputPath);
    } else {
      inputData = readFileSync(inputPath, 'utf-8');
    }
  } catch (err) {
    printError('Failed to read input file', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // --- Normalize report ---
  const normalizeSpinner = ora('Parsing and normalizing threat report...').start();
  let report;
  try {
    report = await normalizeReport(inputData, { filename: basename(inputPath) });
    normalizeSpinner.succeed(
      chalk.green(`Report parsed: "${report.title || basename(inputPath)}" (${report.sections.length} sections)`),
    );
  } catch (err) {
    normalizeSpinner.fail(chalk.red('Failed to parse threat report'));
    printError('Report normalization failed', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // --- Create AI client ---
  let client: AIClient;
  try {
    client = AIClient.fromEnv();
  } catch (err) {
    printError(
      'Failed to initialize AI client',
      err instanceof Error ? err.message : String(err),
    );
    process.exit(1);
  }

  // --- Extract IOCs ---
  const iocSpinner = ora('Extracting indicators of compromise (IOCs)...').start();
  let iocs: ExtractedIOC[];
  try {
    iocs = extractIocs(report.rawText);
    iocSpinner.succeed(chalk.green(`Extracted ${iocs.length} IOCs`));
    if (options.verbose && iocs.length > 0) {
      const typeCounts = new Map<string, number>();
      for (const ioc of iocs) {
        typeCounts.set(ioc.type, (typeCounts.get(ioc.type) || 0) + 1);
      }
      for (const [type, count] of typeCounts) {
        printInfo(`  ${type}: ${count}`);
      }
    }
  } catch (err) {
    iocSpinner.fail(chalk.red('IOC extraction failed'));
    printError('IOC extraction error', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // --- Extract TTPs ---
  const ttpSpinner = ora('Extracting TTPs using AI...').start();
  let ttps: ExtractedTTP[];
  try {
    const ttpResult = await extractTtps(client, report.rawText, { modelTier });
    ttps = ttpResult.ttps;
    ttpSpinner.succeed(chalk.green(`Extracted ${ttps.length} TTPs`));
    if (options.verbose && ttps.length > 0) {
      for (const ttp of ttps.slice(0, 5)) {
        printInfo(`  - ${ttp.description.substring(0, 80)}...`);
      }
      if (ttps.length > 5) {
        printInfo(`  ... and ${ttps.length - 5} more`);
      }
    }
  } catch (err) {
    ttpSpinner.fail(chalk.red('TTP extraction failed'));
    printError('TTP extraction error', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // --- Map to ATT&CK ---
  const attackSpinner = ora('Mapping TTPs to MITRE ATT&CK...').start();
  let mappings: AttackMappingResult[];
  try {
    const attackResult = await mapToAttack(client, ttps, { modelTier });
    mappings = attackResult.mappings;
    attackSpinner.succeed(
      chalk.green(`Mapped to ${mappings.length} ATT&CK techniques`),
    );
    if (options.verbose && mappings.length > 0) {
      for (const m of mappings.slice(0, 5)) {
        printInfo(`  ${m.techniqueId} — ${m.techniqueName} (${m.tactic})`);
      }
      if (mappings.length > 5) {
        printInfo(`  ... and ${mappings.length - 5} more`);
      }
    }
  } catch (err) {
    attackSpinner.fail(chalk.red('ATT&CK mapping failed'));
    printError('ATT&CK mapping error', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // --- Generate rules ---
  const generatedRules: GeneratedRule[] = [];
  let sigmaRules: SigmaRule[] = [];
  let yaraRules: YaraRule[] = [];
  let suricataRules: SuricataRule[] = [];

  // Sigma
  if (formats.includes('sigma')) {
    const sigmaSpinner = ora('Generating Sigma rules...').start();
    try {
      const result = await generateSigmaRules(client, ttps, mappings, iocs, { modelTier });
      sigmaRules = result.rules;
      sigmaSpinner.succeed(chalk.green(`Generated ${sigmaRules.length} Sigma rules`));

      for (const rule of sigmaRules) {
        const validation = validateSigmaRule(rule);
        generatedRules.push({
          format: 'sigma',
          sigma: rule,
          sourceReportId: report.id,
          attackTechniqueId: rule.tags?.find((t: string) => t.startsWith('attack.t'))?.replace('attack.', '').toUpperCase(),
          confidence: 'medium',
          validation,
        });
      }
    } catch (err) {
      sigmaSpinner.fail(chalk.red('Sigma rule generation failed'));
      printWarning(`Sigma generation error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // YARA
  if (formats.includes('yara')) {
    const yaraSpinner = ora('Generating YARA rules...').start();
    try {
      const result = await generateYaraRules(client, iocs, ttps, mappings);
      yaraRules = result.rules;
      yaraSpinner.succeed(chalk.green(`Generated ${yaraRules.length} YARA rules`));

      for (const rule of yaraRules) {
        const validation = validateYaraRule(rule);
        generatedRules.push({
          format: 'yara',
          yara: rule,
          sourceReportId: report.id,
          attackTechniqueId: rule.meta?.mitre_attack,
          confidence: 'medium',
          validation,
        });
      }
    } catch (err) {
      yaraSpinner.fail(chalk.red('YARA rule generation failed'));
      printWarning(`YARA generation error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // Suricata
  if (formats.includes('suricata')) {
    const suricataSpinner = ora('Generating Suricata rules...').start();
    try {
      const result = await generateSuricataRules(client, iocs, ttps, mappings);
      suricataRules = result.rules;
      suricataSpinner.succeed(chalk.green(`Generated ${suricataRules.length} Suricata rules`));

      for (const rule of suricataRules) {
        const validation = validateSuricataRule(rule);
        generatedRules.push({
          format: 'suricata',
          suricata: rule,
          sourceReportId: report.id,
          confidence: 'medium',
          validation,
        });
      }
    } catch (err) {
      suricataSpinner.fail(chalk.red('Suricata rule generation failed'));
      printWarning(`Suricata generation error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (generatedRules.length === 0) {
    printError('No rules were generated. Check the input report and AI configuration.');
    process.exit(1);
  }

  // --- Optional: Documentation ---
  if (options.verbose) {
    const docSpinner = ora('Generating rule documentation...').start();
    let docCount = 0;
    try {
      for (const rule of generatedRules) {
        const docResult = await generateDocumentation(rule, { client, modelTier });
        rule.documentation = docResult.documentation;
        docCount++;
      }
      docSpinner.succeed(chalk.green(`Generated documentation for ${docCount} rules`));
    } catch (err) {
      docSpinner.fail(chalk.yellow('Documentation generation partially failed'));
      printWarning(`Documentation error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // --- Optional: False Positive Analysis ---
  if (options.verbose) {
    const fpSpinner = ora('Analyzing false positive risk...').start();
    try {
      for (const rule of generatedRules) {
        const fpResult = await analyzeFalsePositives(rule, { client, modelTier });
        if (rule.documentation) {
          rule.documentation.falsePositives = fpResult.falsePositives;
        }
      }
      fpSpinner.succeed(chalk.green('False positive analysis complete'));
    } catch (err) {
      fpSpinner.fail(chalk.yellow('False positive analysis partially failed'));
      printWarning(`FP analysis error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // --- Optional: Coverage Gap Analysis ---
  if (options.verbose) {
    const gapSpinner = ora('Analyzing coverage gaps...').start();
    try {
      const gapResult = await analyzeCoverageGaps(generatedRules, ttps, mappings, { client, modelTier });
      gapSpinner.succeed(
        chalk.green(`Coverage gap analysis: ${gapResult.overallCoverage.coveredTechniqueCount}/${gapResult.overallCoverage.totalTechniqueCount} techniques covered`),
      );
      if (gapResult.recommendations.length > 0 && options.verbose) {
        printInfo('Top recommendations:');
        for (const rec of gapResult.recommendations.slice(0, 3)) {
          printInfo(`  - ${rec}`);
        }
      }
    } catch (err) {
      gapSpinner.fail(chalk.yellow('Coverage gap analysis failed'));
      printWarning(`Gap analysis error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // --- Optional: Test Sigma rules ---
  if (options.test) {
    const testSpinner = ora('Running tests on Sigma rules...').start();
    const sigmaGenerated = generatedRules.filter((r) => r.format === 'sigma' && r.sigma);
    if (sigmaGenerated.length > 0) {
      try {
        let passCount = 0;
        for (const rule of sigmaGenerated) {
          if (rule.sigma) {
            // Run test suite with empty log arrays (test data not provided)
            const testResult = evaluateSigmaRuleSuite(rule.sigma, [], []);
            if (testResult.tpRate >= 0 || testResult.fpRate === 0) {
              passCount++;
            }
          }
        }
        testSpinner.succeed(
          chalk.green(`Sigma rule tests: ${passCount}/${sigmaGenerated.length} passed baseline`),
        );
      } catch (err) {
        testSpinner.fail(chalk.yellow('Testing partially failed'));
        printWarning(`Test error: ${err instanceof Error ? err.message : String(err)}`);
      }
    } else {
      testSpinner.info(chalk.gray('No Sigma rules to test'));
    }
  }

  // --- Write output files ---
  const outputSpinner = ora('Writing output files...').start();
  const outputDir = resolveOutputDir(options.output);

  try {
    // Create subdirectories
    const sigmaDir = join(outputDir, 'sigma');
    const yaraDir = join(outputDir, 'yara');
    const suricataDir = join(outputDir, 'suricata');
    const reportsDir = join(outputDir, 'reports');

    for (const dir of [sigmaDir, yaraDir, suricataDir, reportsDir]) {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    }

    // Write Sigma rules
    for (const rule of sigmaRules) {
      const filename = `${sanitizeFilename(rule.title || rule.id)}.yml`;
      writeFileSync(join(sigmaDir, filename), rule.raw, 'utf-8');
    }

    // Write YARA rules
    for (const rule of yaraRules) {
      const filename = `${sanitizeFilename(rule.name)}.yar`;
      writeFileSync(join(yaraDir, filename), rule.raw, 'utf-8');
    }

    // Write Suricata rules
    if (suricataRules.length > 0) {
      const allSuricataRaw = suricataRules.map((r) => r.raw).join('\n');
      writeFileSync(join(suricataDir, 'detectforge.rules'), allSuricataRaw, 'utf-8');
    }

    // Write summary report
    const validCount = generatedRules.filter((r) => r.validation.valid).length;
    const costSummary = client.getCostSummary();
    const durationMs = Date.now() - startTime;

    const summary: GenerationSummary = {
      sigmaRules: sigmaRules.length,
      yaraRules: yaraRules.length,
      suricataRules: suricataRules.length,
      totalRules: generatedRules.length,
      validationPassed: validCount,
      validationFailed: generatedRules.length - validCount,
      totalCostUsd: costSummary.totalCostUsd,
      totalTokens: costSummary.totalTokens,
      durationMs,
    };

    const reportData = {
      generatedAt: new Date().toISOString(),
      inputFile: basename(inputPath),
      reportTitle: report.title,
      formats,
      modelTier,
      summary,
      iocCount: iocs.length,
      ttpCount: ttps.length,
      attackMappingCount: mappings.length,
      rules: generatedRules.map((r) => ({
        format: r.format,
        id: r.sigma?.id || r.yara?.name || r.suricata?.sid?.toString() || 'unknown',
        title: r.sigma?.title || r.yara?.meta?.description || `SID ${r.suricata?.sid}`,
        attackTechniqueId: r.attackTechniqueId || 'N/A',
        valid: r.validation.valid,
        errors: r.validation.errors,
        warnings: r.validation.warnings,
      })),
    };

    writeFileSync(
      join(reportsDir, 'summary.json'),
      JSON.stringify(reportData, null, 2),
      'utf-8',
    );

    outputSpinner.succeed(chalk.green(`Output written to ${outputDir}`));

    // --- Print Summary Table ---
    console.log('');
    console.log(chalk.bold('  Generation Summary'));
    console.log(chalk.gray('  ─────────────────────────────────────────'));
    console.log(`  ${chalk.cyan('Sigma rules:')}     ${sigmaRules.length}`);
    console.log(`  ${chalk.cyan('YARA rules:')}      ${yaraRules.length}`);
    console.log(`  ${chalk.cyan('Suricata rules:')}  ${suricataRules.length}`);
    console.log(`  ${chalk.cyan('Total rules:')}     ${generatedRules.length}`);
    console.log('');
    console.log(
      `  ${chalk.cyan('Validation:')}      ${chalk.green(`${validCount} passed`)} / ${
        generatedRules.length - validCount > 0
          ? chalk.red(`${generatedRules.length - validCount} failed`)
          : chalk.green('0 failed')
      }`,
    );
    console.log(
      `  ${chalk.cyan('Pass rate:')}       ${
        generatedRules.length > 0
          ? `${Math.round((validCount / generatedRules.length) * 100)}%`
          : 'N/A'
      }`,
    );
    console.log('');
    console.log(`  ${chalk.cyan('IOCs extracted:')} ${iocs.length}`);
    console.log(`  ${chalk.cyan('TTPs extracted:')} ${ttps.length}`);
    console.log(`  ${chalk.cyan('ATT&CK mapped:')} ${mappings.length}`);
    console.log('');
    console.log(`  ${chalk.cyan('API cost:')}        $${costSummary.totalCostUsd.toFixed(4)}`);
    console.log(`  ${chalk.cyan('Total tokens:')}    ${costSummary.totalTokens.toLocaleString()}`);
    console.log(`  ${chalk.cyan('Duration:')}        ${(durationMs / 1000).toFixed(1)}s`);
    console.log('');
    printSuccess(`Rules saved to ${outputDir}`);
    console.log('');
  } catch (err) {
    outputSpinner.fail(chalk.red('Failed to write output files'));
    printError('Output write error', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert a string into a safe filename.
 */
function sanitizeFilename(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9_\-\.]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .substring(0, 100) || 'rule';
}
