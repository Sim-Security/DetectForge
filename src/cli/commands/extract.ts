/**
 * Extract command — IOC and TTP extraction from threat reports.
 *
 * Reads a threat intelligence report, normalizes it, extracts IOCs
 * and TTPs using regex + AI, maps to MITRE ATT&CK, and writes the
 * structured extraction result as JSON.
 */

import { readFileSync, writeFileSync } from 'fs';
import { resolve, basename, extname, dirname } from 'path';
import { mkdirSync, existsSync } from 'fs';
import type { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';

import { AIClient } from '@/ai/client.js';
import { normalizeReport } from '@/ingestion/index.js';
import { extractIocs, extractTtps, mapToAttack } from '@/extraction/index.js';
import type { ExtractionResult } from '@/types/index.js';
import type { ModelTier } from '@/ai/client.js';
import {
  resolveInputPath,
  printError,
  printInfo,
  printSuccess,
} from '../options.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ExtractOptions {
  input: string;
  output: string;
  model: string;
}

// ---------------------------------------------------------------------------
// Command Registration
// ---------------------------------------------------------------------------

export function registerExtractCommand(program: Command): void {
  program
    .command('extract')
    .description('Extract IOCs and TTPs from a threat report (no rule generation)')
    .requiredOption('-i, --input <path>', 'Path to threat report')
    .option('-o, --output <file>', 'Output JSON file', 'extracted.json')
    .option('--model <tier>', 'AI model tier: fast, standard, quality', 'standard')
    .action(async (options: ExtractOptions) => {
      await runExtract(options);
    });
}

// ---------------------------------------------------------------------------
// Main Logic
// ---------------------------------------------------------------------------

async function runExtract(options: ExtractOptions): Promise<void> {
  const startTime = Date.now();

  console.log('');
  console.log(chalk.bold.cyan('  DetectForge — IOC/TTP Extraction'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));
  console.log('');

  // --- Resolve paths ---
  const inputPath = resolveInputPath(options.input);
  const outputPath = resolve(options.output);
  const modelTier = options.model as ModelTier;

  printInfo(`Input:  ${inputPath}`);
  printInfo(`Output: ${outputPath}`);
  printInfo(`Model:  ${modelTier}`);
  console.log('');

  // --- Read input ---
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
  const normalizeSpinner = ora('Parsing threat report...').start();
  let report;
  try {
    report = await normalizeReport(inputData, { filename: basename(inputPath) });
    normalizeSpinner.succeed(
      chalk.green(`Parsed: "${report.title || basename(inputPath)}" (${report.sections.length} sections)`),
    );
  } catch (err) {
    normalizeSpinner.fail(chalk.red('Failed to parse report'));
    printError('Report parsing failed', err instanceof Error ? err.message : String(err));
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
  const iocSpinner = ora('Extracting IOCs...').start();
  let iocs;
  try {
    iocs = extractIocs(report.rawText);
    iocSpinner.succeed(chalk.green(`Extracted ${iocs.length} IOCs`));
  } catch (err) {
    iocSpinner.fail(chalk.red('IOC extraction failed'));
    printError('IOC extraction error', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // --- Extract TTPs ---
  const ttpSpinner = ora('Extracting TTPs using AI...').start();
  let ttps;
  try {
    const ttpResult = await extractTtps(client, report.rawText, { modelTier });
    ttps = ttpResult.ttps;
    ttpSpinner.succeed(chalk.green(`Extracted ${ttps.length} TTPs`));
  } catch (err) {
    ttpSpinner.fail(chalk.red('TTP extraction failed'));
    printError('TTP extraction error', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // --- Map to ATT&CK ---
  const attackSpinner = ora('Mapping to MITRE ATT&CK...').start();
  let mappings;
  try {
    const attackResult = await mapToAttack(client, ttps, { modelTier });
    mappings = attackResult.mappings;
    attackSpinner.succeed(chalk.green(`Mapped ${mappings.length} ATT&CK techniques`));
  } catch (err) {
    attackSpinner.fail(chalk.red('ATT&CK mapping failed'));
    printError('ATT&CK mapping error', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // --- Build extraction result ---
  const durationMs = Date.now() - startTime;
  const costSummary = client.getCostSummary();

  const result: ExtractionResult = {
    reportId: report.id,
    iocs,
    ttps,
    attackMappings: mappings,
    metadata: {
      processingTimeMs: durationMs,
      aiTokensUsed: costSummary.totalTokens,
      aiCostUsd: costSummary.totalCostUsd,
      iocExtractionMethod: 'regex',
      ttpExtractionMethod: 'ai',
      attackMappingMethod: 'ai_with_validation',
    },
  };

  // --- Write output ---
  const writeSpinner = ora('Writing extraction results...').start();
  try {
    const outDir = dirname(outputPath);
    if (!existsSync(outDir)) {
      mkdirSync(outDir, { recursive: true });
    }

    writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf-8');
    writeSpinner.succeed(chalk.green(`Results written to ${outputPath}`));
  } catch (err) {
    writeSpinner.fail(chalk.red('Failed to write output'));
    printError('Write error', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  // --- Summary ---
  console.log('');
  console.log(chalk.bold('  Extraction Summary'));
  console.log(chalk.gray('  ─────────────────────────────────────────'));
  console.log(`  ${chalk.cyan('IOCs extracted:')}      ${iocs.length}`);

  // IOC type breakdown
  const iocTypeCounts = new Map<string, number>();
  for (const ioc of iocs) {
    iocTypeCounts.set(ioc.type, (iocTypeCounts.get(ioc.type) || 0) + 1);
  }
  for (const [type, count] of iocTypeCounts) {
    console.log(`    ${chalk.gray(type)}: ${count}`);
  }

  console.log(`  ${chalk.cyan('TTPs extracted:')}      ${ttps.length}`);
  console.log(`  ${chalk.cyan('ATT&CK techniques:')}   ${mappings.length}`);

  // ATT&CK technique list
  for (const m of mappings.slice(0, 10)) {
    console.log(`    ${chalk.gray(`${m.techniqueId} — ${m.techniqueName} (${m.tactic})`)}`);
  }
  if (mappings.length > 10) {
    console.log(`    ${chalk.gray(`... and ${mappings.length - 10} more`)}`);
  }

  console.log('');
  console.log(`  ${chalk.cyan('API cost:')}            $${costSummary.totalCostUsd.toFixed(4)}`);
  console.log(`  ${chalk.cyan('Total tokens:')}        ${costSummary.totalTokens.toLocaleString()}`);
  console.log(`  ${chalk.cyan('Duration:')}            ${(durationMs / 1000).toFixed(1)}s`);
  console.log('');
  printSuccess(`Extraction complete: ${outputPath}`);
  console.log('');
}
