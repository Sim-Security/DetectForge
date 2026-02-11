#!/usr/bin/env bun
/**
 * Batch generate: run the full pipeline on all threat reports.
 *
 * For each report in data/threat-reports/reports/:
 *   1. TTP extraction (AI)
 *   2. ATT&CK mapping (AI)
 *   3. Sigma rule generation (AI)
 *   4. Validation + output
 *
 * Usage:  bun run scripts/batch-generate.ts [--sigma-only] [--model <tier>]
 *
 * Reports that fail are logged and skipped; the script continues to the next.
 */

import { readdir, readFile } from 'node:fs/promises';
import { join, resolve, basename } from 'node:path';
import { spawnSync } from 'node:child_process';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(import.meta.dirname ?? '.', '..');
const REPORTS_DIR = join(PROJECT_ROOT, 'data/threat-reports/reports');
const OUTPUT_DIR = join(PROJECT_ROOT, 'rules');
const CLI_ENTRY = join(PROJECT_ROOT, 'src/cli/index.ts');

// Parse args
const args = process.argv.slice(2);
const sigmaOnly = args.includes('--sigma-only') || true; // default to sigma-only
const modelIdx = args.indexOf('--model');
const model = modelIdx >= 0 && args[modelIdx + 1] ? args[modelIdx + 1] : 'standard';

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

interface ReportResult {
  file: string;
  status: 'success' | 'error';
  durationSec: number;
  error?: string;
}

async function main(): Promise<void> {
  console.log('DetectForge — Batch Generate');
  console.log('============================\n');

  // Find all reports
  const files = await readdir(REPORTS_DIR);
  const reports = files.filter((f) => f.endsWith('.txt') || f.endsWith('.md') || f.endsWith('.html'));

  console.log(`Found ${reports.length} reports in ${REPORTS_DIR}`);
  console.log(`Output: ${OUTPUT_DIR}`);
  console.log(`Model:  ${model}`);
  console.log(`Format: ${sigmaOnly ? 'sigma-only' : 'sigma,yara,suricata'}`);
  console.log('');

  const results: ReportResult[] = [];
  let totalRulesGenerated = 0;

  for (let i = 0; i < reports.length; i++) {
    const file = reports[i];
    const inputPath = join(REPORTS_DIR, file);
    const num = `[${i + 1}/${reports.length}]`;

    console.log(`${num} Processing: ${file}`);
    const start = Date.now();

    try {
      const cmdArgs = [
        'run', CLI_ENTRY, 'generate',
        '-i', inputPath,
        '-o', OUTPUT_DIR,
        '--model', model,
      ];
      if (sigmaOnly) cmdArgs.push('--sigma-only');

      const result = spawnSync('bun', cmdArgs, {
        cwd: PROJECT_ROOT,
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 1_800_000, // 30 min per report
        env: { ...process.env },
      });

      const durationSec = (Date.now() - start) / 1000;
      const stdout = result.stdout?.toString() ?? '';
      const stderr = result.stderr?.toString() ?? '';

      if (result.status === 0) {
        // Extract rule count from output
        const sigmaMatch = stdout.match(/Generated (\d+) Sigma rules/);
        const ruleCount = sigmaMatch ? parseInt(sigmaMatch[1], 10) : 0;
        totalRulesGenerated += ruleCount;

        console.log(`  ✓ Done in ${durationSec.toFixed(1)}s — ${ruleCount} Sigma rules`);
        results.push({ file, status: 'success', durationSec });
      } else {
        // Extract meaningful error
        const errorLine = stderr.split('\n').find((l) => l.includes('Error') || l.includes('error')) ?? stderr.substring(0, 200);
        console.log(`  ✗ Failed in ${durationSec.toFixed(1)}s — ${errorLine.trim()}`);
        results.push({ file, status: 'error', durationSec, error: errorLine.trim() });
      }
    } catch (err) {
      const durationSec = (Date.now() - start) / 1000;
      const errorMsg = err instanceof Error ? err.message : String(err);
      console.log(`  ✗ Error in ${durationSec.toFixed(1)}s — ${errorMsg}`);
      results.push({ file, status: 'error', durationSec, error: errorMsg });
    }

    console.log('');
  }

  // Summary
  const succeeded = results.filter((r) => r.status === 'success').length;
  const failed = results.filter((r) => r.status === 'error').length;
  const totalTime = results.reduce((sum, r) => sum + r.durationSec, 0);

  console.log('='.repeat(60));
  console.log('BATCH GENERATE SUMMARY');
  console.log('='.repeat(60));
  console.log(`  Reports processed: ${results.length}`);
  console.log(`  Succeeded:         ${succeeded}`);
  console.log(`  Failed:            ${failed}`);
  console.log(`  Total rules:       ${totalRulesGenerated}`);
  console.log(`  Total time:        ${totalTime.toFixed(1)}s (${(totalTime / 60).toFixed(1)}m)`);
  console.log(`  Avg per report:    ${(totalTime / results.length).toFixed(1)}s`);
  console.log('');

  if (failed > 0) {
    console.log('Failed reports:');
    for (const r of results.filter((r) => r.status === 'error')) {
      console.log(`  - ${r.file}: ${r.error}`);
    }
    console.log('');
  }

  console.log('Next steps:');
  console.log('  1. bun run scripts/batch-benchmark.ts   — analyze quality of all generated rules');
  console.log('  2. bun run scripts/test-rule-effectiveness.ts — test TP/FP rates');
  console.log('');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
