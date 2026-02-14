#!/usr/bin/env bun
/**
 * Test all Sigma rules against real OTRF attack simulation data.
 *
 * Compares synthetic TP/FP rates with real-data TP/FP rates to reveal
 * where template-generated test logs overestimate detection capability.
 *
 * Usage:
 *   bun run scripts/test-rules-real-data.ts             # test only (datasets must exist)
 *   bun run scripts/test-rules-real-data.ts --download   # download datasets first
 */

import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { SigmaRule } from '@/types/detection-rule.js';
import { downloadDatasets } from '@/testing/real-data/dataset-downloader.js';
import { testRulesAgainstRealData } from '@/testing/real-data/real-data-tester.js';
import type { RealDataTestResult, PerDatasetResult } from '@/testing/real-data/real-data-tester.js';
import type { MatchQuality } from '@/testing/real-data/real-data-tester.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(import.meta.dirname ?? '.', '..');
const RULES_DIR = join(PROJECT_ROOT, 'rules');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function findYmlFiles(dir: string): Promise<string[]> {
  const results: string[] = [];
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...(await findYmlFiles(fullPath)));
      } else if (entry.name.endsWith('.yml') || entry.name.endsWith('.yaml')) {
        results.push(fullPath);
      }
    }
  } catch {
    // Directory doesn't exist
  }
  return results;
}

async function parseRuleFile(filePath: string): Promise<SigmaRule | null> {
  try {
    const content = await readFile(filePath, 'utf-8');
    const parsed = parseYaml(content);
    if (!parsed || typeof parsed !== 'object') return null;

    const obj = parsed as Record<string, unknown>;
    if (!obj.detection || !obj.logsource) return null;

    const logsource = obj.logsource as Record<string, unknown>;
    const detection = obj.detection as Record<string, unknown>;

    return {
      id: String(obj.id ?? ''),
      title: String(obj.title ?? ''),
      status: String(obj.status ?? 'experimental') as SigmaRule['status'],
      description: String(obj.description ?? ''),
      references: Array.isArray(obj.references) ? obj.references.map(String) : [],
      author: String(obj.author ?? ''),
      date: String(obj.date ?? ''),
      modified: String(obj.modified ?? ''),
      tags: Array.isArray(obj.tags) ? obj.tags.map(String) : [],
      logsource: {
        product: logsource.product ? String(logsource.product) : undefined,
        category: logsource.category ? String(logsource.category) : undefined,
        service: logsource.service ? String(logsource.service) : undefined,
      },
      detection: {
        ...detection,
        condition: String(detection.condition ?? ''),
      },
      falsepositives: Array.isArray(obj.falsepositives) ? obj.falsepositives.map(String) : [],
      level: String(obj.level ?? 'medium') as SigmaRule['level'],
      raw: content,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

function pct(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}

function verdictIcon(verdict: string): string {
  if (verdict === 'pass') return 'PASS';
  if (verdict === 'fail') return 'FAIL';
  if (verdict === 'behavior-mismatch') return 'B-M ';
  return ' -- ';
}

function matchLabel(matchType: MatchQuality): string {
  if (matchType === 'technique-match') return 'TEC';
  if (matchType === 'behavior-mismatch') return 'B-M';
  if (matchType === 'category-only') return 'CAT';
  return '---';
}

function printTable(results: RealDataTestResult[]): void {
  const cols = [
    'Verdict'.padEnd(7),
    'Match'.padEnd(5),
    'Conf'.padEnd(4),
    'Evade'.padStart(6),
    'Rule Title'.padEnd(50),
    'Category'.padEnd(12),
    'Syn TP'.padStart(7),
    'Beh TP'.padStart(7),
    'Real TP'.padStart(8),
    'Best TP'.padStart(8),
    'HO TP'.padStart(8),
  ];
  cols.push(
    'Var'.padStart(5),
    'Syn FP'.padStart(7),
    'Real FP'.padStart(8),
    'Atk#'.padStart(5),
    'Ben#'.padStart(5),
  );
  const header = cols.join(' | ');

  console.log(header);
  console.log('-'.repeat(header.length));

  // Sort: technique-match first (pass, fail), then behavior-mismatch, then category-only, then no-data
  const sorted = [...results].sort((a, b) => {
    const matchOrder: Record<string, number> = { 'technique-match': 0, 'behavior-mismatch': 1, 'category-only': 2, 'no-data': 3 };
    const matchDiff = (matchOrder[a.matchType] ?? 4) - (matchOrder[b.matchType] ?? 4);
    if (matchDiff !== 0) return matchDiff;
    const verdictOrder: Record<string, number> = { pass: 0, fail: 1, 'behavior-mismatch': 2, 'no-data': 3 };
    return (verdictOrder[a.verdict] ?? 4) - (verdictOrder[b.verdict] ?? 4);
  });

  for (const r of sorted) {
    const realTp = r.real ? pct(r.real.tpRate) : 'N/A';
    const realFp = r.real ? pct(r.real.fpRate) : 'N/A';
    const bestTp = r.bestDatasetResult ? pct(r.bestDatasetResult.tpRate) : 'N/A';
    const behTp = r.behavioralTpRate !== null ? pct(r.behavioralTpRate) : 'N/A';
    const confLabel = r.confidence ? r.confidence.level.substring(0, 4).toUpperCase() : '----';
    const evadeLabel = r.evasionResilience
      ? pct(r.evasionResilience.resilienceScore)
      : 'N/A';

    const hoResults = r.holdOutResults ?? [];
    const bestHo = hoResults.filter((d: PerDatasetResult) => d.attackCount > 0)
      .reduce<PerDatasetResult | null>((best, d) => !best || d.tpRate > best.tpRate ? d : best, null);
    const hoTp = bestHo ? pct(bestHo.tpRate) : (r.holdOutVerdict === 'no-holdout' ? '--' : 'N/A');
    const varLabel = r.perDatasetVariance > 0 ? pct(r.perDatasetVariance) : '--';

    const rowCols = [
      verdictIcon(r.verdict).padEnd(7),
      matchLabel(r.matchType).padEnd(5),
      confLabel.padEnd(4),
      evadeLabel.padStart(6),
      r.ruleTitle.substring(0, 50).padEnd(50),
      r.ruleCategory.substring(0, 12).padEnd(12),
      pct(r.synthetic.tpRate).padStart(7),
      behTp.padStart(7),
      realTp.padStart(8),
      bestTp.padStart(8),
      hoTp.padStart(8),
    ];
    rowCols.push(
      varLabel.padStart(5),
      pct(r.synthetic.fpRate).padStart(7),
      realFp.padStart(8),
      String(r.attackLogsCount).padStart(5),
      String(r.benignLogsCount).padStart(5),
    );
    const row = rowCols.join(' | ');

    console.log(row);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function printVerboseDiagnostics(
  results: RealDataTestResult[],
  rules: SigmaRule[],
): void {
  // Show per-dataset breakdown for technique-matched and behavior-mismatch rules with data
  const techMatched = results.filter(
    (r) => (r.matchType === 'technique-match' || r.matchType === 'behavior-mismatch') && r.real !== null,
  );

  if (techMatched.length === 0) {
    console.log('\n  No technique-matched rules to diagnose.\n');
    return;
  }

  console.log(`\n${'='.repeat(80)}`);
  console.log('VERBOSE DIAGNOSTICS — Per-Dataset Breakdown');
  console.log('='.repeat(80));

  for (const r of techMatched) {
    const rule = rules.find((rl) => rl.id === r.ruleId);
    const icon = r.verdict === 'pass' ? 'PASS' : r.verdict === 'behavior-mismatch' ? 'B-M ' : 'FAIL';
    console.log(`\n  [${icon}] ${r.ruleTitle}`);
    console.log(`  Category: ${r.ruleCategory}`);
    console.log(`  Pooled: TP ${pct(r.real!.tpRate)} (${r.real!.truePositives}/${r.attackLogsCount}) | FP ${pct(r.real!.fpRate)} (${r.real!.falsePositives}/${r.benignLogsCount})`);

    if (r.bestDatasetResult) {
      console.log(`  Best:   TP ${pct(r.bestDatasetResult.tpRate)} (${r.bestDatasetResult.truePositives}/${r.bestDatasetResult.attackCount}) from ${r.bestDatasetResult.datasetId}`);
    }

    // Per-dataset breakdown
    if (r.perDatasetResults.length > 1) {
      console.log('  Per-dataset:');
      for (const ds of r.perDatasetResults) {
        const dsMark = ds === r.bestDatasetResult ? ' ← best' : '';
        console.log(`    ${ds.datasetId}: TP ${pct(ds.tpRate)} (${ds.truePositives}/${ds.attackCount}) | FP ${pct(ds.fpRate)} (${ds.falsePositives}/${ds.benignCount})${dsMark}`);
      }
    }

    // Show detection fields for failing rules
    if (r.verdict === 'fail' && rule) {
      const detection = rule.detection;
      const selectionNames = Object.keys(detection).filter((k) => k !== 'condition');
      console.log(`  Condition: ${detection.condition}`);
      console.log(`  Selections: ${selectionNames.join(', ')}`);

      for (const selName of selectionNames) {
        const sel = detection[selName];
        if (typeof sel === 'object' && sel !== null) {
          const items = Array.isArray(sel) ? sel : [sel];
          const fieldNames: string[] = [];
          for (const item of items) {
            if (typeof item === 'object' && item !== null) {
              fieldNames.push(...Object.keys(item as Record<string, unknown>));
            }
          }
          if (fieldNames.length > 0) {
            console.log(`    ${selName}: ${fieldNames.join(', ')}`);
          }
        }
      }
    }

    console.log('  ' + '-'.repeat(60));
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const shouldDownload = args.includes('--download');
  const verbose = args.includes('--verbose');

  console.log('DetectForge — Real Attack Data Tester');
  console.log('======================================\n');

  // Step 1: Optionally download datasets
  if (shouldDownload) {
    console.log('Downloading OTRF datasets...\n');
    const dlResult = await downloadDatasets();
    console.log(
      `\nDownloaded: ${dlResult.downloaded} | Skipped: ${dlResult.skipped} | Failed: ${dlResult.failed}\n`,
    );
  }

  // Step 2: Find and parse all Sigma rules
  const ymlFiles = await findYmlFiles(RULES_DIR);
  const sigmaFiles = ymlFiles.filter(
    (f) => f.includes('/sigma/') || f.endsWith('.sigma.yml'),
  );

  const rules: SigmaRule[] = [];
  for (const filePath of sigmaFiles) {
    const rule = await parseRuleFile(filePath);
    if (rule) rules.push(rule);
  }

  console.log(`Rules:    ${rules.length} Sigma rules loaded\n`);

  if (rules.length === 0) {
    console.log('No Sigma rules found. Generate rules first.');
    return;
  }

  // Step 3: Run real data tests (hold-out validation always enabled)
  console.log('Testing rules against real attack data...\n');
  const summary = await testRulesAgainstRealData(rules);

  // Step 4: Print results
  console.log(`Datasets: ${summary.rulesWithData > 0 ? 'loaded' : 'none found'}`);
  console.log(`Rules with matching data: ${summary.rulesWithData}/${summary.totalRules}\n`);

  printTable(summary.results);

  // Step 5: Print summary
  console.log('\n' + '='.repeat(80));
  console.log('SUMMARY');
  console.log('='.repeat(80));
  console.log(`  Total rules:        ${summary.totalRules}`);

  // Segmented metrics by match quality
  if (summary.techniqueMatchedCount > 0) {
    console.log('');
    console.log('  TECHNIQUE-MATCHED (honest signal — best per-dataset):');
    console.log(`    Rules:     ${summary.techniqueMatchedCount}`);
    console.log(`    Pass rate: ${summary.techniqueMatchedPassed}/${summary.techniqueMatchedCount} (${pct(summary.techniqueMatchedCount > 0 ? summary.techniqueMatchedPassed / summary.techniqueMatchedCount : 0)})`);
    console.log(`    Avg best TP: ${pct(summary.avgTechniqueMatchedTpRate)}`);
  }

  if (summary.behaviorMismatchCount > 0) {
    console.log('');
    console.log('  BEHAVIOR-MISMATCH (technique matched, but different attack variant):');
    console.log(`    Rules:     ${summary.behaviorMismatchCount}`);
  }

  if (summary.categoryOnlyCount > 0) {
    console.log('');
    console.log('  CATEGORY-ONLY (weak signal):');
    console.log(`    Rules:     ${summary.categoryOnlyCount}`);
    console.log(`    Avg TP:    ${pct(summary.avgCategoryOnlyTpRate)}`);
  }

  console.log('');
  console.log('  NO DATA:');
  console.log(`    Rules:     ${summary.noDataCount}`);

  if (summary.rulesWithData > 0) {
    console.log('');
    console.log('  OVERALL (all rules with data):');
    console.log(`    Rules with data:  ${summary.rulesWithData}/${summary.totalRules}`);
    console.log(`    Synthetic TP avg: ${pct(summary.avgSyntheticTpRate)}`);
    console.log(`    Real TP avg:      ${pct(summary.avgRealTpRate)}`);
    console.log(`    TP gap:           ${pct(summary.avgSyntheticTpRate - summary.avgRealTpRate)}`);
    console.log(`    Pass rate:        ${summary.passed}/${summary.rulesWithData}`);
  }

  console.log('');

  // Step 6: Verbose diagnostics for failing rules
  if (verbose) {
    printVerboseDiagnostics(summary.results, rules);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
