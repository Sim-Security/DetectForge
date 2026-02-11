#!/usr/bin/env bun
/**
 * Test all existing Sigma rules for TP/FP effectiveness.
 *
 * Loads all .yml files from rules/ subdirectories, parses them as Sigma
 * rules, then runs the effectiveness tester against each one.
 *
 * Usage:  bun run scripts/test-rule-effectiveness.ts
 *
 * All evaluation is in-memory — zero API calls, runs in <5 seconds.
 */

import { readdir, readFile } from 'node:fs/promises';
import { join, resolve, basename } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { testRulesEffectiveness } from '@/testing/effectiveness-tester.js';
import type { SigmaRule } from '@/types/detection-rule.js';
import type { EffectivenessResult } from '@/testing/effectiveness-tester.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(import.meta.dirname ?? '.', '..');
const RULES_DIR = join(PROJECT_ROOT, 'rules');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Recursively find all .yml files under a directory.
 */
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
    // Directory doesn't exist or isn't readable
  }
  return results;
}

/**
 * Parse a YAML file into a SigmaRule object.
 */
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
      references: Array.isArray(obj.references)
        ? obj.references.map(String)
        : [],
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
      falsepositives: Array.isArray(obj.falsepositives)
        ? obj.falsepositives.map(String)
        : [],
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

function formatPct(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}

function statusIcon(pass: boolean): string {
  return pass ? 'PASS' : 'FAIL';
}

function printTable(results: EffectivenessResult[]): void {
  // Header
  const header = [
    'Status'.padEnd(6),
    'Rule Title'.padEnd(55),
    'TP Rate'.padStart(8),
    'FP Rate'.padStart(8),
    'Fields'.padStart(8),
    'TP'.padStart(4),
    'FN'.padStart(4),
    'FP'.padStart(4),
    'TN'.padStart(4),
  ].join(' | ');

  console.log(header);
  console.log('-'.repeat(header.length));

  for (const r of results) {
    const row = [
      statusIcon(r.pass).padEnd(6),
      r.ruleTitle.substring(0, 55).padEnd(55),
      formatPct(r.suite.tpRate).padStart(8),
      formatPct(r.suite.fpRate).padStart(8),
      formatPct(r.fieldValidation.fieldValidityRate).padStart(8),
      String(r.suite.truePositives).padStart(4),
      String(r.suite.falseNegatives).padStart(4),
      String(r.suite.falsePositives).padStart(4),
      String(r.suite.trueNegatives).padStart(4),
    ].join(' | ');

    console.log(row);

    // Print failure reasons
    if (r.failures.length > 0) {
      for (const f of r.failures) {
        console.log(`         -> ${f}`);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('DetectForge — Rule Effectiveness Tester');
  console.log('=======================================\n');

  // Find all Sigma rule files
  const ymlFiles = await findYmlFiles(RULES_DIR);
  const sigmaFiles = ymlFiles.filter(
    (f) => f.includes('/sigma/') || f.endsWith('.sigma.yml'),
  );

  console.log(`Found ${sigmaFiles.length} Sigma rule files in ${RULES_DIR}\n`);

  if (sigmaFiles.length === 0) {
    console.log('No Sigma rules found. Generate some rules first.');
    return;
  }

  // Parse rules
  const rules: SigmaRule[] = [];
  const parseErrors: string[] = [];

  for (const filePath of sigmaFiles) {
    const rule = await parseRuleFile(filePath);
    if (rule) {
      rules.push(rule);
    } else {
      parseErrors.push(basename(filePath));
    }
  }

  if (parseErrors.length > 0) {
    console.log(`Skipped ${parseErrors.length} unparseable files: ${parseErrors.join(', ')}\n`);
  }

  console.log(`Testing ${rules.length} rules...\n`);

  // Run effectiveness tests
  const summary = testRulesEffectiveness(rules, {
    attackLogCount: 10,
    benignLogCount: 20,
  });

  // Print results table
  printTable(summary.results);

  // Print summary
  console.log('\n' + '='.repeat(80));
  console.log('SUMMARY');
  console.log('='.repeat(80));
  console.log(`  Total rules tested:  ${summary.totalRules}`);
  console.log(`  Passed:              ${summary.passedRules}`);
  console.log(`  Failed:              ${summary.failedRules}`);
  console.log(`  Avg TP rate:         ${formatPct(summary.avgTpRate)}`);
  console.log(`  Avg FP rate:         ${formatPct(summary.avgFpRate)}`);
  console.log(`  Avg field validity:  ${formatPct(summary.avgFieldValidity)}`);

  // Print field validation details for rules with issues
  const fieldIssues = summary.results.filter(
    (r) => !r.fieldValidation.unknownLogsource && r.fieldValidation.invalidFields.length > 0,
  );
  if (fieldIssues.length > 0) {
    console.log('\n--- Field Validity Issues ---');
    for (const r of fieldIssues) {
      console.log(
        `  ${r.ruleTitle}: invalid fields [${r.fieldValidation.invalidFields.join(', ')}]`,
      );
    }
  }

  console.log('');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
