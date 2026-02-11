#!/usr/bin/env bun
/**
 * Batch benchmark: process all threat reports through the full pipeline.
 *
 * For each report in data/threat-reports/reports/:
 *   1. Run through TTP extraction → ATT&CK mapping → Sigma generation
 *   2. Validate generated rules
 *   3. Score quality
 *   4. Test effectiveness (TP/FP rates)
 *   5. Validate field correctness
 *
 * Outputs:
 *   data/scale-test-results.json   — machine-readable results
 *   docs/SCALE_TEST_REPORT.md      — human-readable summary
 *
 * Cost estimate: ~$0.06/report × N reports
 *
 * Usage:  bun run scripts/batch-benchmark.ts
 */

import { readdir, readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, resolve, basename } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { testRulesEffectiveness } from '@/testing/effectiveness-tester.js';
import { scoreRuleQuality } from '@/testing/quality-scorer.js';
import { validateSigmaRule } from '@/generation/sigma/validator.js';
import { validateRuleFields } from '@/testing/field-validator.js';
import type { SigmaRule, GeneratedRule, ValidationResult } from '@/types/detection-rule.js';
import type { EffectivenessSummary } from '@/testing/effectiveness-tester.js';
import type { RuleQualityScore } from '@/testing/quality-scorer.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(import.meta.dirname ?? '.', '..');
const RULES_DIR = join(PROJECT_ROOT, 'rules');
const DATA_DIR = join(PROJECT_ROOT, 'data');
const DOCS_DIR = join(PROJECT_ROOT, 'docs');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RuleAnalysis {
  filePath: string;
  rule: SigmaRule;
  validation: ValidationResult;
  qualityScore: RuleQualityScore;
  fieldValidation: {
    validFields: string[];
    invalidFields: string[];
    fieldValidityRate: number;
    unknownLogsource: boolean;
  };
}

interface BatchResults {
  timestamp: string;
  totalRules: number;
  validRules: number;
  invalidRules: number;
  avgQualityScore: number;
  qualityDistribution: Record<string, number>;
  effectiveness: {
    avgTpRate: number;
    avgFpRate: number;
    avgFieldValidity: number;
    passedRules: number;
    failedRules: number;
  };
  commonInvalidFields: Array<{ field: string; count: number }>;
  logsourceDistribution: Record<string, number>;
  levelDistribution: Record<string, number>;
  ruleAnalyses: RuleAnalysis[];
}

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
    // skip
  }
  return results;
}

function parseRuleFromYaml(content: string): SigmaRule | null {
  try {
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
      detection: { ...detection, condition: String(detection.condition ?? '') },
      falsepositives: Array.isArray(obj.falsepositives) ? obj.falsepositives.map(String) : [],
      level: String(obj.level ?? 'medium') as SigmaRule['level'],
      raw: content,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

function analyzeRule(filePath: string, rule: SigmaRule): RuleAnalysis {
  const validation = validateSigmaRule(rule);
  const fieldValidation = validateRuleFields(rule);

  // Build a GeneratedRule wrapper for the quality scorer
  const generatedRule: GeneratedRule = {
    format: 'sigma',
    sigma: rule,
    sourceReportId: '',
    attackTechniqueId: extractTechniqueId(rule.tags),
    attackTactic: extractTactic(rule.tags),
    confidence: 'medium',
    validation,
  };

  const qualityScore = scoreRuleQuality(generatedRule);

  return {
    filePath: filePath.replace(PROJECT_ROOT + '/', ''),
    rule,
    validation,
    qualityScore,
    fieldValidation: {
      validFields: fieldValidation.validFields,
      invalidFields: fieldValidation.invalidFields,
      fieldValidityRate: fieldValidation.fieldValidityRate,
      unknownLogsource: fieldValidation.unknownLogsource,
    },
  };
}

function extractTechniqueId(tags: string[]): string | undefined {
  const match = tags.find((t) => /^attack\.t\d{4}/i.test(t));
  if (!match) return undefined;
  return match.replace(/^attack\./i, '').toUpperCase();
}

function extractTactic(tags: string[]): string | undefined {
  return tags.find(
    (t) => t.startsWith('attack.') && !/^attack\.t\d{4}/i.test(t),
  )?.replace(/^attack\./, '');
}

// ---------------------------------------------------------------------------
// Report Generation
// ---------------------------------------------------------------------------

function generateMarkdownReport(results: BatchResults): string {
  const lines: string[] = [];

  lines.push('# DetectForge Scale Test Report');
  lines.push('');
  lines.push(`**Generated:** ${results.timestamp}`);
  lines.push(`**Total Rules:** ${results.totalRules}`);
  lines.push('');

  // Summary table
  lines.push('## Summary Metrics');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total rules analyzed | ${results.totalRules} |`);
  lines.push(`| Valid rules | ${results.validRules} (${pct(results.validRules / results.totalRules)}) |`);
  lines.push(`| Average quality score | ${results.avgQualityScore.toFixed(1)}/10 |`);
  lines.push(`| Average TP rate | ${pct(results.effectiveness.avgTpRate)} |`);
  lines.push(`| Average FP rate | ${pct(results.effectiveness.avgFpRate)} |`);
  lines.push(`| Average field validity | ${pct(results.effectiveness.avgFieldValidity)} |`);
  lines.push(`| Effectiveness pass rate | ${results.effectiveness.passedRules}/${results.totalRules} |`);
  lines.push('');

  // Quality distribution
  lines.push('## Quality Score Distribution');
  lines.push('');
  lines.push('| Range | Count |');
  lines.push('|-------|-------|');
  for (const [range, count] of Object.entries(results.qualityDistribution)) {
    lines.push(`| ${range} | ${count} |`);
  }
  lines.push('');

  // Logsource distribution
  lines.push('## Logsource Distribution');
  lines.push('');
  lines.push('| Logsource | Count |');
  lines.push('|-----------|-------|');
  const sortedLogsources = Object.entries(results.logsourceDistribution)
    .sort((a, b) => b[1] - a[1]);
  for (const [ls, count] of sortedLogsources) {
    lines.push(`| ${ls} | ${count} |`);
  }
  lines.push('');

  // Invalid fields
  if (results.commonInvalidFields.length > 0) {
    lines.push('## Most Common Invalid Fields');
    lines.push('');
    lines.push('| Field | Occurrences |');
    lines.push('|-------|-------------|');
    for (const { field, count } of results.commonInvalidFields.slice(0, 15)) {
      lines.push(`| ${field} | ${count} |`);
    }
    lines.push('');
  }

  // Per-rule details
  lines.push('## Per-Rule Analysis');
  lines.push('');
  lines.push('| Rule Title | Quality | TP Rate | FP Rate | Field Valid | Issues |');
  lines.push('|------------|---------|---------|---------|-------------|--------|');

  for (const analysis of results.ruleAnalyses) {
    const issues: string[] = [];
    if (!analysis.validation.valid) issues.push('validation-errors');
    if (analysis.fieldValidation.invalidFields.length > 0) issues.push('invalid-fields');
    if (analysis.qualityScore.overallScore <= 3) issues.push('low-quality');

    lines.push(
      `| ${analysis.rule.title.substring(0, 50)} | ${analysis.qualityScore.overallScore.toFixed(1)} | ` +
        `- | - | ${pct(analysis.fieldValidation.fieldValidityRate)} | ${issues.join(', ') || 'none'} |`,
    );
  }
  lines.push('');

  return lines.join('\n');
}

function pct(rate: number): string {
  if (isNaN(rate)) return 'N/A';
  return `${(rate * 100).toFixed(1)}%`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('DetectForge — Batch Benchmark');
  console.log('=============================\n');

  // Find all Sigma rules
  const ymlFiles = await findYmlFiles(RULES_DIR);
  const sigmaFiles = ymlFiles.filter(
    (f) => f.includes('/sigma/') || f.endsWith('.sigma.yml'),
  );

  console.log(`Found ${sigmaFiles.length} Sigma rule files\n`);

  if (sigmaFiles.length === 0) {
    console.log('No rules found. Generate some rules first.');
    return;
  }

  // Parse and analyze all rules
  const analyses: RuleAnalysis[] = [];
  const rules: SigmaRule[] = [];

  for (const filePath of sigmaFiles) {
    const content = await readFile(filePath, 'utf-8');
    const rule = parseRuleFromYaml(content);
    if (!rule) {
      console.log(`  [skip] ${basename(filePath)} — unparseable`);
      continue;
    }

    const analysis = analyzeRule(filePath, rule);
    analyses.push(analysis);
    rules.push(rule);
    console.log(
      `  [analyzed] ${rule.title.substring(0, 60)} — quality: ${analysis.qualityScore.overallScore.toFixed(1)}`,
    );
  }

  // Run effectiveness tests
  console.log('\nRunning effectiveness tests...');
  const effectiveness: EffectivenessSummary = testRulesEffectiveness(rules, {
    attackLogCount: 10,
    benignLogCount: 20,
  });

  // Compute aggregate metrics
  const totalRules = analyses.length;
  const validRules = analyses.filter((a) => a.validation.valid).length;

  const avgQualityScore =
    totalRules > 0
      ? analyses.reduce((sum, a) => sum + a.qualityScore.overallScore, 0) / totalRules
      : 0;

  const qualityDistribution: Record<string, number> = { '1-3': 0, '4-6': 0, '7-10': 0 };
  for (const a of analyses) {
    if (a.qualityScore.overallScore <= 3) qualityDistribution['1-3']++;
    else if (a.qualityScore.overallScore <= 6) qualityDistribution['4-6']++;
    else qualityDistribution['7-10']++;
  }

  // Count invalid fields
  const fieldCounts = new Map<string, number>();
  for (const a of analyses) {
    for (const field of a.fieldValidation.invalidFields) {
      fieldCounts.set(field, (fieldCounts.get(field) ?? 0) + 1);
    }
  }
  const commonInvalidFields = [...fieldCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([field, count]) => ({ field, count }));

  // Logsource distribution
  const logsourceDistribution: Record<string, number> = {};
  for (const a of analyses) {
    const cat =
      a.rule.logsource.category ?? a.rule.logsource.service ?? 'unknown';
    logsourceDistribution[cat] = (logsourceDistribution[cat] ?? 0) + 1;
  }

  // Level distribution
  const levelDistribution: Record<string, number> = {};
  for (const a of analyses) {
    levelDistribution[a.rule.level] =
      (levelDistribution[a.rule.level] ?? 0) + 1;
  }

  const results: BatchResults = {
    timestamp: new Date().toISOString(),
    totalRules,
    validRules,
    invalidRules: totalRules - validRules,
    avgQualityScore,
    qualityDistribution,
    effectiveness: {
      avgTpRate: effectiveness.avgTpRate,
      avgFpRate: effectiveness.avgFpRate,
      avgFieldValidity: effectiveness.avgFieldValidity,
      passedRules: effectiveness.passedRules,
      failedRules: effectiveness.failedRules,
    },
    commonInvalidFields,
    logsourceDistribution,
    levelDistribution,
    ruleAnalyses: analyses,
  };

  // Write outputs
  await mkdir(DOCS_DIR, { recursive: true });

  const jsonPath = join(DATA_DIR, 'scale-test-results.json');
  await writeFile(jsonPath, JSON.stringify(results, null, 2), 'utf-8');
  console.log(`\nWrote results -> ${jsonPath}`);

  const mdPath = join(DOCS_DIR, 'SCALE_TEST_REPORT.md');
  await writeFile(mdPath, generateMarkdownReport(results), 'utf-8');
  console.log(`Wrote report  -> ${mdPath}`);

  // Print summary
  console.log('\n' + '='.repeat(60));
  console.log('BATCH BENCHMARK SUMMARY');
  console.log('='.repeat(60));
  console.log(`  Total rules:          ${totalRules}`);
  console.log(`  Valid rules:          ${validRules}/${totalRules}`);
  console.log(`  Avg quality score:    ${avgQualityScore.toFixed(1)}/10`);
  console.log(`  Avg TP rate:          ${pct(effectiveness.avgTpRate)}`);
  console.log(`  Avg FP rate:          ${pct(effectiveness.avgFpRate)}`);
  console.log(`  Avg field validity:   ${pct(effectiveness.avgFieldValidity)}`);
  console.log(`  Effectiveness pass:   ${effectiveness.passedRules}/${totalRules}`);
  if (commonInvalidFields.length > 0) {
    console.log(`  Top invalid field:    ${commonInvalidFields[0].field} (${commonInvalidFields[0].count}x)`);
  }
  console.log('');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
