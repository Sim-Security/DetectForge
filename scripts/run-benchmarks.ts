#!/usr/bin/env bun
/**
 * Benchmark runner for DetectForge.
 *
 * Orchestrates pipeline benchmarks against all fixture reports using
 * mocked AI responses (default) or real AI when --live is specified.
 *
 * Usage:
 *   bun scripts/run-benchmarks.ts                         # stdout markdown
 *   bun scripts/run-benchmarks.ts --output docs/BENCHMARKS.md
 *   bun scripts/run-benchmarks.ts --live                  # uses real API key from .env
 */

import { readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

// Ingestion
import { normalizeReport } from '@/ingestion/normalizer.js';

// Extraction (regex, no AI)
import { extractIocs } from '@/extraction/ioc-extractor.js';

// Validators
import { validateSigmaRule } from '@/generation/sigma/validator.js';
import { validateYaraRule } from '@/generation/yara/validator.js';
import { validateSuricataRule } from '@/generation/suricata/validator.js';

// Types
import type { ThreatReport } from '@/types/threat-report.js';
import type {
  ExtractedIOC,
  ExtractedTTP,
  AttackMappingResult,
} from '@/types/extraction.js';
import type {
  SigmaRule,
  YaraRule,
  SuricataRule,
} from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

interface CLIArgs {
  output?: string;
  live: boolean;
}

function parseCLIArgs(): CLIArgs {
  const args = process.argv.slice(2);
  const result: CLIArgs = { live: false };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && i + 1 < args.length) {
      result.output = args[i + 1];
      i++;
    } else if (args[i] === '--live') {
      result.live = true;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Fixture directory
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(import.meta.dirname ?? '.', '..');
const FIXTURE_DIR = join(PROJECT_ROOT, 'tests', 'fixtures', 'reports');

// ---------------------------------------------------------------------------
// Mock data factories — used when --live is NOT specified
// ---------------------------------------------------------------------------

function buildMockTtps(): ExtractedTTP[] {
  return [
    {
      description: 'Password spray attack targeting cloud accounts',
      tools: ['Proxy Network'],
      targetPlatforms: ['Azure AD', 'Windows'],
      artifacts: [
        { type: 'event_log', description: 'Multiple failed authentication attempts' },
      ],
      detectionOpportunities: [
        'Monitor for distributed failed logins',
      ],
      confidence: 'high',
    },
    {
      description: 'Malicious OAuth application creation for persistent access',
      tools: ['Azure AD', 'OAuth'],
      targetPlatforms: ['Azure AD', 'Microsoft 365'],
      artifacts: [
        { type: 'event_log', description: 'New OAuth application registration' },
      ],
      detectionOpportunities: [
        'Alert on new OAuth application creation from non-admin accounts',
      ],
      confidence: 'high',
    },
    {
      description: 'PowerShell execution with encoded commands',
      tools: ['PowerShell'],
      targetPlatforms: ['Windows'],
      artifacts: [
        { type: 'process', description: 'powershell.exe with encoded command' },
      ],
      detectionOpportunities: [
        'Monitor for powershell.exe with -enc or -encodedcommand flags',
      ],
      confidence: 'medium',
    },
  ];
}

function buildMockMappings(ttps: ExtractedTTP[]): AttackMappingResult[] {
  const techniques = [
    { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactic: 'Credential Access', formats: ['sigma'] as ('sigma' | 'yara' | 'suricata')[] },
    { id: 'T1098.003', name: 'Account Manipulation: Additional Cloud Roles', tactic: 'Persistence', formats: ['sigma'] as ('sigma' | 'yara' | 'suricata')[] },
    { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', formats: ['sigma', 'yara'] as ('sigma' | 'yara' | 'suricata')[] },
  ];

  return techniques.map((t, idx) => ({
    techniqueId: t.id,
    techniqueName: t.name,
    tactic: t.tactic,
    confidence: 'high' as const,
    reasoning: `Mapped from TTP: ${ttps[idx % ttps.length].description}`,
    sourceTtp: ttps[idx % ttps.length],
    suggestedRuleFormats: t.formats,
    validated: true,
  }));
}

function buildMockSigmaRules(
  mappings: AttackMappingResult[],
): SigmaRule[] {
  return mappings
    .filter((m) => m.suggestedRuleFormats.includes('sigma'))
    .map((m) => ({
      id: randomUUID(),
      title: `DetectForge - ${m.techniqueName} Detection`,
      status: 'experimental' as const,
      description: `Detects ${m.techniqueName} (${m.techniqueId}) activity.`,
      references: [],
      author: 'DetectForge',
      date: '2026/02/10',
      modified: '2026/02/10',
      tags: [
        `attack.${m.tactic.toLowerCase().replace(/\s+/g, '_')}`,
        `attack.${m.techniqueId.toLowerCase()}`,
      ],
      logsource: { product: 'windows', category: 'process_creation' },
      detection: {
        selection: { CommandLine: ['*encoded*'] },
        condition: 'selection',
      },
      falsepositives: ['Legitimate administrative scripts'],
      level: 'high' as const,
      raw: '',
    }));
}

function buildMockYaraRules(
  mappings: AttackMappingResult[],
): YaraRule[] {
  const hasYara = mappings.some((m) => m.suggestedRuleFormats.includes('yara'));
  if (!hasYara) return [];

  return [
    {
      name: 'DetectForge_Payload_Detection',
      tags: ['malware'],
      meta: {
        description: 'Detects malicious payload indicators',
        author: 'DetectForge',
        date: '2026-02-10',
        reference: 'https://detectforge.local/report',
        mitre_attack: 'T1059.001',
      },
      strings: [
        { identifier: '$s1', value: '-EncodedCommand', type: 'text', modifiers: ['ascii', 'nocase'] },
        { identifier: '$s2', value: 'Invoke-Expression', type: 'text', modifiers: ['ascii'] },
      ],
      condition: 'filesize < 5MB and any of ($s*)',
      raw: [
        'rule DetectForge_Payload_Detection : malware {',
        '    meta:',
        '        description = "Detects malicious payload indicators"',
        '        author = "DetectForge"',
        '        date = "2026-02-10"',
        '        reference = "https://detectforge.local/report"',
        '        mitre_attack = "T1059.001"',
        '    strings:',
        '        $s1 = "-EncodedCommand" ascii nocase',
        '        $s2 = "Invoke-Expression" ascii',
        '    condition:',
        '        filesize < 5MB and any of ($s*)',
        '}',
      ].join('\n'),
    },
  ];
}

function buildMockSuricataRules(
  iocs: ExtractedIOC[],
  mappings: AttackMappingResult[],
): SuricataRule[] {
  const networkIocs = iocs.filter((i) => ['ipv4', 'domain', 'url'].includes(i.type));
  const hasSuricata = mappings.some((m) => m.suggestedRuleFormats.includes('suricata'));
  if (networkIocs.length === 0 && !hasSuricata) return [];

  // Generate one Suricata rule per network IOC (up to 3)
  return networkIocs.slice(0, 3).map((ioc, idx) => {
    const sid = 9_000_001 + idx;
    const msg = `"DetectForge - C2 traffic to ${ioc.value}"`;
    return {
      action: 'alert' as const,
      protocol: 'tcp',
      sourceIp: '$HOME_NET',
      sourcePort: 'any',
      direction: '->' as const,
      destIp: '$EXTERNAL_NET',
      destPort: 'any',
      options: [
        { keyword: 'msg', value: msg },
        { keyword: 'flow', value: 'established,to_server' },
        { keyword: 'content', value: `"${ioc.value}"` },
        { keyword: 'metadata', value: 'mitre_attack T1071.001' },
        { keyword: 'classtype', value: 'trojan-activity' },
        { keyword: 'sid', value: String(sid) },
        { keyword: 'rev', value: '1' },
      ],
      sid,
      rev: 1,
      raw: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:${msg}; flow:established,to_server; content:"${ioc.value}"; metadata:mitre_attack T1071.001; classtype:trojan-activity; sid:${sid}; rev:1;)`,
    };
  });
}

// ---------------------------------------------------------------------------
// Report result type
// ---------------------------------------------------------------------------

interface ReportBenchmark {
  name: string;
  iocCount: number;
  ttpCount: number;
  sigmaCount: number;
  yaraCount: number;
  suricataCount: number;
  validCount: number;
  totalCount: number;
  validationPassRate: number;
  processingTimeMs: number;
}

// ---------------------------------------------------------------------------
// Pipeline runner
// ---------------------------------------------------------------------------

async function runMockPipeline(filepath: string): Promise<ReportBenchmark> {
  const start = performance.now();
  const filename = filepath.split('/').pop() ?? 'unknown';
  const reportName = filename.replace('.md', '').replace(/-/g, ' ');

  // Step 1: Ingest
  const markdown = readFileSync(filepath, 'utf-8');
  const report = await normalizeReport(markdown, { filename, format: 'markdown' });

  // Step 2: Extract IOCs (regex)
  const iocs = extractIocs(report.rawText);

  // Step 3: Mock TTP extraction
  const ttps = buildMockTtps();

  // Step 4: Mock ATT&CK mapping
  const mappings = buildMockMappings(ttps);

  // Step 5: Mock rule generation
  const sigmaRules = buildMockSigmaRules(mappings);
  const yaraRules = buildMockYaraRules(mappings);
  const suricataRules = buildMockSuricataRules(iocs, mappings);

  // Step 6: Validate
  const sigmaValid = sigmaRules.filter((r) => validateSigmaRule(r).valid).length;
  const yaraValid = yaraRules.filter((r) => validateYaraRule(r).valid).length;
  const suricataValid = suricataRules.filter((r) => validateSuricataRule(r).valid).length;

  const totalCount = sigmaRules.length + yaraRules.length + suricataRules.length;
  const validCount = sigmaValid + yaraValid + suricataValid;

  const elapsed = performance.now() - start;

  return {
    name: reportName,
    iocCount: iocs.length,
    ttpCount: ttps.length,
    sigmaCount: sigmaRules.length,
    yaraCount: yaraRules.length,
    suricataCount: suricataRules.length,
    validCount,
    totalCount,
    validationPassRate: totalCount > 0 ? (validCount / totalCount) * 100 : 0,
    processingTimeMs: elapsed,
  };
}

// ---------------------------------------------------------------------------
// Markdown report generation
// ---------------------------------------------------------------------------

function generateMarkdownReport(results: ReportBenchmark[]): string {
  const now = new Date().toISOString().split('T')[0];
  const lines: string[] = [];

  lines.push('# DetectForge Benchmark Results');
  lines.push('');
  lines.push(`> Generated on ${now} using mock AI pipeline.`);
  lines.push('');

  // Summary table
  lines.push('## Report Processing Summary');
  lines.push('');
  lines.push('| Report | IOCs | TTPs | Sigma | YARA | Suricata | Valid | Time |');
  lines.push('|--------|------|------|-------|------|----------|-------|------|');

  let totalIocs = 0;
  let totalTtps = 0;
  let totalSigma = 0;
  let totalYara = 0;
  let totalSuricata = 0;
  let totalValid = 0;
  let totalRules = 0;
  let totalTimeMs = 0;

  for (const r of results) {
    const pct = r.validationPassRate.toFixed(0) + '%';
    const time = (r.processingTimeMs / 1000).toFixed(2) + 's';
    lines.push(
      `| ${r.name} | ${r.iocCount} | ${r.ttpCount} | ${r.sigmaCount} | ${r.yaraCount} | ${r.suricataCount} | ${pct} | ${time} |`,
    );
    totalIocs += r.iocCount;
    totalTtps += r.ttpCount;
    totalSigma += r.sigmaCount;
    totalYara += r.yaraCount;
    totalSuricata += r.suricataCount;
    totalValid += r.validCount;
    totalRules += r.totalCount;
    totalTimeMs += r.processingTimeMs;
  }

  const overallPct = totalRules > 0 ? ((totalValid / totalRules) * 100).toFixed(0) : '0';
  const totalTime = (totalTimeMs / 1000).toFixed(2) + 's';
  lines.push(
    `| **Total** | **${totalIocs}** | **${totalTtps}** | **${totalSigma}** | **${totalYara}** | **${totalSuricata}** | **${overallPct}%** | **${totalTime}** |`,
  );
  lines.push('');

  // Quality metrics
  lines.push('## Quality Metrics');
  lines.push('');
  lines.push(`- **Total rules generated**: ${totalRules}`);
  lines.push(`- **Validation pass rate**: ${overallPct}%`);
  lines.push(`- **Total IOCs extracted**: ${totalIocs}`);
  lines.push(`- **Average IOCs per report**: ${results.length > 0 ? (totalIocs / results.length).toFixed(1) : 0}`);
  lines.push(`- **Average processing time**: ${results.length > 0 ? (totalTimeMs / results.length / 1000).toFixed(3) : 0}s`);
  lines.push('');

  // Format breakdown
  lines.push('## Rule Format Distribution');
  lines.push('');
  lines.push(`| Format | Count | Percentage |`);
  lines.push(`|--------|-------|------------|`);
  if (totalRules > 0) {
    lines.push(`| Sigma | ${totalSigma} | ${((totalSigma / totalRules) * 100).toFixed(0)}% |`);
    lines.push(`| YARA | ${totalYara} | ${((totalYara / totalRules) * 100).toFixed(0)}% |`);
    lines.push(`| Suricata | ${totalSuricata} | ${((totalSuricata / totalRules) * 100).toFixed(0)}% |`);
  }
  lines.push('');

  // Coverage analysis
  lines.push('## Coverage Analysis');
  lines.push('');
  lines.push('### IOC Type Distribution');
  lines.push('');
  lines.push('IOC extraction is performed using regex patterns. The distribution across');
  lines.push('reports reflects the indicator types documented in each threat report.');
  lines.push('');

  // Per-report IOC counts
  for (const r of results) {
    lines.push(`- **${r.name}**: ${r.iocCount} IOCs extracted`);
  }
  lines.push('');

  lines.push('---');
  lines.push('');
  lines.push('*Benchmarks generated by DetectForge Sprint 5 pipeline.*');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseCLIArgs();
  const pipelineStart = performance.now();

  console.log('[run-benchmarks] Starting DetectForge benchmark suite...');

  if (args.live) {
    console.log('[run-benchmarks] --live flag detected. Live AI mode is not yet implemented in Sprint 5.');
    console.log('[run-benchmarks] Falling back to mock pipeline.');
  }

  // Discover fixture reports
  const fixtureFiles = readdirSync(FIXTURE_DIR)
    .filter((f) => f.endsWith('.md'))
    .sort()
    .map((f) => join(FIXTURE_DIR, f));

  if (fixtureFiles.length === 0) {
    console.error('[run-benchmarks] No fixture reports found in', FIXTURE_DIR);
    process.exit(1);
  }

  console.log(`[run-benchmarks] Found ${fixtureFiles.length} fixture reports.`);

  // Run benchmarks
  const results: ReportBenchmark[] = [];

  for (const filepath of fixtureFiles) {
    const name = filepath.split('/').pop() ?? 'unknown';
    console.log(`[run-benchmarks] Processing: ${name}`);

    const result = await runMockPipeline(filepath);
    results.push(result);

    console.log(
      `  -> IOCs: ${result.iocCount}, TTPs: ${result.ttpCount}, ` +
        `Rules: ${result.totalCount} (${result.validationPassRate.toFixed(0)}% valid), ` +
        `Time: ${(result.processingTimeMs / 1000).toFixed(3)}s`,
    );
  }

  const totalElapsed = performance.now() - pipelineStart;
  console.log(`\n[run-benchmarks] All benchmarks complete in ${(totalElapsed / 1000).toFixed(2)}s.`);

  // Generate markdown report
  const markdown = generateMarkdownReport(results);

  if (args.output) {
    const outPath = resolve(PROJECT_ROOT, args.output);
    const outDir = dirname(outPath);
    if (!existsSync(outDir)) {
      mkdirSync(outDir, { recursive: true });
    }
    writeFileSync(outPath, markdown, 'utf-8');
    console.log(`[run-benchmarks] Report written to: ${outPath}`);
  } else {
    console.log('\n' + markdown);
  }
}

main().catch((err) => {
  console.error('[run-benchmarks] Fatal error:', err);
  process.exit(1);
});
