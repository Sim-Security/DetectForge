/**
 * Human-readable Markdown report generator.
 *
 * Transforms the complete pipeline output into a well-structured
 * Markdown document suitable for viewing in GitHub, GitLab, or any
 * Markdown renderer.
 */

import type { PipelineReport } from '@/reporting/json-reporter.js';
import type { GeneratedRule } from '@/types/detection-rule.js';
import type { ExtractedIOC } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface MarkdownReportOptions {
  /** Include raw rule text in the report. Default: true */
  includeRuleContent?: boolean;
  /** Include false positive analysis section. Default: true */
  includeFPAnalysis?: boolean;
  /** Include ATT&CK coverage analysis section. Default: true */
  includeCoverage?: boolean;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a complete Markdown report from pipeline data.
 *
 * @param data    - The complete pipeline report.
 * @param options - Optional rendering options.
 * @returns A Markdown-formatted string.
 */
export function generateMarkdownReport(
  data: PipelineReport,
  options?: MarkdownReportOptions,
): string {
  const opts: Required<MarkdownReportOptions> = {
    includeRuleContent: options?.includeRuleContent ?? true,
    includeFPAnalysis: options?.includeFPAnalysis ?? true,
    includeCoverage: options?.includeCoverage ?? true,
  };

  const sections: string[] = [];

  sections.push(renderTitle());
  sections.push(renderExecutiveSummary(data));
  sections.push(renderExtractionResults(data));
  sections.push(renderGeneratedRules(data, opts));
  sections.push(renderValidationResults(data));

  if (data.quality) {
    sections.push(renderQualityAssessment(data));
  }

  if (opts.includeCoverage && data.coverage) {
    sections.push(renderAttackCoverage(data));
  }

  sections.push(renderCostSummary(data));
  sections.push(renderFooter(data));

  return sections.join('\n\n');
}

// ---------------------------------------------------------------------------
// Section Renderers
// ---------------------------------------------------------------------------

function renderTitle(): string {
  return '# DetectForge Analysis Report';
}

function renderExecutiveSummary(data: PipelineReport): string {
  const lines: string[] = ['## Executive Summary', ''];
  lines.push(`| Property | Value |`);
  lines.push(`| --- | --- |`);
  lines.push(`| **Input File** | \`${data.metadata.inputFile}\` |`);
  lines.push(`| **Generated At** | ${data.metadata.generatedAt} |`);
  lines.push(`| **DetectForge Version** | ${data.metadata.detectforgeVersion} |`);
  lines.push(`| **Processing Time** | ${formatDuration(data.metadata.processingTimeMs)} |`);
  lines.push(`| **Total Rules** | ${data.validation.totalRules} |`);
  lines.push(`| **Valid Rules** | ${data.validation.validRules} (${formatPercent(data.validation.passRate)}) |`);
  lines.push(`| **Invalid Rules** | ${data.validation.invalidRules} |`);

  if (data.quality) {
    lines.push(`| **Average Quality Score** | ${data.quality.averageScore}/10 |`);
  }

  if (data.coverage) {
    lines.push(`| **ATT&CK Coverage** | ${data.coverage.coveragePercentage}% (${data.coverage.coveredTechniques}/${data.coverage.totalTechniques}) |`);
  }

  lines.push(`| **Total API Cost** | $${data.cost.totalUsd.toFixed(4)} |`);

  return lines.join('\n');
}

function renderExtractionResults(data: PipelineReport): string {
  const lines: string[] = ['## Extraction Results', ''];

  // IOC Summary
  lines.push('### IOC Summary', '');

  if (data.extraction.iocs.length === 0) {
    lines.push('No IOCs extracted.');
  } else {
    const iocsByType = groupIOCsByType(data.extraction.iocs);

    lines.push('| Type | Count | Examples |');
    lines.push('| --- | ---: | --- |');

    for (const [type, iocs] of Object.entries(iocsByType)) {
      const examples = iocs
        .slice(0, 3)
        .map(i => `\`${i.value}\``)
        .join(', ');
      const suffix = iocs.length > 3 ? ', ...' : '';
      lines.push(`| ${type} | ${iocs.length} | ${examples}${suffix} |`);
    }
  }

  lines.push('');

  // TTP Summary
  lines.push('### TTP Summary', '');

  if (data.extraction.ttps.length === 0) {
    lines.push('No TTPs extracted.');
  } else {
    for (const ttp of data.extraction.ttps) {
      const tools = ttp.tools.length > 0 ? ttp.tools.join(', ') : 'N/A';
      lines.push(`- **${ttp.description}**`);
      lines.push(`  - Tools: ${tools}`);
      lines.push(`  - Platforms: ${ttp.targetPlatforms.join(', ') || 'N/A'}`);
      lines.push(`  - Confidence: ${ttp.confidence}`);
    }
  }

  lines.push('');

  // ATT&CK Mappings
  if (data.extraction.attackMappings.length > 0) {
    lines.push('### ATT&CK Mappings', '');
    lines.push('| Technique ID | Name | Tactic | Confidence | Validated |');
    lines.push('| --- | --- | --- | --- | --- |');

    for (const mapping of data.extraction.attackMappings) {
      const validated = mapping.validated ? 'Yes' : 'No';
      lines.push(
        `| ${mapping.techniqueId} | ${mapping.techniqueName} | ${mapping.tactic} | ${mapping.confidence} | ${validated} |`,
      );
    }
  }

  return lines.join('\n');
}

function renderGeneratedRules(
  data: PipelineReport,
  opts: Required<MarkdownReportOptions>,
): string {
  const lines: string[] = ['## Generated Rules', ''];

  const sigmaRules = data.rules.filter(r => r.format === 'sigma');
  const yaraRules = data.rules.filter(r => r.format === 'yara');
  const suricataRules = data.rules.filter(r => r.format === 'suricata');

  if (sigmaRules.length > 0) {
    lines.push('### Sigma Rules', '');
    for (const rule of sigmaRules) {
      lines.push(...renderSingleRule(rule, opts));
    }
  }

  if (yaraRules.length > 0) {
    lines.push('### YARA Rules', '');
    for (const rule of yaraRules) {
      lines.push(...renderSingleRule(rule, opts));
    }
  }

  if (suricataRules.length > 0) {
    lines.push('### Suricata Rules', '');
    for (const rule of suricataRules) {
      lines.push(...renderSingleRule(rule, opts));
    }
  }

  if (data.rules.length === 0) {
    lines.push('No rules were generated.');
  }

  return lines.join('\n');
}

function renderSingleRule(
  rule: GeneratedRule,
  opts: Required<MarkdownReportOptions>,
): string[] {
  const lines: string[] = [];
  const title = getRuleTitle(rule);
  const description = getRuleDescription(rule);
  const validIcon = rule.validation.valid ? '\\u2705' : '\\u274c';

  lines.push(`#### ${title}`, '');
  lines.push(`- **Description:** ${description}`);
  lines.push(`- **Format:** ${rule.format}`);
  lines.push(`- **Confidence:** ${rule.confidence}`);
  lines.push(`- **Validation:** ${validIcon} ${rule.validation.valid ? 'Valid' : 'Invalid'}`);

  if (rule.attackTechniqueId) {
    lines.push(`- **ATT&CK Technique:** ${rule.attackTechniqueId}${rule.attackTactic ? ` (${rule.attackTactic})` : ''}`);
  }

  if (rule.validation.errors.length > 0) {
    lines.push(`- **Errors:** ${rule.validation.errors.join('; ')}`);
  }

  if (rule.validation.warnings.length > 0) {
    lines.push(`- **Warnings:** ${rule.validation.warnings.join('; ')}`);
  }

  if (opts.includeRuleContent) {
    const raw = getRuleRaw(rule);
    if (raw) {
      const lang = rule.format === 'sigma' ? 'yaml' : rule.format === 'yara' ? 'yara' : '';
      lines.push('', `\`\`\`${lang}`, raw, '```');
    }
  }

  if (opts.includeFPAnalysis && rule.documentation?.falsePositives) {
    const fps = rule.documentation.falsePositives;
    if (fps.length > 0) {
      lines.push('', '**False Positive Analysis:**', '');
      for (const fp of fps) {
        lines.push(`- **${fp.scenario}** (likelihood: ${fp.likelihood})`);
        lines.push(`  - Tuning: ${fp.tuningAdvice}`);
      }
    }
  }

  lines.push('');
  return lines;
}

function renderValidationResults(data: PipelineReport): string {
  const lines: string[] = ['## Validation Results', ''];

  lines.push('| Rule | Format | Valid | Errors |');
  lines.push('| --- | --- | --- | --- |');

  for (const rule of data.rules) {
    const title = getRuleTitle(rule);
    const valid = rule.validation.valid ? 'Yes' : 'No';
    const errors = rule.validation.errors.length > 0
      ? rule.validation.errors.join('; ')
      : '-';
    lines.push(`| ${title} | ${rule.format} | ${valid} | ${errors} |`);
  }

  lines.push('');
  lines.push(`**Pass Rate:** ${formatPercent(data.validation.passRate)} (${data.validation.validRules}/${data.validation.totalRules})`);

  return lines.join('\n');
}

function renderQualityAssessment(data: PipelineReport): string {
  const lines: string[] = ['## Quality Assessment', ''];

  if (!data.quality) {
    lines.push('Quality assessment was not performed.');
    return lines.join('\n');
  }

  lines.push(`**Average Score:** ${data.quality.averageScore}/10`, '');

  // Score distribution
  lines.push('### Score Distribution', '');
  lines.push('| Range | Count |');
  lines.push('| --- | ---: |');

  for (const [range, count] of Object.entries(data.quality.scoreDistribution)) {
    lines.push(`| ${range} | ${count} |`);
  }

  lines.push('');

  // Per-rule breakdown
  lines.push('### Per-Rule Scores', '');
  lines.push('| Rule | Format | Overall | Syntax | Logic | Docs | ATT&CK | FP |');
  lines.push('| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |');

  for (const score of data.quality.perRuleScores) {
    const d = score.dimensions;
    lines.push(
      `| ${score.ruleId} | ${score.format} | ${score.overallScore} | ${d.syntaxValidity} | ${d.detectionLogic} | ${d.documentation} | ${d.attackMapping} | ${d.falsePosHandling} |`,
    );
  }

  // Recommendations
  if (data.quality.recommendations.length > 0) {
    lines.push('');
    lines.push('### Recommendations', '');
    for (const rec of data.quality.recommendations) {
      lines.push(`- ${rec}`);
    }
  }

  return lines.join('\n');
}

function renderAttackCoverage(data: PipelineReport): string {
  const lines: string[] = ['## ATT&CK Coverage', ''];

  if (!data.coverage) {
    lines.push('Coverage analysis was not performed.');
    return lines.join('\n');
  }

  lines.push(
    `**Overall Coverage:** ${data.coverage.coveragePercentage}% (${data.coverage.coveredTechniques}/${data.coverage.totalTechniques} techniques)`,
    '',
  );

  // Tactic breakdown table
  lines.push('### Coverage by Tactic', '');
  lines.push('| Tactic | Covered | Total | Percentage |');
  lines.push('| --- | ---: | ---: | ---: |');

  for (const [tactic, breakdown] of Object.entries(data.coverage.tacticBreakdown)) {
    lines.push(
      `| ${tactic} | ${breakdown.covered} | ${breakdown.total} | ${breakdown.percentage}% |`,
    );
  }

  // Uncovered techniques
  if (data.coverage.uncoveredTechniqueIds.length > 0) {
    lines.push('');
    lines.push('### Uncovered Techniques', '');
    for (const id of data.coverage.uncoveredTechniqueIds) {
      lines.push(`- ${id}`);
    }
  }

  return lines.join('\n');
}

function renderCostSummary(data: PipelineReport): string {
  const lines: string[] = ['## Cost Summary', ''];

  lines.push(`**Total Cost:** $${data.cost.totalUsd.toFixed(4)}`, '');

  const operations = Object.entries(data.cost.byOperation);
  if (operations.length > 0) {
    lines.push('| Operation | Cost |');
    lines.push('| --- | ---: |');

    for (const [operation, cost] of operations) {
      lines.push(`| ${operation} | $${cost.toFixed(4)} |`);
    }
  }

  return lines.join('\n');
}

function renderFooter(data: PipelineReport): string {
  const lines: string[] = [
    '---',
    '',
    `*Generated by DetectForge v${data.metadata.detectforgeVersion} on ${data.metadata.generatedAt}*`,
  ];
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getRuleTitle(rule: GeneratedRule): string {
  if (rule.format === 'sigma' && rule.sigma) return rule.sigma.title;
  if (rule.format === 'yara' && rule.yara) return rule.yara.name;
  if (rule.format === 'suricata' && rule.suricata) return `SID:${rule.suricata.sid}`;
  return `${rule.format}-unknown`;
}

function getRuleDescription(rule: GeneratedRule): string {
  if (rule.format === 'sigma' && rule.sigma) return rule.sigma.description;
  if (rule.format === 'yara' && rule.yara) return rule.yara.meta.description;
  if (rule.format === 'suricata' && rule.suricata) {
    const msgOpt = rule.suricata.options.find(o => o.keyword === 'msg');
    return msgOpt?.value ?? 'Suricata rule';
  }
  return 'No description available';
}

function getRuleRaw(rule: GeneratedRule): string | undefined {
  if (rule.format === 'sigma' && rule.sigma) return rule.sigma.raw;
  if (rule.format === 'yara' && rule.yara) return rule.yara.raw;
  if (rule.format === 'suricata' && rule.suricata) return rule.suricata.raw;
  return undefined;
}

function groupIOCsByType(iocs: ExtractedIOC[]): Record<string, ExtractedIOC[]> {
  const grouped: Record<string, ExtractedIOC[]> = {};
  for (const ioc of iocs) {
    const type = ioc.type;
    if (!grouped[type]) {
      grouped[type] = [];
    }
    grouped[type].push(ioc);
  }
  return grouped;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatPercent(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}
