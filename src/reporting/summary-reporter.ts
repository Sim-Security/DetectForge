/**
 * Terminal summary table renderer.
 *
 * Produces a formatted, colorized terminal summary of a DetectForge
 * pipeline run using box-drawing characters and chalk colors. Designed
 * to be printed directly to stdout at the end of a pipeline execution.
 */

import chalk from 'chalk';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface SummaryData {
  reportTitle: string;
  processingTimeMs: number;
  extraction: {
    iocCount: number;
    ttpCount: number;
    attackMappingCount: number;
  };
  rules: {
    sigma: number;
    yara: number;
    suricata: number;
    total: number;
    valid: number;
    invalid: number;
  };
  quality?: {
    averageScore: number;
  };
  coverage?: {
    percentage: number;
    coveredTechniques: number;
    totalTechniques: number;
  };
  cost: {
    totalUsd: number;
    totalTokens: number;
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Fixed width of the summary box interior (between the box edges). */
const BOX_WIDTH = 50;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Format the summary data into a colorized terminal table string.
 *
 * Uses Unicode box-drawing characters for the frame and chalk colors
 * for visual emphasis:
 * - Cyan for section headers
 * - Green for pass rates >= 90%
 * - Yellow for pass rates 70-89%
 * - Red for pass rates < 70%
 *
 * @param data - Summary data from the pipeline run.
 * @returns A formatted string ready for terminal output.
 */
export function formatSummaryTable(data: SummaryData): string {
  const lines: string[] = [];

  // Top border
  lines.push(chalk.cyan(`\u2554${''.padStart(BOX_WIDTH, '\u2550')}\u2557`));

  // Title
  lines.push(formatCenteredLine('DetectForge Analysis Summary', true));

  // Separator
  lines.push(chalk.cyan(`\u2560${''.padStart(BOX_WIDTH, '\u2550')}\u2563`));

  // Report metadata
  lines.push(formatLine(`Report: ${data.reportTitle}`));
  lines.push(formatLine(`Processing Time: ${formatDuration(data.processingTimeMs)}`));

  // Separator
  lines.push(chalk.cyan(`\u2560${''.padStart(BOX_WIDTH, '\u2550')}\u2563`));

  // Extraction section
  lines.push(formatSectionHeader('EXTRACTION'));
  lines.push(
    formatLine(
      `  IOCs: ${data.extraction.iocCount}  \u2502  TTPs: ${data.extraction.ttpCount}  \u2502  ATT&CK Mappings: ${data.extraction.attackMappingCount}`,
    ),
  );

  // Separator
  lines.push(chalk.cyan(`\u2560${''.padStart(BOX_WIDTH, '\u2550')}\u2563`));

  // Rules section
  lines.push(formatSectionHeader('RULES GENERATED'));
  lines.push(
    formatLine(
      `  Sigma: ${data.rules.sigma}  \u2502  YARA: ${data.rules.yara}  \u2502  Suricata: ${data.rules.suricata}`,
    ),
  );

  const passRate = data.rules.total > 0
    ? (data.rules.valid / data.rules.total) * 100
    : 0;
  const passRateStr = `${passRate.toFixed(1)}%`;
  const coloredPassRate = colorizeByRate(passRateStr, passRate);
  lines.push(
    formatLineRaw(
      `  Total: ${data.rules.total}  \u2502  Valid: ${data.rules.valid} (${coloredPassRate})`,
    ),
  );

  // Quality and coverage section (conditional)
  if (data.quality || data.coverage) {
    lines.push(chalk.cyan(`\u2560${''.padStart(BOX_WIDTH, '\u2550')}\u2563`));
    lines.push(formatSectionHeader('QUALITY'));

    if (data.quality) {
      const scoreStr = `${data.quality.averageScore.toFixed(1)}/10`;
      const scoreRate = (data.quality.averageScore / 10) * 100;
      const coloredScore = colorizeByRate(scoreStr, scoreRate);
      lines.push(formatLineRaw(`  Average Score: ${coloredScore}`));
    }

    if (data.coverage) {
      const covStr = `${data.coverage.percentage.toFixed(0)}% (${data.coverage.coveredTechniques}/${data.coverage.totalTechniques} techniques)`;
      const coloredCov = colorizeByRate(covStr, data.coverage.percentage);
      lines.push(formatLineRaw(`  Coverage: ${coloredCov}`));
    }
  }

  // Separator
  lines.push(chalk.cyan(`\u2560${''.padStart(BOX_WIDTH, '\u2550')}\u2563`));

  // Cost section
  lines.push(formatSectionHeader('COST'));
  lines.push(
    formatLine(
      `  Total: $${data.cost.totalUsd.toFixed(3)}  \u2502  Tokens: ${formatNumber(data.cost.totalTokens)}`,
    ),
  );

  // Bottom border
  lines.push(chalk.cyan(`\u255a${''.padStart(BOX_WIDTH, '\u2550')}\u255d`));

  return lines.join('\n');
}

/**
 * Print the formatted summary table to stdout.
 *
 * @param data - Summary data from the pipeline run.
 */
export function printSummary(data: SummaryData): void {
  console.log(formatSummaryTable(data));
}

// ---------------------------------------------------------------------------
// Formatting Helpers
// ---------------------------------------------------------------------------

/**
 * Format a line of text padded within the box borders.
 * Text is left-aligned with padding to fill the box width.
 */
function formatLine(text: string): string {
  const padded = text.padEnd(BOX_WIDTH - 2);
  return `${chalk.cyan('\u2551')} ${padded} ${chalk.cyan('\u2551')}`;
}

/**
 * Format a line that may contain chalk-colored segments.
 *
 * Since chalk adds invisible ANSI escape codes, we cannot rely on
 * `.length` for padding. Instead, we compute padding from the
 * "visible" (strip-ANSI) length.
 */
function formatLineRaw(text: string): string {
  const visibleLen = stripAnsi(text).length;
  const paddingNeeded = BOX_WIDTH - 2 - visibleLen;
  const padding = paddingNeeded > 0 ? ' '.repeat(paddingNeeded) : '';
  return `${chalk.cyan('\u2551')} ${text}${padding} ${chalk.cyan('\u2551')}`;
}

/**
 * Format a centered line within the box.
 */
function formatCenteredLine(text: string, isBold: boolean = false): string {
  const totalPadding = BOX_WIDTH - 2 - text.length;
  const leftPad = Math.floor(totalPadding / 2);
  const rightPad = totalPadding - leftPad;
  const padded = ' '.repeat(leftPad) + text + ' '.repeat(rightPad);
  const styled = isBold ? chalk.bold.white(padded) : padded;
  return `${chalk.cyan('\u2551')} ${styled} ${chalk.cyan('\u2551')}`;
}

/**
 * Format a section header line (cyan, bold).
 */
function formatSectionHeader(text: string): string {
  const padded = text.padEnd(BOX_WIDTH - 2);
  return `${chalk.cyan('\u2551')} ${chalk.cyan.bold(padded)} ${chalk.cyan('\u2551')}`;
}

/**
 * Colorize a value string based on a percentage rate.
 * Green >= 90%, Yellow 70-89%, Red < 70%.
 */
function colorizeByRate(text: string, rate: number): string {
  if (rate >= 90) return chalk.green(text);
  if (rate >= 70) return chalk.yellow(text);
  return chalk.red(text);
}

/**
 * Format a processing duration from milliseconds to a human-readable string.
 */
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

/**
 * Format a number with thousands separators.
 */
function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

/**
 * Strip ANSI escape codes from a string to get its visible length.
 */
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*m/g, '');
}
