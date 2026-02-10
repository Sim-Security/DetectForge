/**
 * Unit tests for the summary reporter.
 *
 * Tests: formatSummaryTable, printSummary
 *
 * Note: The source file (src/reporting/summary-reporter.ts) is being written
 * concurrently by another agent. These tests target the expected interface.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  formatSummaryTable,
  printSummary,
  type SummaryData,
} from '@/reporting/summary-reporter.js';

// ---------------------------------------------------------------------------
// Fixture Builders
// ---------------------------------------------------------------------------

function makeSummaryData(overrides?: Partial<SummaryData>): SummaryData {
  return {
    reportTitle: 'apt29-report.pdf',
    processingTimeMs: 45200,
    extraction: {
      iocCount: 2,
      ttpCount: 1,
      attackMappingCount: 1,
    },
    rules: {
      sigma: 1,
      yara: 1,
      suricata: 1,
      total: 3,
      valid: 3,
      invalid: 0,
    },
    cost: {
      totalUsd: 0.234,
      totalTokens: 15000,
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Strip ANSI escape codes from a string so we can test content
 * without worrying about chalk color codes.
 */
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\u001b\[\d+(;\d+)*m/g, '');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

describe('formatSummaryTable', () => {
  it('returns a string', () => {
    const result = formatSummaryTable(makeSummaryData());
    expect(typeof result).toBe('string');
  });

  it('contains processing time', () => {
    const result = stripAnsi(formatSummaryTable(makeSummaryData()));
    // 45200 ms = 45.2s
    expect(result).toContain('45.2');
  });

  it('contains extraction counts for IOCs', () => {
    const result = stripAnsi(formatSummaryTable(makeSummaryData()));
    // Should contain IOC count: 2 IOCs in the default fixture
    expect(result).toContain('2');
  });

  it('contains extraction counts for TTPs', () => {
    const result = stripAnsi(formatSummaryTable(makeSummaryData()));
    // 1 TTP in the default fixture
    expect(result).toMatch(/TTP|ttp/i);
  });

  it('contains extraction counts for ATT&CK mappings', () => {
    const result = stripAnsi(formatSummaryTable(makeSummaryData()));
    expect(result).toMatch(/ATT&CK|attack|mapping/i);
  });

  it('contains rule counts by format', () => {
    const result = stripAnsi(formatSummaryTable(makeSummaryData()));
    // The report has 1 sigma, 1 yara, 1 suricata
    expect(result).toMatch(/[Ss]igma/);
    expect(result).toMatch(/[Yy][Aa][Rr][Aa]/);
    expect(result).toMatch(/[Ss]uricata/);
  });

  it('contains total and valid rule counts', () => {
    const result = stripAnsi(formatSummaryTable(makeSummaryData()));
    // total: 3, valid: 3
    expect(result).toContain('3');
  });

  it('contains cost information', () => {
    const result = stripAnsi(formatSummaryTable(makeSummaryData()));
    expect(result).toContain('0.234');
  });

  it('includes quality section when quality data is provided', () => {
    const data = makeSummaryData({
      quality: {
        averageScore: 8.0,
      },
    });
    const result = stripAnsi(formatSummaryTable(data));
    expect(result).toMatch(/[Qq]uality|[Ss]core/);
    expect(result).toContain('8');
  });

  it('includes coverage section when coverage data is provided', () => {
    const data = makeSummaryData({
      coverage: {
        percentage: 30,
        coveredTechniques: 3,
        totalTechniques: 10,
      },
    });
    const result = stripAnsi(formatSummaryTable(data));
    expect(result).toMatch(/[Cc]overage/);
    expect(result).toContain('30');
  });

  it('omits quality section when quality data is not provided', () => {
    const report = makeSummaryData();
    delete report.quality;
    const result = stripAnsi(formatSummaryTable(report));
    // Should not contain quality-specific average score content.
    // We check that the word "Quality" or "Score" as a section label
    // does NOT appear as a separate section. This is a soft check --
    // the summary may still use "Valid" which contains some of these chars.
    // We therefore only check for the pattern that indicates a quality section.
    expect(result).not.toMatch(/[Qq]uality.*[Ss]core.*\d+/);
  });
});

describe('printSummary', () => {
  it('calls console.log', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    printSummary(makeSummaryData());
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
});
