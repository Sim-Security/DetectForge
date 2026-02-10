/**
 * Machine-readable JSON report generator.
 *
 * Produces a comprehensive JSON document containing the full pipeline
 * output: extraction results, generated rules, validation summary,
 * quality assessment, ATT&CK coverage, and API cost breakdown.
 */

import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';

import type { GeneratedRule } from '@/types/detection-rule.js';
import type {
  ExtractedIOC,
  ExtractedTTP,
  AttackMappingResult,
} from '@/types/extraction.js';
import type { QualityReport } from '@/testing/quality-scorer.js';
import type { CoverageMetrics } from '@/testing/coverage-metrics.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface PipelineReport {
  metadata: {
    generatedAt: string;
    detectforgeVersion: string;
    inputFile: string;
    processingTimeMs: number;
  };
  extraction: {
    iocs: ExtractedIOC[];
    ttps: ExtractedTTP[];
    attackMappings: AttackMappingResult[];
  };
  rules: GeneratedRule[];
  validation: {
    totalRules: number;
    validRules: number;
    invalidRules: number;
    passRate: number;
  };
  quality?: QualityReport;
  coverage?: CoverageMetrics;
  cost: {
    totalUsd: number;
    byOperation: Record<string, number>;
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a formatted JSON string from the pipeline report data.
 *
 * The returned string is pretty-printed with 2-space indentation for
 * human readability while remaining fully machine-parseable.
 *
 * @param data - The complete pipeline report.
 * @returns A formatted JSON string.
 */
export function generateJsonReport(data: PipelineReport): string {
  return JSON.stringify(data, null, 2);
}

/**
 * Write the pipeline report to a JSON file on disk.
 *
 * Creates parent directories if they do not already exist.
 *
 * @param data       - The complete pipeline report.
 * @param outputPath - Absolute or relative path for the output file.
 */
export function writePipelineReport(data: PipelineReport, outputPath: string): void {
  const dir = dirname(outputPath);
  mkdirSync(dir, { recursive: true });
  writeFileSync(outputPath, generateJsonReport(data), 'utf-8');
}
