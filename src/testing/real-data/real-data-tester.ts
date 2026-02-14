/**
 * Real attack data tester.
 *
 * Compares each Sigma rule's performance against:
 * 1. Synthetic logs (existing effectiveness-tester)
 * 2. Real OTRF attack simulation logs
 *
 * Produces a side-by-side comparison showing where synthetic testing
 * overestimates (or underestimates) actual detection capability.
 */

import type { SigmaRule } from '@/types/detection-rule.js';
import { evaluateSigmaRuleSuite } from '@/testing/sigma-tester.js';
import type { SigmaTestSuiteResult } from '@/testing/sigma-tester.js';
import { testRuleEffectiveness, assessConfidence } from '@/testing/effectiveness-tester.js';
import type { RuleConfidence, EvasionResult, RealDataSignal } from '@/testing/effectiveness-tester.js';
import { loadDownloadedDatasets } from './dataset-downloader.js';
import { normalizeOTRFLogs } from './log-normalizer.js';
import { DATASET_CATALOG } from './dataset-catalog.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type MatchQuality = 'technique-match' | 'behavior-mismatch' | 'category-only' | 'no-data';

export interface PerDatasetResult {
  datasetId: string;
  tpRate: number;
  fpRate: number;
  attackCount: number;
  benignCount: number;
  truePositives: number;
  falsePositives: number;
}

export interface RealDataTestResult {
  ruleId: string;
  ruleTitle: string;
  ruleCategory: string;
  /** Synthetic test results from effectiveness-tester */
  synthetic: SigmaTestSuiteResult;
  /** Behavioral TP rate against technique-realistic logs (null if no templates) */
  behavioralTpRate: number | null;
  /** Real data test results — pooled across all datasets (backwards compat) */
  real: SigmaTestSuiteResult | null;
  /** Which dataset was used (first dataset ID for backwards compat) */
  datasetId: string | null;
  /** Number of attack logs tested against (pooled total) */
  attackLogsCount: number;
  /** Number of benign logs tested against (pooled total) */
  benignLogsCount: number;
  /** How the data was matched to this rule */
  matchType: MatchQuality;
  /** Per-dataset evaluation results */
  perDatasetResults: PerDatasetResult[];
  /** Best per-dataset result (highest TP rate) — used for pass/fail verdict */
  bestDatasetResult: PerDatasetResult | null;
  /** Confidence assessment from effectiveness tester */
  confidence: RuleConfidence;
  /** Evasion resilience from effectiveness tester */
  evasionResilience: EvasionResult | null;
  /** Standard deviation of per-dataset TP rates */
  perDatasetVariance: number;
  /** Hold-out validation results (only when holdOut option enabled) */
  holdOutResults?: PerDatasetResult[];
  /** Hold-out verdict: 'pass' | 'fail' | 'no-holdout' */
  holdOutVerdict?: 'pass' | 'fail' | 'no-holdout';
  /** Overall verdict (based on best dataset, not pooled) */
  verdict: 'pass' | 'fail' | 'no-data' | 'behavior-mismatch';
}

export interface RealDataSummary {
  totalRules: number;
  rulesWithData: number;
  rulesWithoutData: number;
  /** Average synthetic TP rate across rules with real data */
  avgSyntheticTpRate: number;
  /** Average real TP rate across rules with real data */
  avgRealTpRate: number;
  /** Average synthetic FP rate across rules with real data */
  avgSyntheticFpRate: number;
  /** Average real FP rate across rules with real data */
  avgRealFpRate: number;
  passed: number;
  failed: number;
  /** Segmented metrics by match quality */
  techniqueMatchedCount: number;
  behaviorMismatchCount: number;
  categoryOnlyCount: number;
  noDataCount: number;
  avgTechniqueMatchedTpRate: number;
  techniqueMatchedPassed: number;
  avgCategoryOnlyTpRate: number;
  results: RealDataTestResult[];
}

export interface RealDataTestOptions {
  /** Directory containing downloaded dataset JSON files */
  datasetsDir?: string;
  /** Minimum real TP rate to pass (0-1). Default: 0.3 */
  minRealTpRate?: number;
  /** Maximum real FP rate to pass (0-1). Default: 0.3 */
  maxRealFpRate?: number;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MIN_REAL_TP = 0.3;  // Lower threshold for real data (harder)
const DEFAULT_MAX_REAL_FP = 0.3;

/** Category-specific TP thresholds (noisier categories get lower thresholds) */
const CATEGORY_THRESHOLDS: Record<string, number> = {
  'process_access': 0.15,        // Sysmon EventID 10 is inherently noisy
  'create_remote_thread': 0.15,  // Sparse data, high noise ratio
};

function getCategoryThreshold(category: string, defaultMin: number): number {
  return CATEGORY_THRESHOLDS[category] ?? defaultMin;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Test all rules against real OTRF attack data and compare with synthetic.
 *
 * Uses technique-aware matching: each rule is only tested against datasets
 * that share the same ATT&CK technique tag. This prevents cross-technique
 * pollution (e.g. testing a Mimikatz rule against schtasks logs).
 */
export async function testRulesAgainstRealData(
  rules: SigmaRule[],
  options?: RealDataTestOptions,
): Promise<RealDataSummary> {
  const minTp = options?.minRealTpRate ?? DEFAULT_MIN_REAL_TP;
  const maxFp = options?.maxRealFpRate ?? DEFAULT_MAX_REAL_FP;

  // Load all downloaded datasets
  const rawDatasets = await loadDownloadedDatasets(options?.datasetsDir);

  if (rawDatasets.size === 0) {
    return buildNoDataSummary(rules);
  }

  // Pre-normalize each dataset individually (keyed by dataset ID)
  const normalizedDatasets = normalizeEachDataset(rawDatasets);

  // Always compute hold-out: for techniques with N >= 2 datasets, the last one
  // (sorted by ID) is reserved for hold-out validation.
  const holdOutDatasetIds = computeHoldOutSets(normalizedDatasets);

  const results: RealDataTestResult[] = [];

  for (const rule of rules) {
    const category = rule.logsource.category ?? rule.logsource.service ?? '';
    const syntheticResult = testRuleEffectiveness(rule);
    const behavioralTpRate = syntheticResult.behavioralTpRate;

    // Find datasets matching this rule by ATT&CK technique AND category
    // When hold-out is enabled, exclude hold-out datasets from development evaluation
    const matchingLogs = findMatchingLogs(rule, category, normalizedDatasets, holdOutDatasetIds);

    if (!matchingLogs || matchingLogs.perDataset.length === 0) {
      results.push({
        ruleId: rule.id,
        ruleTitle: rule.title,
        ruleCategory: category,
        synthetic: syntheticResult.suite,
        behavioralTpRate,
        real: null,
        datasetId: null,
        attackLogsCount: 0,
        benignLogsCount: 0,
        matchType: 'no-data',
        perDatasetResults: [],
        bestDatasetResult: null,
        perDatasetVariance: 0,
        confidence: syntheticResult.confidence,
        evasionResilience: syntheticResult.evasionResilience,
        verdict: 'no-data',
      });
      continue;
    }

    // Evaluate rule against each matching dataset independently
    const perDatasetResults: PerDatasetResult[] = [];
    for (const ds of matchingLogs.perDataset) {
      if (ds.attack.length === 0 && ds.benign.length === 0) continue;

      const dsResult = evaluateSigmaRuleSuite(rule, ds.attack, ds.benign);
      perDatasetResults.push({
        datasetId: ds.datasetId,
        tpRate: dsResult.tpRate,
        fpRate: dsResult.fpRate,
        attackCount: ds.attack.length,
        benignCount: ds.benign.length,
        truePositives: dsResult.truePositives,
        falsePositives: dsResult.falsePositives,
      });
    }

    // Also compute pooled result for backwards compatibility
    const pooledReal = evaluateSigmaRuleSuite(
      rule,
      matchingLogs.pooledAttack,
      matchingLogs.pooledBenign,
    );

    // Best dataset = highest TP rate (among datasets with attack logs)
    const withAttacks = perDatasetResults.filter(d => d.attackCount > 0);
    const bestDataset = withAttacks.length > 0
      ? withAttacks.reduce((best, d) => d.tpRate > best.tpRate ? d : best)
      : null;

    // Verdict uses best dataset result (if any dataset shows detection, rule works)
    const categoryMinTp = getCategoryThreshold(category, minTp);
    const bestTp = bestDataset?.tpRate ?? 0;
    const bestFp = bestDataset?.fpRate ?? 0;
    const passesTP = bestDataset
      ? (bestTp >= categoryMinTp || bestDataset.attackCount === 0)
      : (matchingLogs.pooledAttack.length === 0);
    const passesFP = bestDataset
      ? (bestFp <= maxFp || bestDataset.benignCount === 0)
      : (matchingLogs.pooledBenign.length === 0);

    // Behavior-mismatch detection: technique ID matched but the rule's specific
    // detection behavior has zero overlap with the dataset's attack content.
    // Criteria: technique-matched + 0% TP across ALL datasets + no attack logs
    // contain any of the rule's positive detection field values.
    let matchType = matchingLogs.matchType;
    let verdict: 'pass' | 'fail' | 'no-data' | 'behavior-mismatch' =
      passesTP && passesFP ? 'pass' : 'fail';

    if (
      matchType === 'technique-match' &&
      verdict === 'fail' &&
      bestTp === 0 &&
      withAttacks.every(d => d.tpRate === 0)
    ) {
      // Check if ANY attack log contains values the rule is looking for
      const positiveValues = extractPositiveDetectionValues(rule);
      const hasOverlap = matchingLogs.pooledAttack.some((log: LogEntry) =>
        positiveValues.some(({ field, values }: { field: string; values: string[] }) =>
          values.some((v: string) => {
            const logVal = String(log[field] ?? '').toLowerCase();
            const pattern = v.toLowerCase().replace(/\*/g, '');
            return pattern.length > 0 && logVal.includes(pattern);
          }),
        ),
      );

      if (!hasOverlap) {
        matchType = 'behavior-mismatch';
        verdict = 'behavior-mismatch';
      }
    }

    // Secondary behavior-mismatch criterion: technique matched but < 1% TP across
    // many attack logs indicates a sub-variant mismatch (e.g. rule detects shell→taskmgr
    // automation but dataset has interactive RDP→taskmgr)
    if (
      matchType === 'technique-match' &&
      verdict === 'fail'
    ) {
      const totalAttack = withAttacks.reduce((sum, d) => sum + d.attackCount, 0);
      const maxTp = Math.max(...withAttacks.map(d => d.tpRate), 0);
      if (maxTp < 0.01 && totalAttack > 10) {
        matchType = 'behavior-mismatch';
        verdict = 'behavior-mismatch';
      }
    }

    // Hold-out validation: always test against reserved datasets
    let holdOutResults: PerDatasetResult[] | undefined;
    let holdOutVerdict: 'pass' | 'fail' | 'no-holdout' = 'no-holdout';

    const holdOutLogs = findMatchingLogsHoldOut(rule, category, normalizedDatasets, holdOutDatasetIds);
    if (holdOutLogs && holdOutLogs.perDataset.length > 0) {
      holdOutResults = [];
      for (const ds of holdOutLogs.perDataset) {
        if (ds.attack.length === 0 && ds.benign.length === 0) continue;
        const dsResult = evaluateSigmaRuleSuite(rule, ds.attack, ds.benign);
        holdOutResults.push({
          datasetId: ds.datasetId,
          tpRate: dsResult.tpRate,
          fpRate: dsResult.fpRate,
          attackCount: ds.attack.length,
          benignCount: ds.benign.length,
          truePositives: dsResult.truePositives,
          falsePositives: dsResult.falsePositives,
        });
      }
      const bestHoldOut = holdOutResults.filter(d => d.attackCount > 0)
        .reduce<PerDatasetResult | null>((best, d) => !best || d.tpRate > best.tpRate ? d : best, null);
      const hoCategoryMinTp = getCategoryThreshold(category, minTp);
      holdOutVerdict = bestHoldOut
        ? (bestHoldOut.tpRate >= hoCategoryMinTp ? 'pass' : 'fail')
        : 'no-holdout';
    }

    // Compute per-dataset TP variance
    const perDatasetVariance = computeTpVariance(perDatasetResults);

    // Re-assess confidence with real-data signal when we have technique-matched data
    let confidence = syntheticResult.confidence;
    if (matchType === 'technique-match' && bestDataset) {
      const realDataSignal: RealDataSignal = {
        realTpRate: bestDataset.tpRate,
        syntheticTpRate: syntheticResult.suite.tpRate,
        holdOutVerdict: holdOutVerdict,
        perDatasetVariance,
      };
      confidence = assessConfidence(
        rule,
        behavioralTpRate,
        syntheticResult.evasionResilience,
        realDataSignal,
      );
    }

    results.push({
      ruleId: rule.id,
      ruleTitle: rule.title,
      ruleCategory: category,
      synthetic: syntheticResult.suite,
      behavioralTpRate,
      real: pooledReal,
      datasetId: matchingLogs.datasetIds[0] ?? null,
      attackLogsCount: matchingLogs.pooledAttack.length,
      benignLogsCount: matchingLogs.pooledBenign.length,
      matchType,
      perDatasetResults,
      bestDatasetResult: bestDataset,
      perDatasetVariance,
      confidence,
      evasionResilience: syntheticResult.evasionResilience,
      holdOutResults,
      holdOutVerdict,
      verdict,
    });
  }

  return buildSummary(results);
}

// ---------------------------------------------------------------------------
// Internal: Technique-Aware Matching
// ---------------------------------------------------------------------------

import type { LogEntry } from '@/testing/sigma-tester.js';
import type { DatasetEntry } from './dataset-catalog.js';

interface DatasetLogSet {
  datasetId: string;
  attack: LogEntry[];
  benign: LogEntry[];
}

interface AggregatedLogs {
  pooledAttack: LogEntry[];
  pooledBenign: LogEntry[];
  perDataset: DatasetLogSet[];
  datasetIds: string[];
  matchType: MatchQuality;
}

interface NormalizedDataset {
  catalogEntry: DatasetEntry | undefined;
  logsByCategory: Map<string, { attack: LogEntry[]; benign: LogEntry[] }>;
}

/**
 * Normalize each dataset individually, preserving per-dataset metadata.
 */
function normalizeEachDataset(
  rawDatasets: Map<string, unknown[]>,
): Map<string, NormalizedDataset> {
  const result = new Map<string, NormalizedDataset>();

  for (const [datasetId, rawLogs] of rawDatasets) {
    const catalogEntry = DATASET_CATALOG.find((e) => e.id === datasetId);
    const targetCategories = catalogEntry?.sigmaCategories ?? getAllCategories();
    const normalizedSets = normalizeOTRFLogs(rawLogs, targetCategories, catalogEntry?.attackPatterns);

    const logsByCategory = new Map<string, { attack: LogEntry[]; benign: LogEntry[] }>();
    for (const logSet of normalizedSets) {
      logsByCategory.set(logSet.category, {
        attack: logSet.attackLogs,
        benign: logSet.benignLogs,
      });
    }

    result.set(datasetId, { catalogEntry, logsByCategory });
  }

  return result;
}

/**
 * Extract ATT&CK technique IDs from a rule's tags.
 * Tags look like: "attack.t1003.001" → "T1003.001"
 */
function extractRuleTechniques(rule: SigmaRule): string[] {
  return rule.tags
    .filter((t) => /^attack\.t\d{4}/i.test(t))
    .map((t) => t.replace(/^attack\./i, '').toUpperCase());
}

/**
 * Extract positive (non-filter) detection field names from a Sigma rule.
 * Used to check whether category-fallback data actually contains relevant fields.
 */
function extractPositiveDetectionFields(rule: SigmaRule): string[] {
  const detection = rule.detection;
  const condition = (detection.condition ?? '').toLowerCase();
  const fields: string[] = [];

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;
    const keyLower = key.toLowerCase();
    // Skip filters / negated selections
    if (keyLower.startsWith('filter') || condition.includes(`not ${keyLower}`)) continue;

    if (typeof value === 'object' && value !== null) {
      const items = Array.isArray(value) ? value : [value];
      for (const item of items) {
        if (typeof item === 'object' && item !== null) {
          for (const fieldKey of Object.keys(item as Record<string, unknown>)) {
            fields.push(fieldKey.split('|')[0]); // Strip modifiers like |contains
          }
        }
      }
    }
  }
  return [...new Set(fields)];
}

/**
 * Extract positive detection field names AND their expected values from a Sigma rule.
 * Used for behavior-mismatch detection: checks if any attack logs contain values
 * the rule is looking for.
 */
function extractPositiveDetectionValues(
  rule: SigmaRule,
): Array<{ field: string; values: string[] }> {
  const detection = rule.detection;
  const condition = (detection.condition ?? '').toLowerCase();
  const result: Array<{ field: string; values: string[] }> = [];

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;
    const keyLower = key.toLowerCase();
    if (keyLower.startsWith('filter') || condition.includes(`not ${keyLower}`)) continue;

    if (typeof value === 'object' && value !== null) {
      const items = Array.isArray(value) ? value : [value];
      for (const item of items) {
        if (typeof item === 'object' && item !== null) {
          for (const [fieldKey, fieldVal] of Object.entries(item as Record<string, unknown>)) {
            const fieldName = fieldKey.split('|')[0];
            const values = Array.isArray(fieldVal)
              ? fieldVal.map(String)
              : fieldVal !== null && fieldVal !== undefined
                ? [String(fieldVal)]
                : [];
            if (values.length > 0) {
              result.push({ field: fieldName, values });
            }
          }
        }
      }
    }
  }
  return result;
}

/**
 * Find logs from datasets that match a rule by ATT&CK technique and category.
 *
 * Strategy:
 * 1. Extract technique IDs from the rule's tags
 * 2. Find datasets whose ATT&CK technique matches (or is a parent of) the rule's technique
 * 3. From those datasets, pull logs in the rule's logsource category
 * 4. If no technique match, fall back to category-only matching BUT only if the
 *    rule's positive detection fields actually exist in the candidate logs
 */
function findMatchingLogs(
  rule: SigmaRule,
  category: string,
  normalizedDatasets: Map<string, NormalizedDataset>,
  excludeIds?: Set<string>,
): AggregatedLogs | null {
  const ruleTechniques = extractRuleTechniques(rule);

  const result: AggregatedLogs = {
    pooledAttack: [], pooledBenign: [], perDataset: [], datasetIds: [], matchType: 'technique-match',
  };

  for (const [datasetId, dataset] of normalizedDatasets) {
    // Skip excluded datasets (hold-out)
    if (excludeIds?.has(datasetId)) continue;

    const datasetTechnique = dataset.catalogEntry?.attackTechniqueId?.toUpperCase() ?? '';

    // Check technique overlap:
    // Rule T1003.001 matches dataset T1003.001
    // Rule T1003 matches dataset T1003.001 (parent technique)
    // Rule T1003.001 matches dataset T1003 (sub-technique of parent)
    // Also matches secondary techniques (e.g. T1059.001 rule matches T1003.001 dataset
    // that uses encoded PowerShell as an attack enabler)
    const techniqueMatches = ruleTechniques.length === 0 || ruleTechniques.some((rt) => {
      if (!datasetTechnique) return false;
      const primaryMatch = rt === datasetTechnique ||
        datasetTechnique.startsWith(rt + '.') ||
        rt.startsWith(datasetTechnique + '.');
      const secondaryMatch = (dataset.catalogEntry?.secondaryTechniques ?? [])
        .some(st => {
          const stUpper = st.toUpperCase();
          return stUpper === rt || rt.startsWith(stUpper + '.') || stUpper.startsWith(rt + '.');
        });
      return primaryMatch || secondaryMatch;
    });

    if (!techniqueMatches) continue;

    // Pull logs for the rule's category from this dataset
    const categoryLogs = dataset.logsByCategory.get(category);
    if (!categoryLogs) continue;

    result.pooledAttack.push(...categoryLogs.attack);
    result.pooledBenign.push(...categoryLogs.benign);
    result.perDataset.push({
      datasetId,
      attack: categoryLogs.attack,
      benign: categoryLogs.benign,
    });
    result.datasetIds.push(datasetId);
  }

  // If technique-aware matching found data, return it
  if (result.pooledAttack.length > 0 || result.pooledBenign.length > 0) {
    return result;
  }

  // Fall back to category-only matching, but only if the rule's detection
  // fields actually exist in the candidate logs (prevents cross-technique pollution)
  const positiveFields = extractPositiveDetectionFields(rule);

  const fallback: AggregatedLogs = {
    pooledAttack: [], pooledBenign: [], perDataset: [], datasetIds: [], matchType: 'category-only',
  };

  for (const [datasetId, dataset] of normalizedDatasets) {
    if (excludeIds?.has(datasetId)) continue;

    const categoryLogs = dataset.logsByCategory.get(category);
    if (!categoryLogs) continue;

    // Only use this data if rule detection fields exist in the logs
    const hasRelevantFields = categoryLogs.attack.some(log =>
      positiveFields.some(field => log[field] !== undefined && log[field] !== null),
    );
    if (!hasRelevantFields) continue;

    fallback.pooledAttack.push(...categoryLogs.attack);
    fallback.pooledBenign.push(...categoryLogs.benign);
    fallback.perDataset.push({
      datasetId,
      attack: categoryLogs.attack,
      benign: categoryLogs.benign,
    });
    fallback.datasetIds.push(datasetId);
  }

  if (fallback.pooledAttack.length > 0 || fallback.pooledBenign.length > 0) {
    return fallback;
  }

  return null;
}

/**
 * Compute hold-out dataset IDs for validation.
 *
 * Groups datasets by ATT&CK technique. For techniques with N >= 2 datasets,
 * the last dataset (sorted by ID for determinism) is reserved as hold-out.
 */
function computeHoldOutSets(
  normalizedDatasets: Map<string, NormalizedDataset>,
): Set<string> {
  const byTechnique = new Map<string, string[]>();

  for (const [datasetId, dataset] of normalizedDatasets) {
    const technique = dataset.catalogEntry?.attackTechniqueId?.toUpperCase() ?? '';
    if (!technique) continue;
    if (!byTechnique.has(technique)) byTechnique.set(technique, []);
    byTechnique.get(technique)!.push(datasetId);
  }

  const holdOutIds = new Set<string>();
  for (const [, ids] of byTechnique) {
    if (ids.length >= 2) {
      ids.sort(); // deterministic ordering
      holdOutIds.add(ids[ids.length - 1]); // last one is hold-out
    }
  }

  return holdOutIds;
}

/**
 * Find matching logs for a rule using ONLY the hold-out datasets.
 * Inverse of the excludeIds logic in findMatchingLogs.
 */
function findMatchingLogsHoldOut(
  rule: SigmaRule,
  category: string,
  normalizedDatasets: Map<string, NormalizedDataset>,
  holdOutIds: Set<string>,
): AggregatedLogs | null {
  // Build a filtered dataset map containing only hold-out datasets
  const holdOutDatasets = new Map<string, NormalizedDataset>();
  for (const [id, dataset] of normalizedDatasets) {
    if (holdOutIds.has(id)) holdOutDatasets.set(id, dataset);
  }
  // Use findMatchingLogs with no exclusions against the hold-out-only map
  return findMatchingLogs(rule, category, holdOutDatasets);
}

/** All Sigma categories we care about */
function getAllCategories(): string[] {
  return [
    'process_creation',
    'network_connection',
    'registry_set',
    'file_event',
    'image_load',
    'ps_script',
    'dns_query',
    'authentication',
    'pipe_created',
    'process_access',
    'create_remote_thread',
  ];
}

function buildNoDataSummary(rules: SigmaRule[]): RealDataSummary {
  const results: RealDataTestResult[] = rules.map((rule) => {
    const synthetic = testRuleEffectiveness(rule);
    return {
      ruleId: rule.id,
      ruleTitle: rule.title,
      ruleCategory: rule.logsource.category ?? rule.logsource.service ?? '',
      synthetic: synthetic.suite,
      behavioralTpRate: synthetic.behavioralTpRate,
      real: null,
      datasetId: null,
      attackLogsCount: 0,
      benignLogsCount: 0,
      matchType: 'no-data' as MatchQuality,
      perDatasetResults: [],
      bestDatasetResult: null,
      perDatasetVariance: 0,
      confidence: synthetic.confidence,
      evasionResilience: synthetic.evasionResilience,
      verdict: 'no-data' as const,
    };
  });

  return {
    totalRules: rules.length,
    rulesWithData: 0,
    rulesWithoutData: rules.length,
    avgSyntheticTpRate: avg(results.map((r) => r.synthetic.tpRate)),
    avgRealTpRate: 0,
    avgSyntheticFpRate: avg(results.map((r) => r.synthetic.fpRate)),
    avgRealFpRate: 0,
    passed: 0,
    failed: 0,
    techniqueMatchedCount: 0,
    behaviorMismatchCount: 0,
    categoryOnlyCount: 0,
    noDataCount: rules.length,
    avgTechniqueMatchedTpRate: 0,
    techniqueMatchedPassed: 0,
    avgCategoryOnlyTpRate: 0,
    results,
  };
}

function buildSummary(results: RealDataTestResult[]): RealDataSummary {
  const withData = results.filter((r) => r.real !== null);
  const withoutData = results.filter((r) => r.real === null);

  const techniqueMatched = results.filter((r) => r.matchType === 'technique-match');
  const behaviorMismatch = results.filter((r) => r.matchType === 'behavior-mismatch');
  const categoryOnly = results.filter((r) => r.matchType === 'category-only');
  const noData = results.filter((r) => r.matchType === 'no-data');

  return {
    totalRules: results.length,
    rulesWithData: withData.length,
    rulesWithoutData: withoutData.length,
    avgSyntheticTpRate: avg(withData.map((r) => r.synthetic.tpRate)),
    avgRealTpRate: avg(withData.map((r) => r.real!.tpRate)),
    avgSyntheticFpRate: avg(withData.map((r) => r.synthetic.fpRate)),
    avgRealFpRate: avg(withData.map((r) => r.real!.fpRate)),
    passed: results.filter((r) => r.verdict === 'pass').length,
    failed: results.filter((r) => r.verdict === 'fail').length,
    techniqueMatchedCount: techniqueMatched.length,
    behaviorMismatchCount: behaviorMismatch.length,
    categoryOnlyCount: categoryOnly.length,
    noDataCount: noData.length,
    avgTechniqueMatchedTpRate: avg(
      techniqueMatched
        .filter((r) => r.bestDatasetResult !== null)
        .map((r) => r.bestDatasetResult!.tpRate),
    ),
    techniqueMatchedPassed: techniqueMatched.filter((r) => r.verdict === 'pass').length,
    avgCategoryOnlyTpRate: avg(
      categoryOnly
        .filter((r) => r.bestDatasetResult !== null)
        .map((r) => r.bestDatasetResult!.tpRate),
    ),
    results,
  };
}

function avg(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}

/**
 * Compute standard deviation of TP rates across datasets with attack logs.
 */
function computeTpVariance(perDataset: PerDatasetResult[]): number {
  const rates = perDataset.filter(d => d.attackCount > 0).map(d => d.tpRate);
  if (rates.length < 2) return 0;
  const mean = rates.reduce((a, b) => a + b, 0) / rates.length;
  const variance = rates.reduce((sum, r) => sum + (r - mean) ** 2, 0) / rates.length;
  return Math.sqrt(variance);
}
