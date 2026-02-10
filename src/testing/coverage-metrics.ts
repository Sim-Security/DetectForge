/**
 * ATT&CK coverage metrics for generated detection rules.
 *
 * Calculates how many MITRE ATT&CK techniques are covered by the
 * generated rule set, provides per-tactic breakdowns, and exports
 * ATT&CK Navigator JSON layers for visualization.
 */

import type { GeneratedRule } from '@/types/detection-rule.js';
import type { AttackMappingResult } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface CoverageMetrics {
  totalTechniques: number;
  coveredTechniques: number;
  coveragePercentage: number;
  tacticBreakdown: Record<string, { covered: number; total: number; percentage: number }>;
  coveredTechniqueIds: string[];
  uncoveredTechniqueIds: string[];
  navigatorLayer: AttackNavigatorLayer;
}

export interface AttackNavigatorLayer {
  name: string;
  versions: { attack: string; navigator: string; layer: string };
  domain: string;
  description: string;
  techniques: Array<{
    techniqueID: string;
    tactic: string;
    color: string;
    comment: string;
    enabled: boolean;
    score: number;
  }>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default color for covered techniques in Navigator layers. */
const COVERED_COLOR = '#31a354';

/** Default color for uncovered techniques in Navigator layers. */
const UNCOVERED_COLOR = '#d73027';

/** ATT&CK Navigator format versions. */
const NAVIGATOR_VERSIONS = {
  attack: '14',
  navigator: '4.9.5',
  layer: '4.5',
};

/** Valid ATT&CK technique ID pattern: T1234 or T1234.001 */
const TECHNIQUE_ID_RE = /^T\d{4}(\.\d{3})?$/;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Calculate coverage metrics from generated rules and ATT&CK mappings.
 *
 * Aggregates all unique technique IDs from both the rule set
 * (`attackTechniqueId` field) and the provided ATT&CK mapping results
 * to determine the full universe of known techniques, then computes
 * which are covered by at least one rule.
 *
 * @param rules    - All generated detection rules.
 * @param mappings - All ATT&CK mapping results from extraction.
 * @returns Comprehensive coverage metrics with Navigator layer data.
 */
export function calculateCoverageMetrics(
  rules: GeneratedRule[],
  mappings: AttackMappingResult[],
): CoverageMetrics {
  // 1. Build the universe of all known technique IDs from mappings
  const allTechniques = new Map<string, string>(); // techniqueId -> tactic
  for (const m of mappings) {
    if (m.techniqueId && TECHNIQUE_ID_RE.test(m.techniqueId)) {
      allTechniques.set(m.techniqueId, normalizeTactic(m.tactic));
    }
  }

  // Also pull technique IDs from rules that might not be in mappings
  for (const rule of rules) {
    if (rule.attackTechniqueId && TECHNIQUE_ID_RE.test(rule.attackTechniqueId)) {
      if (!allTechniques.has(rule.attackTechniqueId)) {
        allTechniques.set(
          rule.attackTechniqueId,
          normalizeTactic(rule.attackTactic ?? 'unknown'),
        );
      }
    }
  }

  // 2. Determine which techniques are covered by at least one rule
  const coveredSet = new Set<string>();
  for (const rule of rules) {
    if (
      rule.attackTechniqueId &&
      TECHNIQUE_ID_RE.test(rule.attackTechniqueId) &&
      rule.validation.valid
    ) {
      coveredSet.add(rule.attackTechniqueId);
    }
  }

  // 3. Compute IDs
  const allTechniqueIds = [...allTechniques.keys()].sort();
  const coveredTechniqueIds = allTechniqueIds.filter(id => coveredSet.has(id));
  const uncoveredTechniqueIds = allTechniqueIds.filter(id => !coveredSet.has(id));

  const totalTechniques = allTechniqueIds.length;
  const coveredTechniques = coveredTechniqueIds.length;
  const coveragePercentage =
    totalTechniques > 0
      ? Math.round((coveredTechniques / totalTechniques) * 10000) / 100
      : 0;

  // 4. Tactic breakdown
  const tacticBreakdown = computeTacticBreakdown(allTechniques, coveredSet);

  // 5. Navigator layer
  const navigatorLayer = buildNavigatorLayer(
    allTechniques,
    coveredSet,
    coveragePercentage,
  );

  return {
    totalTechniques,
    coveredTechniques,
    coveragePercentage,
    tacticBreakdown,
    coveredTechniqueIds,
    uncoveredTechniqueIds,
    navigatorLayer,
  };
}

/**
 * Export an ATT&CK Navigator JSON layer as a formatted string.
 *
 * @param metrics - The coverage metrics containing the navigator layer.
 * @returns Pretty-printed JSON string of the Navigator layer.
 */
export function exportNavigatorLayer(metrics: CoverageMetrics): string {
  return JSON.stringify(metrics.navigatorLayer, null, 2);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Normalize tactic names to a consistent lowercase format.
 */
function normalizeTactic(tactic: string): string {
  return tactic
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-');
}

/**
 * Compute per-tactic coverage breakdown.
 */
function computeTacticBreakdown(
  allTechniques: Map<string, string>,
  coveredSet: Set<string>,
): Record<string, { covered: number; total: number; percentage: number }> {
  const tacticTotals = new Map<string, number>();
  const tacticCovered = new Map<string, number>();

  for (const [techId, tactic] of allTechniques) {
    tacticTotals.set(tactic, (tacticTotals.get(tactic) ?? 0) + 1);
    if (coveredSet.has(techId)) {
      tacticCovered.set(tactic, (tacticCovered.get(tactic) ?? 0) + 1);
    }
  }

  const breakdown: Record<string, { covered: number; total: number; percentage: number }> = {};
  for (const [tactic, total] of tacticTotals) {
    const covered = tacticCovered.get(tactic) ?? 0;
    breakdown[tactic] = {
      covered,
      total,
      percentage: total > 0 ? Math.round((covered / total) * 10000) / 100 : 0,
    };
  }

  return breakdown;
}

/**
 * Build the ATT&CK Navigator layer object.
 */
function buildNavigatorLayer(
  allTechniques: Map<string, string>,
  coveredSet: Set<string>,
  coveragePercentage: number,
): AttackNavigatorLayer {
  const techniques: AttackNavigatorLayer['techniques'] = [];

  for (const [techId, tactic] of allTechniques) {
    const isCovered = coveredSet.has(techId);
    techniques.push({
      techniqueID: techId,
      tactic,
      color: isCovered ? COVERED_COLOR : UNCOVERED_COLOR,
      comment: isCovered ? 'Covered by generated rule' : 'No detection rule generated',
      enabled: true,
      score: isCovered ? 100 : 0,
    });
  }

  return {
    name: 'DetectForge Coverage Layer',
    versions: NAVIGATOR_VERSIONS,
    domain: 'enterprise-attack',
    description: `Detection coverage: ${coveragePercentage}% of identified techniques. Generated by DetectForge.`,
    techniques,
  };
}
