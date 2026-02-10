/**
 * SigmaHQ Reference Corpus – Quality Scorer
 *
 * Scores a generated Sigma rule against reference rules from the SigmaHQ
 * corpus.  Evaluates field coverage, condition complexity, false-positive
 * documentation, metadata completeness, and ATT&CK technique alignment.
 */

import type { SigmaReferenceRule } from './loader.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface QualityScore {
  overall: number;              // 1-10
  fieldCoverage: number;        // 1-10: does the rule use appropriate fields?
  conditionComplexity: number;  // 1-10: is the detection logic sufficiently specific?
  fpDocumentation: number;      // 1-10: quality of false positive documentation
  metadataCompleteness: number; // 1-10: all required fields present?
  techniqueAlignment: number;   // 1-10: does the detection match the ATT&CK technique?
  details: string[];            // Specific feedback items
}

export interface ComparisonResult {
  similarities: string[];
  differences: string[];
  improvements: string[];
  gaps: string[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Required top-level fields in a well-formed Sigma rule. */
const REQUIRED_FIELDS = [
  'title',
  'id',
  'status',
  'description',
  'author',
  'date',
  'logsource',
  'detection',
  'level',
];

/** Optional but recommended fields. */
const RECOMMENDED_FIELDS = [
  'tags',
  'falsepositives',
  'references',
  'modified',
];

/** Known ATT&CK tactic names for tag validation. */
const TACTIC_NAMES = new Set([
  'reconnaissance',
  'resource_development',
  'initial_access',
  'execution',
  'persistence',
  'privilege_escalation',
  'defense_evasion',
  'credential_access',
  'discovery',
  'lateral_movement',
  'collection',
  'command_and_control',
  'exfiltration',
  'impact',
]);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Clamp a numeric score into the [1, 10] range.
 */
function clamp(value: number): number {
  return Math.max(1, Math.min(10, Math.round(value)));
}

/**
 * Extract the set of detection field names from a Sigma detection block.
 * Fields like "selection", "filter", "condition" are structural — the
 * interesting parts are the keys *inside* those objects (e.g. CommandLine,
 * Image, ParentImage).
 */
function extractDetectionFields(
  detection: Record<string, unknown>,
): Set<string> {
  const fields = new Set<string>();

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;

    if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const fieldName of Object.keys(value as Record<string, unknown>)) {
        fields.add(fieldName.replace(/\|.*$/, '')); // strip modifiers like |contains
      }
    }
  }

  return fields;
}

/**
 * Count the number of distinct "clauses" in a Sigma condition string.
 * A clause is a selection reference or logical operator block.
 * More clauses generally means more specific detection logic.
 */
function countConditionClauses(
  detection: Record<string, unknown>,
): number {
  const condition = detection.condition;
  if (typeof condition !== 'string') return 0;

  // Count identifiers (selection_*, filter_*, etc.)
  const identifiers = condition.match(/\b[a-zA-Z_]\w*\b/g) ?? [];
  // Exclude pure logical keywords
  const keywords = new Set(['and', 'or', 'not', 'of', 'them', 'all', '1']);
  return identifiers.filter(
    (id) => !keywords.has(id.toLowerCase()),
  ).length;
}

/**
 * Count the total number of detection criteria (field:value pairs)
 * across all selection/filter blocks.
 */
function countDetectionCriteria(
  detection: Record<string, unknown>,
): number {
  let count = 0;

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;

    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const block = value as Record<string, unknown>;
      for (const fieldValue of Object.values(block)) {
        if (Array.isArray(fieldValue)) {
          count += fieldValue.length;
        } else {
          count += 1;
        }
      }
    }
  }

  return count;
}

/**
 * Extract ATT&CK technique IDs from tags array.
 */
function extractTechniquesFromTags(tags: unknown[]): string[] {
  return tags
    .map((t) => String(t))
    .filter((tag) => /^attack\.t\d{4}/i.test(tag))
    .map((tag) => tag.replace(/^attack\./i, '').toUpperCase());
}

/**
 * Extract ATT&CK tactic names from tags array.
 */
function extractTacticsFromTags(tags: unknown[]): string[] {
  return tags
    .map((t) => String(t))
    .filter((tag) => {
      if (!tag.startsWith('attack.')) return false;
      const suffix = tag.replace(/^attack\./, '');
      return TACTIC_NAMES.has(suffix);
    })
    .map((tag) => tag.replace(/^attack\./, ''));
}

// ---------------------------------------------------------------------------
// Scoring functions
// ---------------------------------------------------------------------------

/**
 * Score the field coverage of a generated rule against reference rules.
 */
function scoreFieldCoverage(
  generatedDetection: Record<string, unknown>,
  referenceRules: SigmaReferenceRule[],
  details: string[],
): number {
  if (referenceRules.length === 0) {
    // No reference rules available; give a baseline score based on
    // whether the rule has any detection fields at all.
    const fields = extractDetectionFields(generatedDetection);
    if (fields.size === 0) {
      details.push('No detection fields found in rule.');
      return 2;
    }
    details.push(
      `Rule uses ${fields.size} detection field(s) but no reference rules available for comparison.`,
    );
    return 5;
  }

  const genFields = extractDetectionFields(generatedDetection);

  // Build a frequency map of fields across all reference rules
  const refFieldCounts = new Map<string, number>();
  for (const ref of referenceRules) {
    const refFields = extractDetectionFields(ref.detection);
    for (const f of refFields) {
      refFieldCounts.set(f, (refFieldCounts.get(f) ?? 0) + 1);
    }
  }

  // Common fields are those that appear in >25% of reference rules
  const threshold = Math.max(1, referenceRules.length * 0.25);
  const commonFields = [...refFieldCounts.entries()]
    .filter(([_, count]) => count >= threshold)
    .map(([field]) => field);

  if (commonFields.length === 0) {
    details.push('Reference rules have no commonly-used fields.');
    return genFields.size > 0 ? 6 : 3;
  }

  // Check how many common reference fields the generated rule covers
  const coveredCommon = commonFields.filter((f) => genFields.has(f));
  const coverageRatio = coveredCommon.length / commonFields.length;

  if (coveredCommon.length < commonFields.length) {
    const missing = commonFields.filter((f) => !genFields.has(f));
    details.push(
      `Missing commonly-used detection fields: ${missing.join(', ')}`,
    );
  }

  // Check for extra fields not in references (not necessarily bad, but worth noting)
  const extraFields = [...genFields].filter(
    (f) => !refFieldCounts.has(f),
  );
  if (extraFields.length > 0) {
    details.push(
      `Rule uses fields not commonly seen in references: ${extraFields.join(', ')}`,
    );
  }

  // Score: 1 (no coverage) to 10 (full coverage)
  return clamp(Math.ceil(coverageRatio * 8) + 2);
}

/**
 * Score detection condition complexity.
 */
function scoreConditionComplexity(
  generatedDetection: Record<string, unknown>,
  referenceRules: SigmaReferenceRule[],
  details: string[],
): number {
  const genClauses = countConditionClauses(generatedDetection);
  const genCriteria = countDetectionCriteria(generatedDetection);

  if (genClauses === 0) {
    details.push('No condition clauses found in detection block.');
    return 1;
  }

  if (referenceRules.length === 0) {
    // Score based on absolute criteria count
    if (genCriteria >= 5) return 7;
    if (genCriteria >= 3) return 5;
    if (genCriteria >= 1) return 3;
    return 2;
  }

  // Calculate average complexity of reference rules
  const refCriteriaCounts = referenceRules.map((r) =>
    countDetectionCriteria(r.detection),
  );
  const avgRefCriteria =
    refCriteriaCounts.reduce((a, b) => a + b, 0) / refCriteriaCounts.length;

  const refClauseCounts = referenceRules.map((r) =>
    countConditionClauses(r.detection),
  );
  const avgRefClauses =
    refClauseCounts.reduce((a, b) => a + b, 0) / refClauseCounts.length;

  // Compare generated rule against reference averages
  let score = 5; // baseline

  // Criteria comparison
  if (avgRefCriteria > 0) {
    const criteriaRatio = genCriteria / avgRefCriteria;
    if (criteriaRatio >= 1.0) {
      score += 2;
      details.push(
        `Detection criteria count (${genCriteria}) meets or exceeds reference average (${Math.round(avgRefCriteria)}).`,
      );
    } else if (criteriaRatio >= 0.5) {
      score += 1;
      details.push(
        `Detection criteria count (${genCriteria}) is below reference average (${Math.round(avgRefCriteria)}).`,
      );
    } else {
      score -= 1;
      details.push(
        `Detection criteria count (${genCriteria}) is significantly below reference average (${Math.round(avgRefCriteria)}).`,
      );
    }
  }

  // Clause comparison (filter usage)
  if (avgRefClauses > 1 && genClauses === 1) {
    details.push(
      'Reference rules typically use filters — consider adding filter conditions.',
    );
    score -= 1;
  } else if (genClauses >= 2) {
    details.push(
      'Rule uses multiple condition clauses (selection + filter), which is good practice.',
    );
    score += 1;
  }

  return clamp(score);
}

/**
 * Score false-positive documentation quality.
 */
function scoreFpDocumentation(
  rule: Record<string, unknown>,
  referenceRules: SigmaReferenceRule[],
  details: string[],
): number {
  const fps = Array.isArray(rule.falsepositives) ? rule.falsepositives : [];

  if (fps.length === 0) {
    details.push('No false positives documented.');
    return 2;
  }

  let score = 5; // baseline for having at least one

  // Quality: are they specific strings or just "Unknown"?
  const specificFps = fps.filter((fp) => {
    const s = String(fp).toLowerCase().trim();
    return s !== 'unknown' && s !== 'none' && s !== 'tbd' && s.length > 10;
  });

  if (specificFps.length === 0) {
    details.push(
      'False positive entries are vague (e.g., "Unknown"). Provide specific scenarios.',
    );
    score -= 2;
  } else {
    score += Math.min(3, specificFps.length); // up to +3 for specific entries
    details.push(
      `${specificFps.length} specific false positive scenario(s) documented.`,
    );
  }

  // Compare with reference FPs
  if (referenceRules.length > 0) {
    const refFpCounts = referenceRules
      .map((r) => r.falsepositives.length)
      .filter((n) => n > 0);
    if (refFpCounts.length > 0) {
      const avgRefFps =
        refFpCounts.reduce((a, b) => a + b, 0) / refFpCounts.length;
      if (fps.length >= avgRefFps) {
        score += 1;
      }
    }
  }

  return clamp(score);
}

/**
 * Score metadata completeness.
 */
function scoreMetadataCompleteness(
  rule: Record<string, unknown>,
  details: string[],
): number {
  const presentRequired = REQUIRED_FIELDS.filter(
    (f) => rule[f] != null && rule[f] !== '',
  );
  const missingRequired = REQUIRED_FIELDS.filter(
    (f) => rule[f] == null || rule[f] === '',
  );

  const presentRecommended = RECOMMENDED_FIELDS.filter(
    (f) => rule[f] != null && rule[f] !== '',
  );
  const missingRecommended = RECOMMENDED_FIELDS.filter(
    (f) => rule[f] == null || rule[f] === '',
  );

  if (missingRequired.length > 0) {
    details.push(`Missing required fields: ${missingRequired.join(', ')}`);
  }

  if (missingRecommended.length > 0) {
    details.push(
      `Missing recommended fields: ${missingRecommended.join(', ')}`,
    );
  }

  // Score: required fields are weighted more heavily
  const requiredScore =
    (presentRequired.length / REQUIRED_FIELDS.length) * 7;
  const recommendedScore =
    (presentRecommended.length / RECOMMENDED_FIELDS.length) * 3;

  return clamp(Math.round(requiredScore + recommendedScore));
}

/**
 * Score technique alignment between the generated rule and reference rules.
 */
function scoreTechniqueAlignment(
  rule: Record<string, unknown>,
  referenceRules: SigmaReferenceRule[],
  techniqueId: string | undefined,
  details: string[],
): number {
  const tags = Array.isArray(rule.tags) ? rule.tags : [];
  const genTechniques = extractTechniquesFromTags(tags);
  const genTactics = extractTacticsFromTags(tags);

  // No tags at all is a significant gap
  if (tags.length === 0) {
    details.push('Rule has no tags — ATT&CK technique alignment cannot be assessed.');
    return 2;
  }

  if (genTechniques.length === 0) {
    details.push('No ATT&CK technique tags found (attack.tXXXX format).');
    return 3;
  }

  let score = 5; // baseline for having technique tags

  // Check if the specified technique is in the tags
  if (techniqueId) {
    const normalizedTechnique = techniqueId.toUpperCase();
    if (genTechniques.includes(normalizedTechnique)) {
      score += 2;
      details.push(
        `Rule correctly references target technique ${normalizedTechnique}.`,
      );
    } else {
      details.push(
        `Rule does not reference the target technique ${normalizedTechnique}. ` +
          `Tagged techniques: ${genTechniques.join(', ')}`,
      );
      score -= 2;
    }
  }

  // Check tactic-to-technique consistency with references
  if (referenceRules.length > 0) {
    const refTechniques = new Set(
      referenceRules.flatMap((r) => r.attackTechniques),
    );
    const overlappingTechniques = genTechniques.filter((t) =>
      refTechniques.has(t),
    );
    if (overlappingTechniques.length > 0) {
      score += 1;
      details.push(
        `Technique(s) match reference rules: ${overlappingTechniques.join(', ')}`,
      );
    }

    // Check logsource alignment
    const genLogsource = rule.logsource as Record<string, unknown> | undefined;
    if (genLogsource) {
      const genCat = genLogsource.category as string | undefined;
      const refCategories = new Set(
        referenceRules
          .map((r) => r.logsource.category)
          .filter(Boolean),
      );
      if (genCat && refCategories.size > 0 && !refCategories.has(genCat)) {
        details.push(
          `Logsource category "${genCat}" differs from reference rules (${[...refCategories].join(', ')}).`,
        );
        score -= 1;
      }
    }
  }

  // Bonus for having tactic tags
  if (genTactics.length > 0) {
    score += 1;
  } else {
    details.push('No ATT&CK tactic tags found.');
  }

  return clamp(score);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Score a generated Sigma rule against the reference corpus.
 *
 * @param generatedRule   – The generated rule as a parsed JS object
 * @param referenceRules  – Reference rules from the SigmaHQ corpus to compare against
 * @param techniqueId     – Optional ATT&CK technique the rule should detect
 */
export function scoreRuleQuality(
  generatedRule: Record<string, unknown>,
  referenceRules: SigmaReferenceRule[],
  techniqueId?: string,
): QualityScore {
  const details: string[] = [];
  const detection = (generatedRule.detection ?? {}) as Record<string, unknown>;

  const fieldCoverage = scoreFieldCoverage(detection, referenceRules, details);
  const conditionComplexity = scoreConditionComplexity(
    detection,
    referenceRules,
    details,
  );
  const fpDocumentation = scoreFpDocumentation(
    generatedRule,
    referenceRules,
    details,
  );
  const metadataCompleteness = scoreMetadataCompleteness(
    generatedRule,
    details,
  );
  const techniqueAlignment = scoreTechniqueAlignment(
    generatedRule,
    referenceRules,
    techniqueId,
    details,
  );

  // Overall is a weighted average
  const overall = clamp(
    Math.round(
      fieldCoverage * 0.25 +
        conditionComplexity * 0.25 +
        fpDocumentation * 0.15 +
        metadataCompleteness * 0.15 +
        techniqueAlignment * 0.2,
    ),
  );

  return {
    overall,
    fieldCoverage,
    conditionComplexity,
    fpDocumentation,
    metadataCompleteness,
    techniqueAlignment,
    details,
  };
}

/**
 * Compare a generated rule against a specific reference rule.
 * Returns similarities, differences, potential improvements, and gaps.
 */
export function compareToReference(
  generatedRule: Record<string, unknown>,
  referenceRule: SigmaReferenceRule,
): ComparisonResult {
  const similarities: string[] = [];
  const differences: string[] = [];
  const improvements: string[] = [];
  const gaps: string[] = [];

  const genDetection = (generatedRule.detection ?? {}) as Record<
    string,
    unknown
  >;
  const refDetection = referenceRule.detection;

  // --- Field comparison ---
  const genFields = extractDetectionFields(genDetection);
  const refFields = extractDetectionFields(refDetection);

  const sharedFields = [...genFields].filter((f) => refFields.has(f));
  const genOnlyFields = [...genFields].filter((f) => !refFields.has(f));
  const refOnlyFields = [...refFields].filter((f) => !genFields.has(f));

  if (sharedFields.length > 0) {
    similarities.push(
      `Both rules detect on fields: ${sharedFields.join(', ')}`,
    );
  }

  if (genOnlyFields.length > 0) {
    differences.push(
      `Generated rule uses additional fields: ${genOnlyFields.join(', ')}`,
    );
    // Additional fields can be improvements if they add specificity
    if (genOnlyFields.length <= 3) {
      improvements.push(
        `Additional fields may improve detection specificity: ${genOnlyFields.join(', ')}`,
      );
    }
  }

  if (refOnlyFields.length > 0) {
    gaps.push(
      `Reference rule uses fields not in generated rule: ${refOnlyFields.join(', ')}`,
    );
  }

  // --- Complexity comparison ---
  const genCriteria = countDetectionCriteria(genDetection);
  const refCriteria = countDetectionCriteria(refDetection);

  if (genCriteria > refCriteria) {
    improvements.push(
      `Generated rule has more detection criteria (${genCriteria} vs ${refCriteria}).`,
    );
  } else if (genCriteria < refCriteria) {
    gaps.push(
      `Reference rule has more detection criteria (${refCriteria} vs ${genCriteria}).`,
    );
  } else {
    similarities.push(
      `Both rules have similar detection complexity (${genCriteria} criteria).`,
    );
  }

  // --- Logsource comparison ---
  const genLogsource = (generatedRule.logsource ?? {}) as Record<
    string,
    unknown
  >;
  const refLogsource = referenceRule.logsource;

  if (
    genLogsource.category === refLogsource.category &&
    genLogsource.product === refLogsource.product
  ) {
    similarities.push(
      `Same logsource: category=${refLogsource.category ?? 'n/a'}, product=${refLogsource.product ?? 'n/a'}`,
    );
  } else {
    differences.push(
      `Different logsource configuration. ` +
        `Generated: category=${genLogsource.category ?? 'n/a'}, product=${genLogsource.product ?? 'n/a'}. ` +
        `Reference: category=${refLogsource.category ?? 'n/a'}, product=${refLogsource.product ?? 'n/a'}.`,
    );
  }

  // --- Level comparison ---
  const genLevel = generatedRule.level as string | undefined;
  const refLevel = referenceRule.level;

  if (genLevel && refLevel) {
    if (genLevel === refLevel) {
      similarities.push(`Same severity level: ${refLevel}`);
    } else {
      differences.push(
        `Different severity levels. Generated: ${genLevel}. Reference: ${refLevel}.`,
      );
    }
  }

  // --- Technique alignment ---
  const genTags = Array.isArray(generatedRule.tags)
    ? generatedRule.tags.map((t) => String(t))
    : [];
  const genTechniques = new Set(extractTechniquesFromTags(genTags));
  const refTechniques = new Set(referenceRule.attackTechniques);

  const sharedTechniques = [...genTechniques].filter((t) =>
    refTechniques.has(t),
  );
  const genOnlyTechniques = [...genTechniques].filter(
    (t) => !refTechniques.has(t),
  );
  const refOnlyTechniques = [...refTechniques].filter(
    (t) => !genTechniques.has(t),
  );

  if (sharedTechniques.length > 0) {
    similarities.push(
      `Both rules target technique(s): ${sharedTechniques.join(', ')}`,
    );
  }
  if (genOnlyTechniques.length > 0) {
    differences.push(
      `Generated rule targets additional techniques: ${genOnlyTechniques.join(', ')}`,
    );
  }
  if (refOnlyTechniques.length > 0) {
    gaps.push(
      `Reference rule targets techniques not in generated rule: ${refOnlyTechniques.join(', ')}`,
    );
  }

  // --- False positives ---
  const genFps = Array.isArray(generatedRule.falsepositives)
    ? generatedRule.falsepositives
    : [];
  const refFps = referenceRule.falsepositives;

  if (genFps.length === 0 && refFps.length > 0) {
    gaps.push(
      `Reference rule documents false positives: ${refFps.join('; ')}`,
    );
  } else if (genFps.length > 0 && refFps.length === 0) {
    improvements.push(
      'Generated rule documents false positives where reference does not.',
    );
  }

  return { similarities, differences, improvements, gaps };
}
