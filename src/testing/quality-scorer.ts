/**
 * Overall quality scoring for generated detection rules.
 *
 * Produces a 1-10 score across five dimensions (syntax validity,
 * detection logic, documentation, ATT&CK mapping, false positive
 * handling) and an aggregate overall score.  All scoring is
 * heuristic-based -- no AI calls required.
 */

import type {
  GeneratedRule,
  RuleFormat,
  RuleDocumentation,
  ValidationResult,
} from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface RuleQualityScore {
  ruleId: string;
  format: RuleFormat;
  overallScore: number;
  dimensions: {
    syntaxValidity: number;
    detectionLogic: number;
    documentation: number;
    attackMapping: number;
    falsePosHandling: number;
  };
  explanation: string;
}

export interface QualityReport {
  totalRules: number;
  averageScore: number;
  scoreDistribution: Record<string, number>;
  perRuleScores: RuleQualityScore[];
  recommendations: string[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Clamp a number between min and max. */
function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

/** Required documentation fields for a perfect documentation score. */
const DOC_FIELDS: (keyof RuleDocumentation)[] = [
  'whatItDetects',
  'howItWorks',
  'attackMapping',
  'falsePositives',
  'coverageGaps',
  'recommendedLogSources',
  'tuningRecommendations',
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Score a single rule's quality across five dimensions.
 */
export function scoreRuleQuality(rule: GeneratedRule): RuleQualityScore {
  const ruleId = getRuleId(rule);
  const format = rule.format;

  const syntaxValidity = scoreSyntaxValidity(rule.validation);
  const detectionLogic = scoreDetectionLogic(rule);
  const documentation = scoreDocumentation(rule.documentation);
  const attackMapping = scoreAttackMapping(rule);
  const falsePosHandling = scoreFalsePositiveHandling(rule.documentation);

  const dimensions = {
    syntaxValidity,
    detectionLogic,
    documentation,
    attackMapping,
    falsePosHandling,
  };

  // Weighted average: syntax and detection logic weigh heaviest
  const overallScore = clamp(
    Math.round(
      (syntaxValidity * 0.25 +
        detectionLogic * 0.30 +
        documentation * 0.15 +
        attackMapping * 0.15 +
        falsePosHandling * 0.15) *
        10,
    ) / 10,
    1,
    10,
  );

  const explanation = buildExplanation(dimensions, overallScore);

  return {
    ruleId,
    format,
    overallScore,
    dimensions,
    explanation,
  };
}

/**
 * Generate a quality report for a set of rules.
 */
export function generateQualityReport(rules: GeneratedRule[]): QualityReport {
  const perRuleScores = rules.map(scoreRuleQuality);

  const totalRules = perRuleScores.length;

  const averageScore =
    totalRules > 0
      ? Math.round(
          (perRuleScores.reduce((sum, s) => sum + s.overallScore, 0) / totalRules) * 10,
        ) / 10
      : 0;

  // Score distribution: "1-3", "4-6", "7-10"
  const scoreDistribution: Record<string, number> = {
    '1-3': 0,
    '4-6': 0,
    '7-10': 0,
  };

  for (const s of perRuleScores) {
    if (s.overallScore <= 3) scoreDistribution['1-3']++;
    else if (s.overallScore <= 6) scoreDistribution['4-6']++;
    else scoreDistribution['7-10']++;
  }

  const recommendations = generateRecommendations(perRuleScores);

  return {
    totalRules,
    averageScore,
    scoreDistribution,
    perRuleScores,
    recommendations,
  };
}

// ---------------------------------------------------------------------------
// Dimension Scorers
// ---------------------------------------------------------------------------

/**
 * Score syntax validity.
 * 10 if validation passes with no errors, -2 per error, -1 per warning.
 */
function scoreSyntaxValidity(validation: ValidationResult): number {
  let score = 10;
  score -= validation.errors.length * 2;
  score -= validation.warnings.length * 1;
  return clamp(score, 1, 10);
}

/**
 * Score detection logic based on:
 * - Condition complexity (operator count / string or field count)
 * - Number of detection patterns
 */
function scoreDetectionLogic(rule: GeneratedRule): number {
  let score = 5; // baseline

  if (rule.format === 'yara' && rule.yara) {
    const stringCount = rule.yara.strings?.length ?? 0;
    const conditionOps = countConditionOperators(rule.yara.condition ?? '');

    // More strings = better
    if (stringCount >= 5) score += 3;
    else if (stringCount >= 3) score += 2;
    else if (stringCount >= 2) score += 1;
    else if (stringCount === 0) score -= 2;

    // Some condition complexity is good
    if (conditionOps >= 3) score += 2;
    else if (conditionOps >= 1) score += 1;

  } else if (rule.format === 'suricata' && rule.suricata) {
    const contentCount = rule.suricata.options.filter(
      o => o.keyword === 'content' || o.keyword === 'pcre',
    ).length;
    const hasFlow = rule.suricata.options.some(o => o.keyword === 'flow');

    if (contentCount >= 3) score += 3;
    else if (contentCount >= 2) score += 2;
    else if (contentCount >= 1) score += 1;
    else score -= 2;

    if (hasFlow) score += 1;

  } else if (rule.format === 'sigma' && rule.sigma) {
    // Count detection selections (keys other than "condition")
    const detectionKeys = Object.keys(rule.sigma.detection).filter(k => k !== 'condition');
    if (detectionKeys.length >= 3) score += 3;
    else if (detectionKeys.length >= 2) score += 2;
    else if (detectionKeys.length >= 1) score += 1;

    // Check condition complexity
    const condition = rule.sigma.detection.condition ?? '';
    const ops = countConditionOperators(condition);
    if (ops >= 2) score += 1;
  }

  return clamp(score, 1, 10);
}

/**
 * Score documentation completeness.
 * 10 if all documentation fields are present and populated, 1 if missing.
 */
function scoreDocumentation(doc: RuleDocumentation | undefined): number {
  if (!doc) return 1;

  let fieldsPresent = 0;
  const totalFields = DOC_FIELDS.length;

  for (const field of DOC_FIELDS) {
    const value = doc[field];
    if (value === undefined || value === null) continue;
    if (typeof value === 'string' && value.trim() === '') continue;
    if (Array.isArray(value) && value.length === 0) continue;
    if (typeof value === 'object' && !Array.isArray(value)) {
      // attackMapping object -- check it has at least techniqueId
      const obj = value as Record<string, unknown>;
      if (obj.techniqueId && String(obj.techniqueId).trim() !== '') {
        fieldsPresent++;
      }
      continue;
    }
    fieldsPresent++;
  }

  const ratio = fieldsPresent / totalFields;
  return clamp(Math.round(ratio * 10), 1, 10);
}

/**
 * Score ATT&CK mapping quality.
 * 10 if valid technique ID + tactic, partial credit for partial mapping.
 */
function scoreAttackMapping(rule: GeneratedRule): number {
  let score = 1;

  const techniqueId = rule.attackTechniqueId;
  const tactic = rule.attackTactic;

  // Valid technique ID pattern: T1234 or T1234.001
  const validTechniquePattern = /^T\d{4}(\.\d{3})?$/;

  if (techniqueId && validTechniquePattern.test(techniqueId)) {
    score += 4;
  } else if (techniqueId && techniqueId.startsWith('T')) {
    score += 2; // partial credit for malformed ID
  }

  if (tactic && tactic.trim() !== '') {
    score += 3;
  }

  // Bonus for documentation attack mapping
  if (rule.documentation?.attackMapping) {
    const mapping = rule.documentation.attackMapping;
    if (mapping.techniqueName && mapping.techniqueName.trim() !== '') score += 1;
    if (mapping.platform && mapping.platform.trim() !== '') score += 1;
  }

  return clamp(score, 1, 10);
}

/**
 * Score false positive handling based on:
 * - Number of FP scenarios documented
 * - Presence of tuning advice
 */
function scoreFalsePositiveHandling(doc: RuleDocumentation | undefined): number {
  if (!doc) return 1;

  let score = 1;
  const fpScenarios = doc.falsePositives ?? [];

  // Base score from scenario count
  if (fpScenarios.length >= 3) score += 4;
  else if (fpScenarios.length >= 2) score += 3;
  else if (fpScenarios.length >= 1) score += 2;

  // Bonus for tuning advice in each scenario
  let tuningCount = 0;
  for (const fp of fpScenarios) {
    if (fp.tuningAdvice && fp.tuningAdvice.trim() !== '') tuningCount++;
  }
  if (fpScenarios.length > 0) {
    const tuningRatio = tuningCount / fpScenarios.length;
    score += Math.round(tuningRatio * 3);
  }

  // Bonus for tuning recommendations at the doc level
  if (doc.tuningRecommendations && doc.tuningRecommendations.length > 0) {
    score += 1;
  }

  // Bonus for coverage gaps identified
  if (doc.coverageGaps && doc.coverageGaps.length > 0) {
    score += 1;
  }

  return clamp(score, 1, 10);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract a human-readable rule identifier.
 */
function getRuleId(rule: GeneratedRule): string {
  if (rule.format === 'sigma' && rule.sigma) return rule.sigma.id || rule.sigma.title;
  if (rule.format === 'yara' && rule.yara) return rule.yara.name;
  if (rule.format === 'suricata' && rule.suricata) return `SID:${rule.suricata.sid}`;
  return `${rule.format}-unknown`;
}

/**
 * Count logical operators in a condition string.
 */
function countConditionOperators(condition: string): number {
  const matches = condition.match(
    /\b(and|or|not|any\s+of|all\s+of|for\s+any|for\s+all|1\s+of|selection|filter)\b/gi,
  );
  return matches ? matches.length : 0;
}

/**
 * Build a human-readable explanation of the quality score.
 */
function buildExplanation(
  dimensions: RuleQualityScore['dimensions'],
  overallScore: number,
): string {
  const parts: string[] = [];

  if (overallScore >= 8) {
    parts.push('High quality rule with strong detection logic.');
  } else if (overallScore >= 5) {
    parts.push('Acceptable rule quality with room for improvement.');
  } else {
    parts.push('Rule needs significant improvement.');
  }

  // Identify weakest dimensions
  const dimEntries = Object.entries(dimensions) as [string, number][];
  const weakest = dimEntries.filter(([_, v]) => v <= 3);
  const strongest = dimEntries.filter(([_, v]) => v >= 8);

  if (weakest.length > 0) {
    const names = weakest.map(([k]) => formatDimensionName(k));
    parts.push(`Weakest areas: ${names.join(', ')}.`);
  }

  if (strongest.length > 0) {
    const names = strongest.map(([k]) => formatDimensionName(k));
    parts.push(`Strongest areas: ${names.join(', ')}.`);
  }

  return parts.join(' ');
}

/**
 * Format a dimension key to a human-readable name.
 */
function formatDimensionName(key: string): string {
  const nameMap: Record<string, string> = {
    syntaxValidity: 'syntax validity',
    detectionLogic: 'detection logic',
    documentation: 'documentation',
    attackMapping: 'ATT&CK mapping',
    falsePosHandling: 'false positive handling',
  };
  return nameMap[key] ?? key;
}

/**
 * Generate recommendations based on aggregate quality scores.
 */
function generateRecommendations(scores: RuleQualityScore[]): string[] {
  const recommendations: string[] = [];
  if (scores.length === 0) return recommendations;

  // Compute average per dimension
  const avgDimensions = {
    syntaxValidity: 0,
    detectionLogic: 0,
    documentation: 0,
    attackMapping: 0,
    falsePosHandling: 0,
  };

  for (const s of scores) {
    avgDimensions.syntaxValidity += s.dimensions.syntaxValidity;
    avgDimensions.detectionLogic += s.dimensions.detectionLogic;
    avgDimensions.documentation += s.dimensions.documentation;
    avgDimensions.attackMapping += s.dimensions.attackMapping;
    avgDimensions.falsePosHandling += s.dimensions.falsePosHandling;
  }

  const count = scores.length;
  avgDimensions.syntaxValidity /= count;
  avgDimensions.detectionLogic /= count;
  avgDimensions.documentation /= count;
  avgDimensions.attackMapping /= count;
  avgDimensions.falsePosHandling /= count;

  if (avgDimensions.syntaxValidity < 7) {
    recommendations.push(
      'Improve syntax validity: review validation errors and fix rule structure issues.',
    );
  }

  if (avgDimensions.detectionLogic < 6) {
    recommendations.push(
      'Enhance detection logic: add more content matches, conditions, or string patterns to improve specificity.',
    );
  }

  if (avgDimensions.documentation < 5) {
    recommendations.push(
      'Add comprehensive documentation: include what the rule detects, how it works, and tuning recommendations.',
    );
  }

  if (avgDimensions.attackMapping < 5) {
    recommendations.push(
      'Improve ATT&CK mapping: ensure each rule has a valid technique ID (e.g., T1059.001) and tactic.',
    );
  }

  if (avgDimensions.falsePosHandling < 5) {
    recommendations.push(
      'Document false positive scenarios: add at least 2-3 FP scenarios with tuning advice per rule.',
    );
  }

  const lowScoreCount = scores.filter(s => s.overallScore <= 3).length;
  if (lowScoreCount > 0) {
    recommendations.push(
      `${lowScoreCount} rule(s) scored 3 or below and need immediate attention.`,
    );
  }

  return recommendations;
}
