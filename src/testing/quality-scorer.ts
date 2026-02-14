/**
 * Overall quality scoring for generated detection rules.
 *
 * Produces a 1-10 score across five dimensions (syntax validity,
 * detection logic, documentation, ATT&CK mapping, false positive
 * handling) and an aggregate overall score.  All scoring is
 * heuristic-based -- no AI calls required.
 *
 * v2: Rewrote detection logic, documentation, and FP handling scorers
 * to analyze actual rule content instead of only checking for the
 * RuleDocumentation object (which the generation pipeline never creates).
 */

import type {
  GeneratedRule,
  RuleFormat,
  RuleDocumentation,
  SigmaRule,
  ValidationResult,
} from '@/types/detection-rule.js';
import { validateRuleFields } from '@/testing/field-validator.js';

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
  const documentation = scoreDocumentation(rule.documentation, rule);
  const attackMapping = scoreAttackMapping(rule);
  const falsePosHandling = scoreFalsePositiveHandling(rule.documentation, rule);

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
 * Score detection logic by analyzing actual rule content:
 *
 * Sigma: field relevance (vs template), value pattern diversity,
 *        condition complexity (filters, boolean operators).
 * YARA:  string count, string type diversity, condition complexity.
 * Suricata: content match count, flow presence, protocol specificity.
 */
function scoreDetectionLogic(rule: GeneratedRule): number {
  let score = 2; // low baseline — must earn points from content

  if (rule.format === 'yara' && rule.yara) {
    score = scoreYaraDetectionLogic(rule);
  } else if (rule.format === 'suricata' && rule.suricata) {
    score = scoreSuricataDetectionLogic(rule);
  } else if (rule.format === 'sigma' && rule.sigma) {
    score = scoreSigmaDetectionLogic(rule.sigma);
  }

  return clamp(score, 1, 10);
}

/**
 * Sigma-specific detection logic scorer.
 * Analyzes field relevance, value patterns, and condition structure.
 */
function scoreSigmaDetectionLogic(sigma: SigmaRule): number {
  let score = 2;
  const detection = sigma.detection;
  const detectionKeys = Object.keys(detection).filter(k => k !== 'condition');

  // --- 1. Selection/filter block count (0-2 pts) ---
  if (detectionKeys.length >= 4) score += 2;
  else if (detectionKeys.length >= 2) score += 1;

  // --- 2. Has explicit filter blocks (0-2 pts) ---
  const filterKeys = detectionKeys.filter(k =>
    k.startsWith('filter') || k.startsWith('exclusion'),
  );
  if (filterKeys.length >= 2) score += 2;
  else if (filterKeys.length >= 1) score += 1;

  // --- 3. Field relevance — validate fields against logsource catalog (0-2 pts, -3 for invalids) ---
  const fieldResult = validateRuleFields(sigma);
  if (!fieldResult.unknownLogsource && fieldResult.allDetectionFields.length > 0) {
    if (fieldResult.fieldValidityRate >= 0.8 && fieldResult.validFields.length >= 2) {
      score += 2;
    } else if (fieldResult.fieldValidityRate >= 0.5 || fieldResult.validFields.length >= 1) {
      score += 1;
    }
    // Heavier penalty for invalid fields — this is the #1 defect from red team
    if (fieldResult.invalidFields.length > 0) {
      score -= Math.min(3, fieldResult.invalidFields.length);
    }
  } else if (fieldResult.allDetectionFields.length >= 2) {
    // Unknown logsource but still using multiple fields
    score += 1;
  }

  // --- 4. Value pattern diversity — wildcards, lists, specificity (0-2 pts) ---
  const valueAnalysis = analyzeSigmaValues(detection, detectionKeys);
  if (valueAnalysis.totalValues >= 5 && valueAnalysis.hasWildcards) score += 2;
  else if (valueAnalysis.totalValues >= 3 || valueAnalysis.hasWildcards) score += 1;

  // --- 5. Condition complexity (0-2 pts) ---
  const condition = detection.condition ?? '';
  const condScore = scoreConditionComplexity(condition);
  score += condScore;

  // --- 6. Behavioral robustness check (0 to -3 pts, +1 bonus) ---
  const toolSignatureAnalysis = analyzeToolSignatureDependence(sigma);
  if (toolSignatureAnalysis.primaryIsToolSignature) {
    score -= 3;  // severe penalty: primary detection relies on specific tool filename
  } else if (
    toolSignatureAnalysis.hasToolSignatureFields > 0 &&
    !toolSignatureAnalysis.hasBehavioralFields
  ) {
    score -= 1;  // minor penalty: has tool names but no behavioral backup
  }

  // Bonus: reward rules with multiple detection variants (OR branches)
  if (toolSignatureAnalysis.detectionVariantCount >= 3) {
    score += 1;
  }

  return score;
}

/**
 * YARA-specific detection logic scorer.
 */
function scoreYaraDetectionLogic(rule: GeneratedRule): number {
  let score = 2;
  const yara = rule.yara!;
  const stringCount = yara.strings?.length ?? 0;

  // String count (0-3 pts)
  if (stringCount >= 5) score += 3;
  else if (stringCount >= 3) score += 2;
  else if (stringCount >= 1) score += 1;

  // String type diversity (0-1 pt)
  if (yara.strings && yara.strings.length > 0) {
    const types = new Set(yara.strings.map(s => s.type));
    if (types.size >= 2) score += 1;
  }

  // String modifiers used (0-1 pt)
  const hasModifiers = yara.strings?.some(s => s.modifiers.length > 0) ?? false;
  if (hasModifiers) score += 1;

  // Condition complexity (0-2 pts)
  const conditionOps = countConditionOperators(yara.condition ?? '');
  if (conditionOps >= 3) score += 2;
  else if (conditionOps >= 1) score += 1;

  return score;
}

/**
 * Suricata-specific detection logic scorer.
 */
function scoreSuricataDetectionLogic(rule: GeneratedRule): number {
  let score = 2;
  const suricata = rule.suricata!;
  const options = suricata.options;

  // Content/pcre count (0-3 pts)
  const contentCount = options.filter(
    o => o.keyword === 'content' || o.keyword === 'pcre',
  ).length;
  if (contentCount >= 4) score += 3;
  else if (contentCount >= 2) score += 2;
  else if (contentCount >= 1) score += 1;

  // Flow directive (0-1 pt)
  if (options.some(o => o.keyword === 'flow')) score += 1;

  // Depth/offset/within/distance modifiers (0-1 pt)
  const hasPositionModifiers = options.some(o =>
    ['depth', 'offset', 'within', 'distance'].includes(o.keyword),
  );
  if (hasPositionModifiers) score += 1;

  // Protocol specificity (0-1 pt)
  if (suricata.protocol !== 'ip' && suricata.protocol !== 'any') score += 1;

  // Threshold/flowbits (0-1 pt)
  const hasAdvanced = options.some(o =>
    ['threshold', 'flowbits', 'detection_filter'].includes(o.keyword),
  );
  if (hasAdvanced) score += 1;

  return score;
}

/**
 * Score documentation quality.
 * When a full RuleDocumentation object exists, score it directly.
 * When missing, infer documentation quality from rule content
 * (description, tags, falsepositives array on Sigma rules).
 */
function scoreDocumentation(doc: RuleDocumentation | undefined, rule: GeneratedRule): number {
  // If full documentation object exists, use original scorer
  if (doc) {
    return scoreDocFromObject(doc);
  }

  // Infer documentation quality from rule content
  let score = 1;

  // Description quality (0-3 pts)
  const description = getRuleDescription(rule);
  if (description) {
    const descLen = description.trim().length;
    if (descLen >= 100) score += 3;
    else if (descLen >= 50) score += 2;
    else if (descLen > 0) score += 1;
  }

  // Tags present and meaningful (0-2 pts)
  const tags = getRuleTags(rule);
  const attackTags = tags.filter(t => t.startsWith('attack.'));
  if (attackTags.length >= 2) score += 2;
  else if (attackTags.length >= 1) score += 1;

  // Has references/source (0-1 pt)
  if (rule.format === 'sigma' && rule.sigma?.references && rule.sigma.references.length > 0) {
    score += 1;
  } else if (rule.format === 'yara' && rule.yara?.meta.reference) {
    score += 1;
  }

  // Has inline FP documentation (0-2 pts)
  const fpStrings = getInlineFalsePositives(rule);
  if (fpStrings.length >= 3) score += 2;
  else if (fpStrings.length >= 1) score += 1;

  return clamp(score, 1, 10);
}

/** Score from a full RuleDocumentation object. */
function scoreDocFromObject(doc: RuleDocumentation): number {
  let fieldsPresent = 0;
  const totalFields = DOC_FIELDS.length;

  for (const field of DOC_FIELDS) {
    const value = doc[field];
    if (value === undefined || value === null) continue;
    if (typeof value === 'string' && value.trim() === '') continue;
    if (Array.isArray(value) && value.length === 0) continue;
    if (typeof value === 'object' && !Array.isArray(value)) {
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
 * Score false positive handling.
 * When a full RuleDocumentation exists, use its structured FP data.
 * Otherwise, infer from rule content: Sigma falsepositives[] array,
 * filter/exclusion blocks in detection, description mentions.
 */
function scoreFalsePositiveHandling(doc: RuleDocumentation | undefined, rule: GeneratedRule): number {
  // If full documentation exists, use the structured scorer
  if (doc) {
    return scoreFpFromDoc(doc);
  }

  // Infer FP handling from rule content
  let score = 1;

  // Inline falsepositives strings (0-3 pts)
  const fpStrings = getInlineFalsePositives(rule);
  if (fpStrings.length >= 3) score += 3;
  else if (fpStrings.length >= 2) score += 2;
  else if (fpStrings.length >= 1) score += 1;

  // FP string quality — longer/more specific is better (0-2 pts)
  if (fpStrings.length > 0) {
    const avgLen = fpStrings.reduce((sum, s) => sum + s.length, 0) / fpStrings.length;
    if (avgLen >= 40) score += 2;
    else if (avgLen >= 20) score += 1;
  }

  // Detection has filter/exclusion blocks (0-2 pts) — shows FP awareness
  if (rule.format === 'sigma' && rule.sigma) {
    const detKeys = Object.keys(rule.sigma.detection);
    const filterCount = detKeys.filter(k =>
      k.startsWith('filter') || k.startsWith('exclusion'),
    ).length;
    if (filterCount >= 2) score += 2;
    else if (filterCount >= 1) score += 1;
  }

  // Level is set appropriately — not always "critical" (0-1 pt)
  if (rule.format === 'sigma' && rule.sigma) {
    if (rule.sigma.level !== 'critical') score += 1;
  }

  return clamp(score, 1, 10);
}

/** Score FP handling from a full RuleDocumentation object. */
function scoreFpFromDoc(doc: RuleDocumentation): number {
  let score = 1;
  const fpScenarios = doc.falsePositives ?? [];

  if (fpScenarios.length >= 3) score += 4;
  else if (fpScenarios.length >= 2) score += 3;
  else if (fpScenarios.length >= 1) score += 2;

  let tuningCount = 0;
  for (const fp of fpScenarios) {
    if (fp.tuningAdvice && fp.tuningAdvice.trim() !== '') tuningCount++;
  }
  if (fpScenarios.length > 0) {
    const tuningRatio = tuningCount / fpScenarios.length;
    score += Math.round(tuningRatio * 3);
  }

  if (doc.tuningRecommendations && doc.tuningRecommendations.length > 0) {
    score += 1;
  }

  if (doc.coverageGaps && doc.coverageGaps.length > 0) {
    score += 1;
  }

  return clamp(score, 1, 10);
}

// ---------------------------------------------------------------------------
// Tool-Signature Analysis
// ---------------------------------------------------------------------------

export interface ToolSignatureAnalysis {
  /** Whether the primary selection's ONLY detection criterion is a tool-specific filename */
  primaryIsToolSignature: boolean;
  /** Count of fields with tool-specific filenames across all positive selections */
  hasToolSignatureFields: number;
  /** Whether any selection uses behavioral fields (GrantedAccess, CallTrace, etc.) */
  hasBehavioralFields: boolean;
  /** Number of distinct positive selection blocks (OR-level detection variants) */
  detectionVariantCount: number;
  /** Tool-specific filenames found in the detection */
  toolNames: string[];
}

/**
 * Known Windows system binaries.
 * Detecting execution FROM these is behavioral detection — they are OS
 * capabilities, not third-party tools. Rules that detect these are NOT
 * tool-signature rules.
 */
export const KNOWN_SYSTEM_BINARIES = new Set([
  'cmd.exe', 'powershell.exe', 'pwsh.exe', 'rundll32.exe', 'regsvr32.exe',
  'mshta.exe', 'cscript.exe', 'wscript.exe', 'schtasks.exe', 'reg.exe',
  'net.exe', 'net1.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe',
  'msiexec.exe', 'cmstp.exe', 'vssadmin.exe', 'ntdsutil.exe', 'fsutil.exe',
  'taskmgr.exe', 'services.exe', 'svchost.exe', 'lsass.exe', 'explorer.exe',
  'taskhostw.exe', 'dllhost.exe', 'wmiprvse.exe',
]);

/**
 * Behavioral field names that indicate OS-level detection (not tool-specific).
 * Presence of these exempts from tool-signature penalty.
 */
export const BEHAVIORAL_DETECTION_FIELDS = new Set([
  'grantedaccess', 'calltrace', 'targetimage', 'startfunction',
  'parentcommandline', 'targetobject', 'sourceimage',
]);

/**
 * Analyze a Sigma rule for tool-signature dependence.
 *
 * Checks whether the primary detection relies on specific tool filenames
 * (e.g., mimikatz.exe, Seatbelt.exe) rather than behavioral indicators.
 */
export function analyzeToolSignatureDependence(sigma: SigmaRule): ToolSignatureAnalysis {
  const detection = sigma.detection;
  const condition = (detection.condition ?? '').toLowerCase();
  const detectionKeys = Object.keys(detection).filter(k => k !== 'condition');

  // Classify selections into positive vs filter
  const positiveKeys = detectionKeys.filter(k => {
    const nameLower = k.toLowerCase();
    if (nameLower.startsWith('filter') || nameLower.startsWith('exclusion')) return false;
    if (condition.includes(`not ${nameLower}`)) return false;
    return true;
  });

  const result: ToolSignatureAnalysis = {
    primaryIsToolSignature: false,
    hasToolSignatureFields: 0,
    hasBehavioralFields: false,
    detectionVariantCount: positiveKeys.length,
    toolNames: [],
  };

  // Count "1 of selection*" or "1 of them" patterns as having multiple variants
  if (positiveKeys.length === 1) {
    const block = detection[positiveKeys[0]];
    if (Array.isArray(block)) {
      result.detectionVariantCount = block.length;
    }
  }

  let firstPositiveChecked = false;

  for (const key of positiveKeys) {
    const block = detection[key];
    const items = Array.isArray(block) ? block : (typeof block === 'object' && block !== null ? [block] : []);

    for (const item of items) {
      if (typeof item !== 'object' || item === null) continue;
      const fields = item as Record<string, unknown>;

      let hasToolNameOnly = false;
      let selectionFieldCount = 0;
      let selectionBehavioralCount = 0;
      let selectionToolSignatureCount = 0;

      for (const rawKey of Object.keys(fields)) {
        const fieldName = rawKey.split('|')[0].toLowerCase();
        selectionFieldCount++;

        // Check for behavioral fields
        if (BEHAVIORAL_DETECTION_FIELDS.has(fieldName)) {
          result.hasBehavioralFields = true;
          selectionBehavioralCount++;
          continue;
        }

        // Check if Image or OriginalFileName points to a tool (not system binary)
        if (fieldName === 'image' || fieldName === 'originalfilename') {
          const values = normalizeFieldValues(fields[rawKey]);
          const toolValues = values.filter(v => isToolSpecificBinary(v));
          if (toolValues.length > 0) {
            selectionToolSignatureCount++;
            result.hasToolSignatureFields++;
            for (const tv of toolValues) {
              const lastSlash = tv.lastIndexOf('\\');
              const name = lastSlash >= 0 ? tv.substring(lastSlash + 1) : tv;
              result.toolNames.push(name.replace(/^\*+/, '').replace(/\*+$/, ''));
            }
          }
        }
      }

      // A selection is "tool signature only" if its ONLY criterion is a tool
      // filename (Image/OriginalFileName not a system binary) with no
      // behavioral fields alongside
      if (selectionToolSignatureCount > 0 && selectionBehavioralCount === 0
          && selectionFieldCount <= selectionToolSignatureCount) {
        hasToolNameOnly = true;
      }

      // The first positive selection is the "primary"
      if (!firstPositiveChecked && hasToolNameOnly) {
        result.primaryIsToolSignature = true;
      }
    }

    firstPositiveChecked = true;
  }

  return result;
}

/**
 * Check if a Sigma field value references a tool-specific binary
 * (not a known Windows system binary).
 */
function isToolSpecificBinary(value: string): boolean {
  // Extract filename from the value
  const lower = value.toLowerCase().trim();

  // Handle wildcards: *\filename.exe → extract filename
  let filename = lower;
  const lastBackslash = lower.lastIndexOf('\\');
  if (lastBackslash >= 0) {
    filename = lower.substring(lastBackslash + 1);
  }

  // Remove trailing wildcards
  filename = filename.replace(/^\*+/, '').replace(/\*+$/, '');

  // Must end with .exe to be an executable check
  if (!filename.endsWith('.exe')) return false;

  // If it's a known system binary, it's behavioral detection
  if (KNOWN_SYSTEM_BINARIES.has(filename)) return false;

  // Otherwise it's a tool-specific binary
  return true;
}

/**
 * Normalize Sigma field values to a string array.
 */
function normalizeFieldValues(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(v => String(v));
  if (value === null || value === undefined) return [];
  return [String(value)];
}

// ---------------------------------------------------------------------------
// Content Analysis Helpers
// ---------------------------------------------------------------------------

/**
 * Analyze value patterns in Sigma detection blocks.
 */
function analyzeSigmaValues(
  detection: Record<string, unknown>,
  detectionKeys: string[],
): { totalValues: number; hasWildcards: boolean; hasLists: boolean } {
  let totalValues = 0;
  let hasWildcards = false;
  let hasLists = false;

  for (const key of detectionKeys) {
    const block = detection[key];
    if (block && typeof block === 'object' && !Array.isArray(block)) {
      for (const value of Object.values(block as Record<string, unknown>)) {
        if (Array.isArray(value)) {
          hasLists = true;
          totalValues += value.length;
          for (const v of value) {
            if (typeof v === 'string' && v.includes('*')) hasWildcards = true;
          }
        } else {
          totalValues++;
          if (typeof value === 'string' && value.includes('*')) hasWildcards = true;
        }
      }
    }
  }

  return { totalValues, hasWildcards, hasLists };
}

/**
 * Score condition complexity — looks at boolean structure, not just keyword count.
 * Returns 0-2 points.
 */
function scoreConditionComplexity(condition: string): number {
  let pts = 0;

  // Has boolean operators (and/or)
  const hasBooleanOps = /\b(and|or)\b/i.test(condition);
  if (hasBooleanOps) pts += 1;

  // Has negation (not filter) — shows FP awareness in condition
  const hasNot = /\bnot\b/i.test(condition);
  // Has grouping or multiple clauses
  const hasGrouping = condition.includes('(') && condition.includes(')');
  // References multiple named blocks
  const blockRefs = condition.match(/\b(selection\w*|filter\w*|exclusion\w*)\b/gi);
  const uniqueBlocks = new Set(blockRefs?.map(b => b.toLowerCase()) ?? []);

  if ((hasNot && uniqueBlocks.size >= 2) || (hasGrouping && uniqueBlocks.size >= 3)) pts += 1;

  return pts;
}

/**
 * Get the rule description string regardless of format.
 */
function getRuleDescription(rule: GeneratedRule): string {
  if (rule.format === 'sigma' && rule.sigma) return rule.sigma.description;
  if (rule.format === 'yara' && rule.yara) return rule.yara.meta.description;
  if (rule.format === 'suricata' && rule.suricata) {
    const msg = rule.suricata.options.find(o => o.keyword === 'msg');
    return msg?.value ?? '';
  }
  return '';
}

/**
 * Get tags regardless of format.
 */
function getRuleTags(rule: GeneratedRule): string[] {
  if (rule.format === 'sigma' && rule.sigma) return rule.sigma.tags;
  if (rule.format === 'yara' && rule.yara) return rule.yara.tags;
  return [];
}

/**
 * Get inline false positive strings from rule content.
 * Sigma has a dedicated falsepositives[] array; YARA/Suricata don't.
 */
function getInlineFalsePositives(rule: GeneratedRule): string[] {
  if (rule.format === 'sigma' && rule.sigma) {
    return rule.sigma.falsepositives ?? [];
  }
  return [];
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
