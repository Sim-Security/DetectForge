/**
 * Rule effectiveness tester.
 *
 * Evaluates each Sigma rule's true-positive and false-positive rates by:
 * 1. Generating synthetic attack and benign logs via log-generator.ts
 * 2. Running the rule against both log sets via sigma-tester.ts
 * 3. Computing TP/FP/TN/FN rates and a pass/fail verdict
 *
 * All evaluation is in-memory with zero API calls.
 */

import type { SigmaRule } from '@/types/detection-rule.js';
import { generateTestLogs, generateEvasionVariants } from './log-generator.js';
import type { GeneratedLogSet, EvasionResult } from './log-generator.js';
export type { EvasionResult } from './log-generator.js';
import { evaluateSigmaRuleSuite } from './sigma-tester.js';
import type { SigmaTestSuiteResult, LogEntry } from './sigma-tester.js';
import { validateRuleFields } from './field-validator.js';
import type { FieldValidationResult } from './field-validator.js';
import { getTemplatesForTechnique, TECHNIQUE_TEMPLATES } from './technique-templates.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface RuleConfidence {
  level: 'high' | 'medium' | 'low' | 'experimental';
  score: number;        // 0-100
  factors: string[];    // human-readable reasons
}

export interface RealDataSignal {
  /** Best-dataset TP rate from real data */
  realTpRate: number;
  /** Synthetic TP rate */
  syntheticTpRate: number;
  /** Hold-out verdict */
  holdOutVerdict?: 'pass' | 'fail' | 'no-holdout';
  /** Standard deviation of per-dataset TP rates */
  perDatasetVariance?: number;
}

export interface EffectivenessResult {
  ruleId: string;
  ruleTitle: string;
  /** Raw suite metrics from sigma-tester (structural — rule-echo logs). */
  suite: SigmaTestSuiteResult;
  /** Field validation result. */
  fieldValidation: FieldValidationResult;
  /** Behavioral TP rate against technique-realistic logs (null if no templates). */
  behavioralTpRate: number | null;
  /** Evasion resilience test result (null if no attack logs). */
  evasionResilience: EvasionResult | null;
  /** Confidence assessment of the rule's robustness. */
  confidence: RuleConfidence;
  /** Whether the rule passes all quality gate thresholds. */
  pass: boolean;
  /** Reasons for failure (empty if pass). */
  failures: string[];
}

export interface EffectivenessThresholds {
  /** Minimum TP rate (0-1). Default: 0.8 */
  minTpRate?: number;
  /** Maximum FP rate (0-1). Default: 0.1 */
  maxFpRate?: number;
  /** Minimum field validity rate (0-1). Default: 0.7 */
  minFieldValidity?: number;
}

export interface EffectivenessSummary {
  totalRules: number;
  passedRules: number;
  failedRules: number;
  avgTpRate: number;
  avgFpRate: number;
  avgFieldValidity: number;
  results: EffectivenessResult[];
}

export interface EffectivenessOptions {
  /** Number of attack logs to generate per rule. Default: 10 */
  attackLogCount?: number;
  /** Number of benign logs to generate per rule. Default: 20 */
  benignLogCount?: number;
  /** Pass/fail thresholds. */
  thresholds?: EffectivenessThresholds;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_THRESHOLDS: Required<EffectivenessThresholds> = {
  minTpRate: 0.8,
  maxFpRate: 0.1,
  minFieldValidity: 0.7,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Test a single Sigma rule's effectiveness.
 *
 * Generates synthetic logs, evaluates the rule against them, and checks
 * the results against configurable thresholds.
 */
export function testRuleEffectiveness(
  rule: SigmaRule,
  options?: EffectivenessOptions,
): EffectivenessResult {
  const attackCount = options?.attackLogCount ?? 10;
  const benignCount = options?.benignLogCount ?? 20;
  const thresholds = {
    ...DEFAULT_THRESHOLDS,
    ...options?.thresholds,
  };

  // Generate test logs
  const logSet: GeneratedLogSet = generateTestLogs(rule, {
    attackLogCount: attackCount,
    benignLogCount: benignCount,
  });

  // Evaluate rule against logs
  const suite: SigmaTestSuiteResult = evaluateSigmaRuleSuite(
    rule,
    logSet.attackLogs,
    logSet.benignLogs,
  );

  // Validate fields
  const fieldValidation: FieldValidationResult = validateRuleFields(rule);

  // Behavioral evaluation: test rule against technique-realistic logs
  const behavioralTpRate = evaluateBehavioralTp(rule);

  // Evasion resilience: test rule against mutated attack logs
  const evasionResilience = evaluateEvasionResilience(rule, logSet, suite);

  // Confidence assessment
  const confidence = assessConfidence(rule, behavioralTpRate, evasionResilience);

  // Check thresholds
  const failures: string[] = [];

  if (suite.tpRate < thresholds.minTpRate) {
    failures.push(
      `TP rate ${pct(suite.tpRate)} < minimum ${pct(thresholds.minTpRate)}`,
    );
  }

  if (suite.fpRate > thresholds.maxFpRate) {
    failures.push(
      `FP rate ${pct(suite.fpRate)} > maximum ${pct(thresholds.maxFpRate)}`,
    );
  }

  if (
    !fieldValidation.unknownLogsource &&
    fieldValidation.fieldValidityRate < thresholds.minFieldValidity
  ) {
    failures.push(
      `Field validity ${pct(fieldValidation.fieldValidityRate)} < minimum ${pct(thresholds.minFieldValidity)}` +
        ` (invalid: ${fieldValidation.invalidFields.join(', ')})`,
    );
  }

  return {
    ruleId: rule.id,
    ruleTitle: rule.title,
    suite,
    fieldValidation,
    behavioralTpRate,
    evasionResilience,
    confidence,
    pass: failures.length === 0,
    failures,
  };
}

/**
 * Test multiple rules and return an aggregate summary.
 */
export function testRulesEffectiveness(
  rules: SigmaRule[],
  options?: EffectivenessOptions,
): EffectivenessSummary {
  const results = rules.map((rule) => testRuleEffectiveness(rule, options));

  const totalRules = results.length;
  const passedRules = results.filter((r) => r.pass).length;
  const failedRules = totalRules - passedRules;

  const avgTpRate =
    totalRules === 0
      ? 0
      : results.reduce((sum, r) => sum + r.suite.tpRate, 0) / totalRules;

  const avgFpRate =
    totalRules === 0
      ? 0
      : results.reduce((sum, r) => sum + r.suite.fpRate, 0) / totalRules;

  const avgFieldValidity =
    totalRules === 0
      ? 0
      : results.reduce((sum, r) => sum + r.fieldValidation.fieldValidityRate, 0) /
        totalRules;

  return {
    totalRules,
    passedRules,
    failedRules,
    avgTpRate,
    avgFpRate,
    avgFieldValidity,
    results,
  };
}

// ---------------------------------------------------------------------------
// Behavioral Evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate a rule against technique-realistic log templates.
 *
 * Returns the TP rate against templates that match the rule's ATT&CK
 * technique and logsource category. Returns null if no templates exist.
 */
function evaluateBehavioralTp(rule: SigmaRule): number | null {
  // Extract ATT&CK technique IDs from rule tags
  const techniques = rule.tags
    .filter((t) => /^attack\.t\d{4}/i.test(t))
    .map((t) => t.replace(/^attack\./i, '').toUpperCase());

  if (techniques.length === 0) return null;

  const category = rule.logsource.category ?? rule.logsource.service ?? '';

  // Collect templates from all matching techniques
  const templateLogs: LogEntry[] = [];
  for (const tech of techniques) {
    const templates = getTemplatesForTechnique(tech, category);
    for (const t of templates) {
      templateLogs.push(t.fields as LogEntry);
    }
  }

  if (templateLogs.length === 0) return null;

  // Evaluate rule against the technique-realistic logs
  const result = evaluateSigmaRuleSuite(rule, templateLogs, []);
  return result.tpRate;
}

// ---------------------------------------------------------------------------
// Confidence Assessment
// ---------------------------------------------------------------------------

/**
 * Known behavioral field names that indicate OS-level detection.
 */
const BEHAVIORAL_FIELDS = new Set([
  'grantedaccess', 'calltrace', 'targetimage', 'startfunction',
  'sourceimage', 'targetobject', 'parentcommandline',
]);

/**
 * Known system binaries — detecting execution FROM these is behavioral.
 */
const CONFIDENCE_SYSTEM_BINARIES = new Set([
  'cmd.exe', 'powershell.exe', 'pwsh.exe', 'rundll32.exe', 'regsvr32.exe',
  'mshta.exe', 'cscript.exe', 'wscript.exe', 'schtasks.exe', 'reg.exe',
  'net.exe', 'net1.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe',
  'msiexec.exe', 'cmstp.exe', 'vssadmin.exe', 'ntdsutil.exe', 'fsutil.exe',
  'taskmgr.exe', 'services.exe', 'svchost.exe', 'lsass.exe', 'explorer.exe',
  'taskhostw.exe', 'dllhost.exe', 'wmiprvse.exe',
]);

/**
 * Assess the confidence level of a rule based on multiple factors:
 * behavioral field usage, evasion resilience, technique template coverage,
 * detection variant breadth, and optionally real-data performance.
 */
export function assessConfidence(
  rule: SigmaRule,
  behavioralTpRate: number | null,
  evasionResilience: EvasionResult | null,
  realDataSignal?: RealDataSignal,
): RuleConfidence {
  let score = 50; // start at neutral
  const factors: string[] = [];

  // Extract technique IDs from tags
  const techniques = rule.tags
    .filter((t) => /^attack\.t\d{4}/i.test(t))
    .map((t) => t.replace(/^attack\./i, '').toUpperCase());

  // Factor 1: Has technique templates (+15)
  const hasTemplates = techniques.some((tech) => {
    const templates = TECHNIQUE_TEMPLATES.get(tech);
    if (templates && templates.length > 0) return true;
    // Check parent technique
    if (tech.includes('.')) {
      const parent = tech.split('.')[0];
      return (TECHNIQUE_TEMPLATES.get(parent)?.length ?? 0) > 0;
    }
    return false;
  });

  if (hasTemplates) {
    score += 15;
    factors.push('Has behavioral technique templates (+15)');
  } else if (techniques.length > 0) {
    score -= 15;
    factors.push('Unknown technique — no reference templates (-15)');
  }

  // Factor 2: Behavioral TP rate from templates (+15)
  if (behavioralTpRate !== null && behavioralTpRate > 0) {
    score += 15;
    factors.push(`Behavioral TP rate ${(behavioralTpRate * 100).toFixed(0)}% (+15)`);
  }

  // Factor 3: Evasion resilience (+25 or -30)
  if (evasionResilience) {
    if (evasionResilience.resilienceScore >= 0.6) {
      score += 25;
      factors.push(`Evasion resilience ${(evasionResilience.resilienceScore * 100).toFixed(0)}% (+25)`);
    } else if (evasionResilience.resilienceScore < 0.2 && evasionResilience.originalTpRate > 0.5) {
      score -= 30;
      factors.push(`Tool-signature primary detection — evasion ${(evasionResilience.resilienceScore * 100).toFixed(0)}% (-30)`);
    }
  }

  // Factor 4: Uses behavioral fields (+15)
  const detection = rule.detection;
  const detectionKeys = Object.keys(detection).filter(k => k !== 'condition');
  let usesBehavioralFields = false;

  for (const key of detectionKeys) {
    const block = detection[key];
    if (typeof block === 'object' && block !== null) {
      const items = Array.isArray(block) ? block : [block];
      for (const item of items) {
        if (typeof item === 'object' && item !== null) {
          for (const fieldKey of Object.keys(item as Record<string, unknown>)) {
            const fieldName = fieldKey.split('|')[0].toLowerCase();
            if (BEHAVIORAL_FIELDS.has(fieldName)) {
              usesBehavioralFields = true;
            }
          }
        }
      }
    }
  }

  if (usesBehavioralFields) {
    score += 15;
    factors.push('Uses behavioral fields (GrantedAccess, CallTrace, etc.) (+15)');
  }

  // Factor 5: Multiple detection variants (+10)
  const positiveKeys = detectionKeys.filter(k => {
    const lower = k.toLowerCase();
    return !lower.startsWith('filter') && !lower.startsWith('exclusion');
  });

  let variantCount = positiveKeys.length;
  if (positiveKeys.length === 1) {
    const block = detection[positiveKeys[0]];
    if (Array.isArray(block)) variantCount = block.length;
  }

  if (variantCount >= 3) {
    score += 10;
    factors.push(`Multiple detection variants (${variantCount}) (+10)`);
  } else if (variantCount <= 1) {
    score -= 10;
    factors.push('Single detection variant (-10)');
  }

  // Factor 6: Check for tool-signature primary (Image field with non-system binary)
  for (const key of positiveKeys) {
    const block = detection[key];
    const items = Array.isArray(block) ? block : (typeof block === 'object' && block !== null ? [block] : []);
    for (const item of items) {
      if (typeof item !== 'object' || item === null) continue;
      const fields = item as Record<string, unknown>;
      for (const fieldKey of Object.keys(fields)) {
        const fieldName = fieldKey.split('|')[0].toLowerCase();
        if (fieldName === 'image' || fieldName === 'originalfilename') {
          const vals = Array.isArray(fields[fieldKey])
            ? (fields[fieldKey] as unknown[]).map(String)
            : [String(fields[fieldKey])];
          const hasToolName = vals.some(v => {
            const filename = v.toLowerCase().split('\\').pop()?.replace(/^\*+/, '') ?? '';
            return filename.endsWith('.exe') && !CONFIDENCE_SYSTEM_BINARIES.has(filename);
          });
          if (hasToolName && !usesBehavioralFields && Object.keys(fields).length <= 2) {
            // Only penalize if not already penalized by evasion
            if (!evasionResilience || evasionResilience.resilienceScore >= 0.2) {
              score -= 15;
              factors.push('Tool-specific filename as primary detection (-15)');
            }
          }
        }
      }
    }
    break; // only check first positive selection for "primary"
  }

  // Factor 7: Synthetic-real gap penalty
  if (realDataSignal) {
    const gap = realDataSignal.syntheticTpRate - realDataSignal.realTpRate;
    if (gap > 0.5) {
      score -= 20;
      factors.push(`Large synthetic-real gap (${pct(gap)}) (-20)`);
    } else if (gap > 0.3) {
      score -= 10;
      factors.push(`Moderate synthetic-real gap (${pct(gap)}) (-10)`);
    }

    // Factor 8: Hold-out failure
    if (realDataSignal.holdOutVerdict === 'fail') {
      score -= 15;
      factors.push('Failed hold-out validation (-15)');
    }

    // Factor 9: High per-dataset variance
    if (realDataSignal.perDatasetVariance !== undefined && realDataSignal.perDatasetVariance > 0.3) {
      score -= 10;
      factors.push(`High per-dataset variance (${pct(realDataSignal.perDatasetVariance)}) (-10)`);
    }
  }

  // Clamp to 0-100
  score = Math.max(0, Math.min(100, score));

  // Determine level
  let level: RuleConfidence['level'];
  if (score >= 75) level = 'high';
  else if (score >= 50) level = 'medium';
  else if (score >= 25) level = 'low';
  else level = 'experimental';

  return { level, score, factors };
}

// ---------------------------------------------------------------------------
// Evasion Resilience Evaluation
// ---------------------------------------------------------------------------

/**
 * Test a rule against evasion-mutated versions of its attack logs.
 *
 * Generates variants that rename tools, change paths, and vary argument
 * formats while preserving behavioral indicators (GrantedAccess, TargetImage
 * for system processes, etc.).
 *
 * A rule with 100% structural TP but 0% evasion TP is a tool-signature rule.
 */
function evaluateEvasionResilience(
  rule: SigmaRule,
  logSet: GeneratedLogSet,
  originalSuite: SigmaTestSuiteResult,
): EvasionResult | null {
  if (logSet.attackLogs.length === 0) return null;
  if (originalSuite.tpRate === 0) return null;

  const { mutatedLogs, mutationsApplied } = generateEvasionVariants(
    logSet.attackLogs,
  );

  if (mutatedLogs.length === 0) return null;

  // Test rule against mutated logs
  const evasionSuite = evaluateSigmaRuleSuite(rule, mutatedLogs, []);

  const evasionTpRate = evasionSuite.tpRate;
  const resilienceScore = originalSuite.tpRate > 0
    ? evasionTpRate / originalSuite.tpRate
    : 0;

  return {
    originalTpRate: originalSuite.tpRate,
    evasionTpRate,
    resilienceScore: Math.min(resilienceScore, 1),
    mutationsApplied,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pct(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}
