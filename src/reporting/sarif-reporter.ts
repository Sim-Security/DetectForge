/**
 * SARIF v2.1.0 report generator.
 *
 * Produces a Static Analysis Results Interchange Format (SARIF) document
 * from generated detection rules for integration with CI/CD pipelines,
 * GitHub Code Scanning, and other SARIF-compatible tools.
 */

import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';

import type { GeneratedRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
}

interface SarifTool {
  driver: SarifDriver;
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRuleDescriptor[];
}

interface SarifRuleDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  properties?: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  level: 'none' | 'note' | 'warning' | 'error';
  message: { text: string };
  properties: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';
const SARIF_VERSION = '2.1.0';
const DETECTFORGE_VERSION = '0.1.0';
const DETECTFORGE_URI = 'https://github.com/Sim-Security/DetectForge';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a SARIF-conformant object from generated detection rules.
 *
 * Each generated rule becomes a SARIF result with:
 * - A `ruleId` derived from ATT&CK technique ID or format-prefixed identifier
 * - A `level` based on validation status: "note" for valid, "warning" for
 *   rules with warnings, "error" for invalid rules
 * - Properties containing ATT&CK technique, tactic, confidence, and
 *   validation details
 *
 * @param rules     - Generated detection rules.
 * @param inputFile - Path to the original threat report input file.
 * @returns A SARIF v2.1.0 compliant object.
 */
export function generateSarifReport(
  rules: GeneratedRule[],
  inputFile: string,
): SarifLog {
  const ruleDescriptors = buildRuleDescriptors(rules);
  const results = buildResults(rules, inputFile);

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'DetectForge',
            version: DETECTFORGE_VERSION,
            informationUri: DETECTFORGE_URI,
            rules: ruleDescriptors,
          },
        },
        results,
      },
    ],
  };
}

/**
 * Write the SARIF report to a JSON file on disk.
 *
 * Creates parent directories if they do not already exist.
 *
 * @param rules      - Generated detection rules.
 * @param inputFile  - Path to the original threat report input file.
 * @param outputPath - Absolute or relative path for the output file.
 */
export function writeSarifReport(
  rules: GeneratedRule[],
  inputFile: string,
  outputPath: string,
): void {
  const report = generateSarifReport(rules, inputFile);
  const dir = dirname(outputPath);
  mkdirSync(dir, { recursive: true });
  writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf-8');
}

// ---------------------------------------------------------------------------
// Internal Builders
// ---------------------------------------------------------------------------

/**
 * Build SARIF rule descriptors (one per unique rule).
 */
function buildRuleDescriptors(rules: GeneratedRule[]): SarifRuleDescriptor[] {
  const descriptors: SarifRuleDescriptor[] = [];
  const seenIds = new Set<string>();

  for (const rule of rules) {
    const ruleId = getSarifRuleId(rule);
    if (seenIds.has(ruleId)) continue;
    seenIds.add(ruleId);

    const name = getRuleName(rule);
    const description = getRuleDescription(rule);

    const descriptor: SarifRuleDescriptor = {
      id: ruleId,
      name,
      shortDescription: { text: description },
    };

    if (rule.documentation?.whatItDetects) {
      descriptor.fullDescription = { text: rule.documentation.whatItDetects };
    }

    if (rule.attackTechniqueId) {
      descriptor.helpUri = `https://attack.mitre.org/techniques/${rule.attackTechniqueId.replace('.', '/')}/`;
      descriptor.properties = {
        'attack-technique': rule.attackTechniqueId,
        'attack-tactic': rule.attackTactic ?? 'unknown',
      };
    }

    descriptors.push(descriptor);
  }

  return descriptors;
}

/**
 * Build SARIF results (one per generated rule).
 */
function buildResults(rules: GeneratedRule[], inputFile: string): SarifResult[] {
  return rules.map(rule => {
    const ruleId = getSarifRuleId(rule);
    const level = determineSarifLevel(rule);
    const message = buildResultMessage(rule, inputFile);

    return {
      ruleId,
      level,
      message: { text: message },
      properties: {
        format: rule.format,
        confidence: rule.confidence,
        attackTechniqueId: rule.attackTechniqueId ?? null,
        attackTactic: rule.attackTactic ?? null,
        sourceReportId: rule.sourceReportId,
        validation: {
          valid: rule.validation.valid,
          syntaxValid: rule.validation.syntaxValid,
          schemaValid: rule.validation.schemaValid,
          errors: rule.validation.errors,
          warnings: rule.validation.warnings,
        },
      },
    };
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Derive a SARIF rule ID from the generated rule.
 *
 * Uses ATT&CK technique ID if available, otherwise constructs a
 * format-prefixed identifier.
 */
function getSarifRuleId(rule: GeneratedRule): string {
  if (rule.attackTechniqueId) {
    return rule.attackTechniqueId;
  }

  if (rule.format === 'sigma' && rule.sigma) {
    return `sigma/${rule.sigma.id || rule.sigma.title}`;
  }
  if (rule.format === 'yara' && rule.yara) {
    return `yara/${rule.yara.name}`;
  }
  if (rule.format === 'suricata' && rule.suricata) {
    return `suricata/SID-${rule.suricata.sid}`;
  }

  return `${rule.format}/unknown`;
}

/**
 * Get a human-readable rule name.
 */
function getRuleName(rule: GeneratedRule): string {
  if (rule.format === 'sigma' && rule.sigma) return rule.sigma.title;
  if (rule.format === 'yara' && rule.yara) return rule.yara.name;
  if (rule.format === 'suricata' && rule.suricata) return `Suricata SID:${rule.suricata.sid}`;
  return `${rule.format}-rule`;
}

/**
 * Get the rule description for the SARIF short description.
 */
function getRuleDescription(rule: GeneratedRule): string {
  if (rule.format === 'sigma' && rule.sigma) return rule.sigma.description;
  if (rule.format === 'yara' && rule.yara) return rule.yara.meta.description;
  if (rule.format === 'suricata' && rule.suricata) {
    const msgOpt = rule.suricata.options.find(o => o.keyword === 'msg');
    return msgOpt?.value ?? 'Suricata detection rule';
  }
  return 'Detection rule generated by DetectForge';
}

/**
 * Determine SARIF severity level from the rule's validation status.
 *
 * - "note": rule is valid with no warnings
 * - "warning": rule is valid but has warnings
 * - "error": rule failed validation
 */
function determineSarifLevel(rule: GeneratedRule): 'note' | 'warning' | 'error' {
  if (!rule.validation.valid) return 'error';
  if (rule.validation.warnings.length > 0) return 'warning';
  return 'note';
}

/**
 * Build a descriptive message for the SARIF result.
 */
function buildResultMessage(rule: GeneratedRule, inputFile: string): string {
  const name = getRuleName(rule);
  const parts: string[] = [
    `Generated ${rule.format} rule "${name}" from ${inputFile}.`,
  ];

  if (rule.attackTechniqueId) {
    parts.push(`Maps to ATT&CK technique ${rule.attackTechniqueId}${rule.attackTactic ? ` (${rule.attackTactic})` : ''}.`);
  }

  parts.push(`Confidence: ${rule.confidence}.`);
  parts.push(`Validation: ${rule.validation.valid ? 'passed' : 'failed'}.`);

  if (rule.validation.errors.length > 0) {
    parts.push(`Errors: ${rule.validation.errors.join('; ')}.`);
  }

  if (rule.validation.warnings.length > 0) {
    parts.push(`Warnings: ${rule.validation.warnings.join('; ')}.`);
  }

  return parts.join(' ');
}
