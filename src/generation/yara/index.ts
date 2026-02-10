/**
 * YARA rule generation module.
 *
 * Re-exports all public APIs from the YARA sub-modules:
 * - templates  — Category-specific YARA templates and suggestion logic
 * - generator  — AI-driven rule generation orchestrator
 * - validator  — Structural and syntactic rule validation
 */

export {
  type YaraTemplate,
  getYaraTemplate,
  getAllYaraTemplates,
  suggestYaraCategory,
} from './templates.js';

export {
  type YaraGenerationOptions,
  type YaraGenerationResult,
  generateYaraRules,
} from './generator.js';

export {
  validateYaraRule,
  validateYaraRaw,
} from './validator.js';
