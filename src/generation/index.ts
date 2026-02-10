/**
 * Detection rule generation modules.
 *
 * This barrel re-exports all generation sub-modules so consumers can
 * import from a single path:
 *
 * ```ts
 * import { generateSigmaRules, validateSigmaRule } from '@/generation/index.js';
 * ```
 */

// --- Sigma ---
export {
  // Templates
  getTemplate,
  getAllTemplates,
  getSuggestedCategory,
  // Generator
  generateSigmaRules,
  // Validator
  validateSigmaRule,
  validateSigmaYaml,
} from './sigma/index.js';

export type {
  SigmaTemplate,
  SigmaGenerationOptions,
  SigmaGenerationResult,
} from './sigma/index.js';

// --- YARA ---
export {
  // Templates
  getYaraTemplate,
  getAllYaraTemplates,
  suggestYaraCategory,
  // Generator
  generateYaraRules,
  // Validator
  validateYaraRule,
  validateYaraRaw,
} from './yara/index.js';

export type {
  YaraTemplate,
  YaraGenerationOptions,
  YaraGenerationResult,
} from './yara/index.js';

// --- Suricata ---
export {
  // Templates
  getSuricataTemplate,
  getAllSuricataTemplates,
  suggestSuricataCategory,
  // Generator
  generateSuricataRules,
  // Validator
  validateSuricataRule,
  validateSuricataRaw,
  validateSuricataRuleSet,
} from './suricata/index.js';

export type {
  SuricataTemplate,
  SuricataGenerationOptions,
  SuricataGenerationResult,
} from './suricata/index.js';
