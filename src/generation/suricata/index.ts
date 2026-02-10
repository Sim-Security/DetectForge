/**
 * Suricata rule generation module — public API.
 *
 * Re-exports templates, generator, and validator for convenient consumption.
 */

export {
  getSuricataTemplate,
  getAllSuricataTemplates,
  suggestSuricataCategory,
} from './templates.js';
export type { SuricataTemplate } from './templates.js';

export {
  generateSuricataRules,
} from './generator.js';
export type {
  SuricataGenerationOptions,
  SuricataGenerationResult,
} from './generator.js';

export {
  validateSuricataRule,
  validateSuricataRaw,
  validateSuricataRuleSet,
} from './validator.js';
