/**
 * Sigma rule generation module.
 *
 * Re-exports the template catalog, rule generator, validator, and AI prompt
 * utilities so consumers can import everything from a single path:
 *
 * ```ts
 * import { generateSigmaRules, validateSigmaRule, getTemplate } from '@/generation/sigma/index.js';
 * ```
 */

// --- Templates ---
export type { SigmaTemplate } from './templates.js';
export { getTemplate, getAllTemplates, getSuggestedCategory } from './templates.js';

// --- Generator ---
export type { SigmaGenerationOptions, SigmaGenerationResult } from './generator.js';
export { generateSigmaRules } from './generator.js';

// --- Validator ---
export { validateSigmaRule, validateSigmaYaml } from './validator.js';
