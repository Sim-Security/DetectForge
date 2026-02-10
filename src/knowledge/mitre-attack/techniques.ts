/**
 * Technique-oriented query helpers that operate on an AttackKnowledgeBase.
 */

import type { AttackTechnique } from '../../types/mitre-attack.js';
import type {
  AttackKnowledgeBase,
  ParsedTechniqueEntry,
} from './loader.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert a parsed technique entry into the full AttackTechnique shape
 * defined in src/types/mitre-attack.ts.  The only field not present in the
 * parsed JSON is `stixId` and `detectionGuidance`; we default them to empty
 * strings since the download script does not persist them.
 */
function toAttackTechnique(entry: ParsedTechniqueEntry): AttackTechnique {
  return {
    id: entry.id,
    name: entry.name,
    description: entry.description,
    tactics: entry.tactics,
    platforms: entry.platforms,
    dataSources: entry.dataSources,
    detectionGuidance: '',
    isSubtechnique: entry.isSubtechnique,
    ...(entry.parentId !== undefined ? { parentId: entry.parentId } : {}),
    url: entry.url,
    stixId: '',
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Look up a single technique by its ATT&CK ID (e.g. "T1059.001").
 */
export function getTechnique(
  kb: AttackKnowledgeBase,
  id: string,
): AttackTechnique | undefined {
  const entry = kb.techniques[id];
  return entry ? toAttackTechnique(entry) : undefined;
}

/**
 * Full-text keyword search across technique names and descriptions.
 * Returns all techniques whose name or description contain the query
 * (case-insensitive).
 */
export function searchTechniques(
  kb: AttackKnowledgeBase,
  query: string,
): AttackTechnique[] {
  const lowerQuery = query.toLowerCase();
  return Object.values(kb.techniques)
    .filter(
      (t) =>
        t.name.toLowerCase().includes(lowerQuery) ||
        t.description.toLowerCase().includes(lowerQuery),
    )
    .map(toAttackTechnique);
}

/**
 * Return all techniques that belong to the given tactic short-name
 * (e.g. "execution", "persistence").
 */
export function getTechniquesByTactic(
  kb: AttackKnowledgeBase,
  tactic: string,
): AttackTechnique[] {
  const lowerTactic = tactic.toLowerCase();
  return Object.values(kb.techniques)
    .filter((t) => t.tactics.some((tc) => tc.toLowerCase() === lowerTactic))
    .map(toAttackTechnique);
}

/**
 * Return all techniques that target the given platform (e.g. "Windows").
 */
export function getTechniquesByPlatform(
  kb: AttackKnowledgeBase,
  platform: string,
): AttackTechnique[] {
  const lowerPlatform = platform.toLowerCase();
  return Object.values(kb.techniques)
    .filter((t) =>
      t.platforms.some((p) => p.toLowerCase() === lowerPlatform),
    )
    .map(toAttackTechnique);
}

/**
 * Return all sub-techniques of a given parent technique ID (e.g. "T1059").
 */
export function getSubtechniques(
  kb: AttackKnowledgeBase,
  parentId: string,
): AttackTechnique[] {
  return Object.values(kb.techniques)
    .filter((t) => t.isSubtechnique && t.parentId === parentId)
    .map(toAttackTechnique);
}

/**
 * Given a sub-technique ID (e.g. "T1059.001"), return the parent technique.
 */
export function getParentTechnique(
  kb: AttackKnowledgeBase,
  subtechniqueId: string,
): AttackTechnique | undefined {
  const child = kb.techniques[subtechniqueId];
  if (!child || !child.parentId) return undefined;
  return getTechnique(kb, child.parentId);
}

/**
 * Returns true if the given technique ID exists in the knowledge base.
 */
export function validateTechniqueId(
  kb: AttackKnowledgeBase,
  id: string,
): boolean {
  return id in kb.techniques;
}
