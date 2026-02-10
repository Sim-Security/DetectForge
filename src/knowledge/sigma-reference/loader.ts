/**
 * SigmaHQ Reference Corpus – Loader & Index
 *
 * Loads the curated SigmaHQ rules from data/sigmahq-rules/, parses them,
 * and provides fast lookup by ATT&CK technique, tactic, logsource category,
 * severity level, and free-text search.
 */

import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { createLogger } from '../../utils/logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SigmaReferenceRule {
  id: string;
  title: string;
  status: string;
  description: string;
  author: string;
  tags: string[];
  attackTechniques: string[];   // Extracted from tags (attack.tXXXX.XXX)
  attackTactics: string[];      // Extracted from tags (attack.initial_access, etc.)
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: Record<string, unknown>;
  level: string;
  falsepositives: string[];
  filePath: string;
  rawYaml: string;
}

export interface CorpusStats {
  totalRules: number;
  byCategory: Record<string, number>;
  byLevel: Record<string, number>;
  byTactic: Record<string, number>;
  techniquesCovered: string[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const logger = createLogger('sigma-reference');

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

/**
 * Extract ATT&CK technique IDs from Sigma tags.
 * Tags like `attack.t1059.001` become `T1059.001`.
 */
function extractTechniques(tags: string[]): string[] {
  return tags
    .filter((tag) => /^attack\.t\d{4}/i.test(tag))
    .map((tag) => tag.replace(/^attack\./i, '').toUpperCase());
}

/**
 * Extract ATT&CK tactic names from Sigma tags.
 * Tags like `attack.execution` become `execution`.
 */
function extractTactics(tags: string[]): string[] {
  return tags
    .filter((tag) => {
      if (!tag.startsWith('attack.')) return false;
      const suffix = tag.replace(/^attack\./, '');
      return TACTIC_NAMES.has(suffix);
    })
    .map((tag) => tag.replace(/^attack\./, ''));
}

/**
 * Recursively collect all .yml files under a directory.
 */
async function collectYmlFiles(dir: string): Promise<string[]> {
  const results: string[] = [];

  if (!existsSync(dir)) {
    return results;
  }

  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      const subFiles = await collectYmlFiles(fullPath);
      results.push(...subFiles);
    } else if (entry.name.endsWith('.yml') || entry.name.endsWith('.yaml')) {
      results.push(fullPath);
    }
  }

  return results;
}

/**
 * Parse a raw YAML string into a SigmaReferenceRule.
 * Returns undefined for malformed rules.
 */
export function parseRuleYaml(
  rawYaml: string,
  filePath: string,
): SigmaReferenceRule | undefined {
  let parsed: unknown;
  try {
    parsed = parseYaml(rawYaml);
  } catch {
    logger.warn(`Failed to parse YAML: ${filePath}`);
    return undefined;
  }

  if (!parsed || typeof parsed !== 'object') {
    logger.warn(`Invalid rule structure: ${filePath}`);
    return undefined;
  }

  const rule = parsed as Record<string, unknown>;

  // A valid Sigma rule must have at minimum a title and detection
  if (!rule.title || !rule.detection) {
    logger.warn(`Missing required fields (title/detection): ${filePath}`);
    return undefined;
  }

  const tags = Array.isArray(rule.tags)
    ? (rule.tags as string[]).map((t) => String(t))
    : [];

  const logsource = (rule.logsource ?? {}) as Record<string, unknown>;
  const falsepositives = Array.isArray(rule.falsepositives)
    ? (rule.falsepositives as unknown[]).map((fp) => String(fp))
    : [];

  return {
    id: String(rule.id ?? ''),
    title: String(rule.title ?? ''),
    status: String(rule.status ?? 'unknown'),
    description: String(rule.description ?? ''),
    author: String(rule.author ?? ''),
    tags,
    attackTechniques: extractTechniques(tags),
    attackTactics: extractTactics(tags),
    logsource: {
      category: logsource.category != null ? String(logsource.category) : undefined,
      product: logsource.product != null ? String(logsource.product) : undefined,
      service: logsource.service != null ? String(logsource.service) : undefined,
    },
    detection: (rule.detection ?? {}) as Record<string, unknown>,
    level: String(rule.level ?? 'unknown'),
    falsepositives,
    filePath,
    rawYaml,
  };
}

// ---------------------------------------------------------------------------
// SigmaReferenceCorpus
// ---------------------------------------------------------------------------

const DEFAULT_DATA_PATH = join(process.cwd(), 'data', 'sigmahq-rules');

export class SigmaReferenceCorpus {
  private rules: SigmaReferenceRule[];
  private indexById: Map<string, SigmaReferenceRule>;
  private indexByTechnique: Map<string, SigmaReferenceRule[]>;
  private indexByTactic: Map<string, SigmaReferenceRule[]>;
  private indexByCategory: Map<string, SigmaReferenceRule[]>;
  private indexByLevel: Map<string, SigmaReferenceRule[]>;

  private constructor(rules: SigmaReferenceRule[]) {
    this.rules = rules;
    this.indexById = new Map();
    this.indexByTechnique = new Map();
    this.indexByTactic = new Map();
    this.indexByCategory = new Map();
    this.indexByLevel = new Map();

    this.buildIndexes();
  }

  // -----------------------------------------------------------------------
  // Construction
  // -----------------------------------------------------------------------

  /**
   * Load the reference corpus from disk.
   * Scans `dataPath` recursively for .yml files and parses each one.
   */
  static async load(dataPath?: string): Promise<SigmaReferenceCorpus> {
    const dir = dataPath ?? DEFAULT_DATA_PATH;

    if (!existsSync(dir)) {
      logger.warn(
        `SigmaHQ data directory not found: ${dir}. ` +
          'Run "bun run data:sigmahq" to download rules.',
      );
      return new SigmaReferenceCorpus([]);
    }

    const ymlFiles = await collectYmlFiles(dir);
    logger.info(`Found ${ymlFiles.length} YAML files in ${dir}`);

    const rules: SigmaReferenceRule[] = [];

    for (const filePath of ymlFiles) {
      try {
        const rawYaml = await readFile(filePath, 'utf-8');
        const relativePath = relative(dir, filePath);
        const rule = parseRuleYaml(rawYaml, relativePath);
        if (rule) {
          rules.push(rule);
        }
      } catch (err) {
        logger.warn(
          `Failed to read ${filePath}: ${(err as Error).message}`,
        );
      }
    }

    logger.info(
      `Loaded ${rules.length} valid Sigma rules from ${ymlFiles.length} files`,
    );

    return new SigmaReferenceCorpus(rules);
  }

  /**
   * Create a corpus from an in-memory array of rules (useful for tests).
   */
  static fromRules(rules: SigmaReferenceRule[]): SigmaReferenceCorpus {
    return new SigmaReferenceCorpus(rules);
  }

  // -----------------------------------------------------------------------
  // Index building
  // -----------------------------------------------------------------------

  private buildIndexes(): void {
    for (const rule of this.rules) {
      // By ID
      if (rule.id) {
        this.indexById.set(rule.id, rule);
      }

      // By technique
      for (const technique of rule.attackTechniques) {
        const existing = this.indexByTechnique.get(technique) ?? [];
        existing.push(rule);
        this.indexByTechnique.set(technique, existing);
      }

      // By tactic
      for (const tactic of rule.attackTactics) {
        const existing = this.indexByTactic.get(tactic) ?? [];
        existing.push(rule);
        this.indexByTactic.set(tactic, existing);
      }

      // By logsource category
      if (rule.logsource.category) {
        const cat = rule.logsource.category;
        const existing = this.indexByCategory.get(cat) ?? [];
        existing.push(rule);
        this.indexByCategory.set(cat, existing);
      }

      // By level
      if (rule.level) {
        const existing = this.indexByLevel.get(rule.level) ?? [];
        existing.push(rule);
        this.indexByLevel.set(rule.level, existing);
      }
    }
  }

  // -----------------------------------------------------------------------
  // Query API
  // -----------------------------------------------------------------------

  getRuleById(id: string): SigmaReferenceRule | undefined {
    return this.indexById.get(id);
  }

  getRulesByTechnique(techniqueId: string): SigmaReferenceRule[] {
    return this.indexByTechnique.get(techniqueId.toUpperCase()) ?? [];
  }

  getRulesByTactic(tactic: string): SigmaReferenceRule[] {
    return this.indexByTactic.get(tactic.toLowerCase()) ?? [];
  }

  getRulesByCategory(category: string): SigmaReferenceRule[] {
    return this.indexByCategory.get(category) ?? [];
  }

  getRulesByLevel(level: string): SigmaReferenceRule[] {
    return this.indexByLevel.get(level.toLowerCase()) ?? [];
  }

  /**
   * Full-text keyword search across rule titles and descriptions.
   * Case-insensitive.
   */
  searchRules(query: string): SigmaReferenceRule[] {
    const lowerQuery = query.toLowerCase();
    return this.rules.filter(
      (rule) =>
        rule.title.toLowerCase().includes(lowerQuery) ||
        rule.description.toLowerCase().includes(lowerQuery),
    );
  }

  getAllRules(): SigmaReferenceRule[] {
    return [...this.rules];
  }

  getStats(): CorpusStats {
    const byCategory: Record<string, number> = {};
    const byLevel: Record<string, number> = {};
    const byTactic: Record<string, number> = {};
    const techniqueSet = new Set<string>();

    for (const rule of this.rules) {
      // Category
      const cat = rule.logsource.category ?? 'uncategorized';
      byCategory[cat] = (byCategory[cat] ?? 0) + 1;

      // Level
      const lvl = rule.level || 'unknown';
      byLevel[lvl] = (byLevel[lvl] ?? 0) + 1;

      // Tactics
      for (const tactic of rule.attackTactics) {
        byTactic[tactic] = (byTactic[tactic] ?? 0) + 1;
      }

      // Techniques
      for (const tech of rule.attackTechniques) {
        techniqueSet.add(tech);
      }
    }

    return {
      totalRules: this.rules.length,
      byCategory,
      byLevel,
      byTactic,
      techniquesCovered: [...techniqueSet].sort(),
    };
  }
}
