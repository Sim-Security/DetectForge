/**
 * Loads the parsed MITRE ATT&CK knowledge base from disk and exposes it as
 * a singleton so that repeated calls share the same data.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

// ---------------------------------------------------------------------------
// Parsed-file shapes (mirrors the download script output)
// ---------------------------------------------------------------------------

export interface ParsedTechniqueEntry {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  dataSources: string[];
  isSubtechnique: boolean;
  parentId?: string;
  url: string;
}

export interface ParsedTacticEntry {
  id: string;
  name: string;
  shortName: string;
  techniques: string[];
}

export interface ParsedDataSourceEntry {
  name: string;
  techniques: string[];
}

export interface ParsedAttackData {
  techniques: Record<string, ParsedTechniqueEntry>;
  tactics: Record<string, ParsedTacticEntry>;
  dataSources: Record<string, ParsedDataSourceEntry>;
  metadata: {
    version: string;
    lastModified: string;
    techniqueCount: number;
    subtechniqueCount: number;
    tacticCount: number;
  };
}

// ---------------------------------------------------------------------------
// AttackKnowledgeBase
// ---------------------------------------------------------------------------

const DEFAULT_DATA_PATH = join(
  process.cwd(),
  'data',
  'mitre-attack',
  'enterprise-attack-parsed.json',
);

export class AttackKnowledgeBase {
  private static instance: AttackKnowledgeBase | null = null;
  private static loadedPath: string | null = null;

  public readonly data: ParsedAttackData;

  private constructor(data: ParsedAttackData) {
    this.data = data;
  }

  /**
   * Load the knowledge base.  Returns the cached singleton when called with
   * the same `dataPath` (or the default).
   */
  static async load(dataPath?: string): Promise<AttackKnowledgeBase> {
    const resolvedPath = dataPath ?? DEFAULT_DATA_PATH;

    if (
      AttackKnowledgeBase.instance &&
      AttackKnowledgeBase.loadedPath === resolvedPath
    ) {
      return AttackKnowledgeBase.instance;
    }

    const raw = await readFile(resolvedPath, 'utf-8');
    const parsed: ParsedAttackData = JSON.parse(raw);

    const kb = new AttackKnowledgeBase(parsed);
    AttackKnowledgeBase.instance = kb;
    AttackKnowledgeBase.loadedPath = resolvedPath;
    return kb;
  }

  /**
   * Create a knowledge base from an in-memory data object (useful for tests).
   */
  static fromData(data: ParsedAttackData): AttackKnowledgeBase {
    const kb = new AttackKnowledgeBase(data);
    AttackKnowledgeBase.instance = kb;
    AttackKnowledgeBase.loadedPath = null;
    return kb;
  }

  /**
   * Reset the singleton (primarily for tests).
   */
  static reset(): void {
    AttackKnowledgeBase.instance = null;
    AttackKnowledgeBase.loadedPath = null;
  }

  // -----------------------------------------------------------------------
  // Convenience getters
  // -----------------------------------------------------------------------

  get techniques(): Record<string, ParsedTechniqueEntry> {
    return this.data.techniques;
  }

  get tactics(): Record<string, ParsedTacticEntry> {
    return this.data.tactics;
  }

  get dataSources(): Record<string, ParsedDataSourceEntry> {
    return this.data.dataSources;
  }

  get metadata() {
    return this.data.metadata;
  }
}
