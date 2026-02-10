#!/usr/bin/env bun
/**
 * Download and parse MITRE ATT&CK Enterprise STIX 2.1 data.
 *
 * Usage:  bun run scripts/download-attack-data.ts
 *
 * Outputs:
 *   data/mitre-attack/enterprise-attack.json         – raw STIX bundle
 *   data/mitre-attack/enterprise-attack-parsed.json   – parsed/indexed lookup
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ATTACK_STIX_URL =
  'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';

const DATA_DIR = join(import.meta.dirname ?? '.', '..', 'data', 'mitre-attack');

// ---------------------------------------------------------------------------
// STIX helpers (lightweight – no external deps)
// ---------------------------------------------------------------------------

interface StixObject {
  type: string;
  id: string;
  name?: string;
  description?: string;
  modified?: string;
  created?: string;
  external_references?: Array<{
    source_name?: string;
    external_id?: string;
    url?: string;
  }>;
  kill_chain_phases?: Array<{
    kill_chain_name: string;
    phase_name: string;
  }>;
  x_mitre_platforms?: string[];
  x_mitre_data_sources?: string[];
  x_mitre_is_subtechnique?: boolean;
  x_mitre_shortname?: string;
  x_mitre_detection?: string;
  x_mitre_deprecated?: boolean;
  revoked?: boolean;
  source_ref?: string;
  target_ref?: string;
  relationship_type?: string;
  x_mitre_version?: string;
  spec_version?: string;
  x_mitre_attack_spec_version?: string;
}

interface StixBundle {
  type: 'bundle';
  id: string;
  spec_version?: string;
  objects: StixObject[];
}

interface ParsedTechnique {
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

interface ParsedTactic {
  id: string;
  name: string;
  shortName: string;
  techniques: string[];
}

interface ParsedDataSource {
  name: string;
  techniques: string[];
}

interface ParsedData {
  techniques: Record<string, ParsedTechnique>;
  tactics: Record<string, ParsedTactic>;
  dataSources: Record<string, ParsedDataSource>;
  metadata: {
    version: string;
    lastModified: string;
    techniqueCount: number;
    subtechniqueCount: number;
    tacticCount: number;
  };
}

// ---------------------------------------------------------------------------
// Extract ATT&CK external ID from a STIX object
// ---------------------------------------------------------------------------

function getAttackId(obj: StixObject): string | undefined {
  return obj.external_references?.find(
    (ref) => ref.source_name === 'mitre-attack',
  )?.external_id;
}

function getAttackUrl(obj: StixObject): string {
  return (
    obj.external_references?.find(
      (ref) => ref.source_name === 'mitre-attack',
    )?.url ?? ''
  );
}

// ---------------------------------------------------------------------------
// Parse the STIX bundle into our indexed structure
// ---------------------------------------------------------------------------

function parseBundle(bundle: StixBundle): ParsedData {
  const techniques: Record<string, ParsedTechnique> = {};
  const tactics: Record<string, ParsedTactic> = {};
  const dataSources: Record<string, ParsedDataSource> = {};

  // Pass 1: collect attack-patterns (techniques) --------------------------------
  for (const obj of bundle.objects) {
    if (obj.type !== 'attack-pattern') continue;
    if (obj.revoked || obj.x_mitre_deprecated) continue;

    const attackId = getAttackId(obj);
    if (!attackId) continue;

    const tacticNames =
      obj.kill_chain_phases
        ?.filter((kc) => kc.kill_chain_name === 'mitre-attack')
        .map((kc) => kc.phase_name) ?? [];

    const isSubtechnique = obj.x_mitre_is_subtechnique === true;
    const parentId = isSubtechnique ? attackId.split('.')[0] : undefined;

    techniques[attackId] = {
      id: attackId,
      name: obj.name ?? '',
      description: obj.description ?? '',
      tactics: tacticNames,
      platforms: obj.x_mitre_platforms ?? [],
      dataSources: obj.x_mitre_data_sources ?? [],
      isSubtechnique,
      ...(parentId ? { parentId } : {}),
      url: getAttackUrl(obj),
    };
  }

  // Pass 2: collect x-mitre-tactic -------------------------------------------
  for (const obj of bundle.objects) {
    if (obj.type !== 'x-mitre-tactic') continue;
    if (obj.revoked || obj.x_mitre_deprecated) continue;

    const attackId = getAttackId(obj);
    if (!attackId) continue;

    const shortName = obj.x_mitre_shortname ?? '';
    // Collect techniques that belong to this tactic
    const tacticTechniques = Object.values(techniques)
      .filter((t) => t.tactics.includes(shortName))
      .map((t) => t.id);

    tactics[attackId] = {
      id: attackId,
      name: obj.name ?? '',
      shortName,
      techniques: tacticTechniques,
    };
  }

  // Pass 3: collect x-mitre-data-source --------------------------------------
  for (const obj of bundle.objects) {
    if (obj.type !== 'x-mitre-data-source') continue;
    if (obj.revoked || obj.x_mitre_deprecated) continue;

    const name = obj.name ?? '';
    if (!name) continue;

    // Find techniques whose dataSources mention this data source name
    const relatedTechniques = Object.values(techniques)
      .filter((t) =>
        t.dataSources.some((ds) =>
          ds.toLowerCase().startsWith(name.toLowerCase()),
        ),
      )
      .map((t) => t.id);

    dataSources[name] = {
      name,
      techniques: relatedTechniques,
    };
  }

  // Build metadata -----------------------------------------------------------
  const techniqueCount = Object.values(techniques).filter(
    (t) => !t.isSubtechnique,
  ).length;
  const subtechniqueCount = Object.values(techniques).filter(
    (t) => t.isSubtechnique,
  ).length;

  let lastModified = '';
  for (const obj of bundle.objects) {
    if (obj.modified && obj.modified > lastModified) {
      lastModified = obj.modified;
    }
  }

  const versionObj = bundle.objects.find(
    (o) => o.type === 'x-mitre-collection',
  );
  const version =
    versionObj?.x_mitre_version ??
    versionObj?.x_mitre_attack_spec_version ??
    'unknown';

  const metadata = {
    version,
    lastModified,
    techniqueCount,
    subtechniqueCount,
    tacticCount: Object.keys(tactics).length,
  };

  return { techniques, tactics, dataSources, metadata };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('[download-attack-data] Downloading Enterprise ATT&CK STIX bundle...');

  const response = await fetch(ATTACK_STIX_URL);
  if (!response.ok) {
    throw new Error(
      `Failed to download ATT&CK data: ${response.status} ${response.statusText}`,
    );
  }

  const rawText = await response.text();
  const bundle: StixBundle = JSON.parse(rawText);
  console.log(
    `[download-attack-data] Downloaded bundle with ${bundle.objects.length} STIX objects.`,
  );

  // Ensure output directory exists
  await mkdir(DATA_DIR, { recursive: true });

  // Save the raw STIX bundle
  const rawPath = join(DATA_DIR, 'enterprise-attack.json');
  await writeFile(rawPath, rawText, 'utf-8');
  console.log(`[download-attack-data] Saved raw bundle  -> ${rawPath}`);

  // Parse and save
  const parsed = parseBundle(bundle);
  const parsedPath = join(DATA_DIR, 'enterprise-attack-parsed.json');
  await writeFile(parsedPath, JSON.stringify(parsed, null, 2), 'utf-8');

  console.log(`[download-attack-data] Saved parsed data -> ${parsedPath}`);
  console.log(
    `[download-attack-data] Techniques: ${parsed.metadata.techniqueCount} ` +
      `(+${parsed.metadata.subtechniqueCount} subtechniques), ` +
      `Tactics: ${parsed.metadata.tacticCount}, ` +
      `Data Sources: ${Object.keys(parsed.dataSources).length}`,
  );
}

main().catch((err) => {
  console.error('[download-attack-data] Fatal error:', err);
  process.exit(1);
});
