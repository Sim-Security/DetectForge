/**
 * Downloads OTRF Security-Datasets archives and extracts JSON log files.
 *
 * Supports .zip and .tar.gz archives. Downloads are idempotent — already-
 * downloaded files are skipped unless force is set.
 */

import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { readdir, writeFile, readFile } from 'node:fs/promises';
import { execSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import type { DatasetEntry } from './dataset-catalog.js';
import { DATASET_CATALOG } from './dataset-catalog.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DownloadResult {
  total: number;
  downloaded: number;
  skipped: number;
  failed: number;
  details: DownloadDetail[];
}

export interface DownloadDetail {
  id: string;
  status: 'downloaded' | 'skipped' | 'failed';
  path?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROJECT_ROOT = resolve(import.meta.dirname ?? '.', '..', '..', '..');
const DEFAULT_OUTPUT_DIR = join(PROJECT_ROOT, 'data', 'real-attack-logs');

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Download OTRF dataset archives, extract JSON files, and save them.
 *
 * @param catalogEntries  Datasets to download (defaults to full catalog)
 * @param outputDir       Directory for extracted JSON files
 */
export async function downloadDatasets(
  catalogEntries?: DatasetEntry[],
  outputDir?: string,
): Promise<DownloadResult> {
  const entries = catalogEntries ?? DATASET_CATALOG;
  const dir = outputDir ?? DEFAULT_OUTPUT_DIR;

  // Ensure output directory exists
  mkdirSync(dir, { recursive: true });

  const details: DownloadDetail[] = [];
  let downloaded = 0;
  let skipped = 0;
  let failed = 0;

  for (const entry of entries) {
    const jsonPath = join(dir, `${entry.id}.json`);

    // Skip if already downloaded
    if (existsSync(jsonPath)) {
      details.push({ id: entry.id, status: 'skipped', path: jsonPath });
      skipped++;
      continue;
    }

    try {
      console.log(`  Downloading ${entry.id} (${entry.sizeEstimate})...`);
      const logs = await fetchAndExtract(entry);

      if (logs.length === 0) {
        details.push({
          id: entry.id,
          status: 'failed',
          error: 'No JSON log entries found in archive',
        });
        failed++;
        continue;
      }

      await writeFile(jsonPath, JSON.stringify(logs, null, 2));
      console.log(`    -> ${logs.length} log entries saved to ${entry.id}.json`);

      details.push({ id: entry.id, status: 'downloaded', path: jsonPath });
      downloaded++;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`    -> FAILED: ${message}`);
      details.push({ id: entry.id, status: 'failed', error: message });
      failed++;
    }
  }

  return { total: entries.length, downloaded, skipped, failed, details };
}

/**
 * Load all previously downloaded dataset JSON files from the output dir.
 */
export async function loadDownloadedDatasets(
  outputDir?: string,
): Promise<Map<string, unknown[]>> {
  const dir = outputDir ?? DEFAULT_OUTPUT_DIR;
  const datasets = new Map<string, unknown[]>();

  if (!existsSync(dir)) return datasets;

  const files = await readdir(dir);
  for (const file of files) {
    if (!file.endsWith('.json')) continue;
    const id = file.replace('.json', '');
    try {
      const content = await readFile(join(dir, file), 'utf-8');
      const logs = JSON.parse(content);
      if (Array.isArray(logs)) {
        datasets.set(id, logs);
      }
    } catch {
      // Skip malformed files
    }
  }

  return datasets;
}

// ---------------------------------------------------------------------------
// Internal: Fetch + Extract
// ---------------------------------------------------------------------------

/**
 * Fetch an archive from URL and extract JSON log entries from it.
 */
async function fetchAndExtract(entry: DatasetEntry): Promise<unknown[]> {
  const response = await fetch(entry.url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const buffer = Buffer.from(await response.arrayBuffer());

  if (entry.format === 'zip') {
    return extractZip(buffer);
  } else {
    return extractTarGz(buffer);
  }
}

/**
 * Extract JSON log entries from a zip archive buffer.
 */
async function extractZip(buffer: Buffer): Promise<unknown[]> {
  const tmpDir = join(DEFAULT_OUTPUT_DIR, '.tmp_extract');
  mkdirSync(tmpDir, { recursive: true });

  const zipPath = join(tmpDir, 'archive.zip');
  await writeFile(zipPath, buffer);

  try {
    execSync(`unzip -o -q "${zipPath}" -d "${tmpDir}"`, { stdio: 'pipe' });
    return await collectJsonLogs(tmpDir);
  } finally {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

/**
 * Extract JSON log entries from a .tar.gz archive buffer.
 */
async function extractTarGz(buffer: Buffer): Promise<unknown[]> {
  const tmpDir = join(DEFAULT_OUTPUT_DIR, '.tmp_extract');
  mkdirSync(tmpDir, { recursive: true });

  const tarPath = join(tmpDir, 'archive.tar.gz');
  await writeFile(tarPath, buffer);

  try {
    execSync(`tar -xzf "${tarPath}" -C "${tmpDir}"`, { stdio: 'pipe' });
    return await collectJsonLogs(tmpDir);
  } finally {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

/**
 * Recursively collect JSON log entries from all .json files in a directory.
 *
 * OTRF datasets store logs as either:
 * - A JSON array of event objects
 * - Newline-delimited JSON (NDJSON) where each line is an event
 */
async function collectJsonLogs(dir: string): Promise<unknown[]> {
  const logs: unknown[] = [];
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });

  for (const entry of entries) {
    if (!entry.name.endsWith('.json')) continue;

    const parentDir = entry.parentPath ?? dir;
    const filePath = join(parentDir, entry.name);

    try {
      const content = await readFile(filePath, 'utf-8');
      const trimmed = content.trim();

      if (trimmed.startsWith('[')) {
        // JSON array
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          logs.push(...parsed);
        }
      } else if (trimmed.startsWith('{')) {
        // NDJSON — one JSON object per line
        for (const line of trimmed.split('\n')) {
          const l = line.trim();
          if (l.startsWith('{')) {
            try {
              logs.push(JSON.parse(l));
            } catch {
              // Skip malformed lines
            }
          }
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  return logs;
}
