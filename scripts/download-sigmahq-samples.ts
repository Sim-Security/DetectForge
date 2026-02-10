#!/usr/bin/env bun
/**
 * Download a curated subset of SigmaHQ rules for the reference corpus.
 *
 * Strategy:
 *   1. Shallow-clone the SigmaHQ/sigma repo into a temp directory
 *   2. Copy rules from target category directories into data/sigmahq-rules/
 *   3. Build an index.json mapping each rule file to its ATT&CK techniques
 *
 * Usage:  bun run scripts/download-sigmahq-samples.ts
 *
 * Outputs:
 *   data/sigmahq-rules/<category>/<rule>.yml   -- individual Sigma rules
 *   data/sigmahq-rules/index.json              -- rule file -> ATT&CK mapping
 */

import { existsSync } from 'node:fs';
import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { execSync } from 'node:child_process';
import { parse as parseYaml } from 'yaml';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SIGMA_REPO_URL = 'https://github.com/SigmaHQ/sigma.git';

const DATA_DIR = join(import.meta.dirname ?? '.', '..', 'data', 'sigmahq-rules');

/**
 * Target directories within the SigmaHQ repo to download rules from.
 * These cover the most common and useful detection categories.
 */
const TARGET_DIRS: string[] = [
  'rules/windows/process_creation',
  'rules/windows/image_load',
  'rules/windows/registry',
  'rules/windows/file',
  'rules/windows/network_connection',
  'rules/windows/dns_query',
  'rules/windows/pipe_created',
  'rules/windows/ps_script',
  'rules/windows/builtin/security',
  'rules/linux/process_creation',
  'rules/linux/auditd',
  'rules/cloud/aws',
  'rules/cloud/azure',
  'rules/cloud/gcp',
];

/**
 * Maximum number of rules to keep per category directory.
 * This keeps the total corpus within a manageable 200-500 range.
 */
const MAX_RULES_PER_DIR = 50;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface IndexEntry {
  filePath: string;
  title: string;
  id: string;
  attackTechniques: string[];
  attackTactics: string[];
  level: string;
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
}

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
 * Exclude technique-like tags (attack.tXXXX).
 */
function extractTactics(tags: string[]): string[] {
  return tags
    .filter(
      (tag) =>
        tag.startsWith('attack.') &&
        !/^attack\.t\d{4}/i.test(tag) &&
        !tag.startsWith('attack.g') &&
        !tag.startsWith('attack.s'),
    )
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('[download-sigmahq] Starting SigmaHQ rule download...');

  // Create output directory
  await mkdir(DATA_DIR, { recursive: true });

  // Create a temporary directory for the clone
  const tmpDir = join(import.meta.dirname ?? '.', '..', '.tmp-sigma-clone');

  try {
    // Clone the SigmaHQ repo (shallow, depth 1) if not already present
    if (existsSync(tmpDir)) {
      console.log('[download-sigmahq] Removing previous temp clone...');
      await rm(tmpDir, { recursive: true, force: true });
    }

    console.log('[download-sigmahq] Cloning SigmaHQ/sigma (shallow)...');
    execSync(`git clone --depth 1 "${SIGMA_REPO_URL}" "${tmpDir}"`, {
      stdio: 'inherit',
      timeout: 300_000, // 5 minutes
    });

    console.log('[download-sigmahq] Clone complete. Copying rules...');

    const index: IndexEntry[] = [];
    let totalCopied = 0;

    for (const targetDir of TARGET_DIRS) {
      const srcDir = join(tmpDir, targetDir);

      if (!existsSync(srcDir)) {
        console.log(`[download-sigmahq]   SKIP (not found): ${targetDir}`);
        continue;
      }

      // Derive category name from the directory path
      // e.g., "rules/windows/process_creation" -> "windows/process_creation"
      const category = targetDir.replace(/^rules\//, '');
      const destDir = join(DATA_DIR, category);
      await mkdir(destDir, { recursive: true });

      // Collect all yml files
      const ymlFiles = await collectYmlFiles(srcDir);

      // Sort by filename for deterministic selection, then limit
      ymlFiles.sort((a, b) => basename(a).localeCompare(basename(b)));
      const selectedFiles = ymlFiles.slice(0, MAX_RULES_PER_DIR);

      let dirCopied = 0;

      for (const srcFile of selectedFiles) {
        const fileName = basename(srcFile);
        const destFile = join(destDir, fileName);

        // Idempotent: skip if file already exists and has content
        if (existsSync(destFile)) {
          // Still index it
          try {
            const content = await readFile(destFile, 'utf-8');
            const parsed = parseYaml(content);
            if (parsed && typeof parsed === 'object') {
              const rule = parsed as Record<string, unknown>;
              const tags = Array.isArray(rule.tags)
                ? (rule.tags as string[])
                : [];
              const logsource = (rule.logsource ?? {}) as Record<
                string,
                unknown
              >;

              index.push({
                filePath: join(category, fileName),
                title: (rule.title as string) ?? '',
                id: (rule.id as string) ?? '',
                attackTechniques: extractTechniques(tags),
                attackTactics: extractTactics(tags),
                level: (rule.level as string) ?? '',
                logsource: {
                  category: logsource.category as string | undefined,
                  product: logsource.product as string | undefined,
                  service: logsource.service as string | undefined,
                },
              });
            }
          } catch {
            // Skip malformed files in index
          }
          dirCopied++;
          continue;
        }

        // Copy the file
        try {
          await cp(srcFile, destFile);

          // Parse for index
          const content = await readFile(srcFile, 'utf-8');
          const parsed = parseYaml(content);
          if (parsed && typeof parsed === 'object') {
            const rule = parsed as Record<string, unknown>;
            const tags = Array.isArray(rule.tags)
              ? (rule.tags as string[])
              : [];
            const logsource = (rule.logsource ?? {}) as Record<
              string,
              unknown
            >;

            index.push({
              filePath: join(category, fileName),
              title: (rule.title as string) ?? '',
              id: (rule.id as string) ?? '',
              attackTechniques: extractTechniques(tags),
              attackTactics: extractTactics(tags),
              level: (rule.level as string) ?? '',
              logsource: {
                category: logsource.category as string | undefined,
                product: logsource.product as string | undefined,
                service: logsource.service as string | undefined,
              },
            });
          }

          dirCopied++;
        } catch (err) {
          console.warn(
            `[download-sigmahq]   WARN: Failed to copy ${fileName}: ${(err as Error).message}`,
          );
        }
      }

      totalCopied += dirCopied;
      console.log(
        `[download-sigmahq]   ${category}: ${dirCopied} rules (of ${ymlFiles.length} available)`,
      );
    }

    // Write index file
    const indexPath = join(DATA_DIR, 'index.json');
    await writeFile(indexPath, JSON.stringify(index, null, 2), 'utf-8');
    console.log(`[download-sigmahq] Wrote index -> ${indexPath}`);

    // Summary stats
    const techniqueSet = new Set(
      index.flatMap((entry) => entry.attackTechniques),
    );
    const tacticSet = new Set(index.flatMap((entry) => entry.attackTactics));
    console.log(
      `[download-sigmahq] Done. ${totalCopied} rules downloaded, ` +
        `covering ${techniqueSet.size} ATT&CK techniques across ${tacticSet.size} tactics.`,
    );
  } finally {
    // Clean up the temp clone
    if (existsSync(tmpDir)) {
      console.log('[download-sigmahq] Cleaning up temp clone...');
      await rm(tmpDir, { recursive: true, force: true });
    }
  }
}

main().catch((err) => {
  console.error('[download-sigmahq] Fatal error:', err);
  process.exit(1);
});
