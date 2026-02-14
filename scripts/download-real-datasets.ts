#!/usr/bin/env bun
/**
 * Download OTRF Security-Datasets for real attack log testing.
 *
 * Downloads 15 curated datasets covering ATT&CK techniques relevant to
 * DetectForge's 76 Sigma rules. Archives are extracted and saved as JSON
 * to data/real-attack-logs/.
 *
 * Usage:  bun run scripts/download-real-datasets.ts
 */

import { DATASET_CATALOG } from '@/testing/real-data/dataset-catalog.js';
import { downloadDatasets } from '@/testing/real-data/dataset-downloader.js';

async function main(): Promise<void> {
  console.log('DetectForge — OTRF Dataset Downloader');
  console.log('=====================================\n');
  console.log(`Catalog: ${DATASET_CATALOG.length} datasets\n`);

  console.log('Datasets to download:');
  for (const entry of DATASET_CATALOG) {
    console.log(`  ${entry.id.padEnd(45)} ${entry.attackTechniqueId.padEnd(12)} ${entry.sizeEstimate}`);
  }
  console.log('');

  const result = await downloadDatasets();

  console.log('\n' + '='.repeat(50));
  console.log('DOWNLOAD SUMMARY');
  console.log('='.repeat(50));
  console.log(`  Total:       ${result.total}`);
  console.log(`  Downloaded:  ${result.downloaded}`);
  console.log(`  Skipped:     ${result.skipped} (already cached)`);
  console.log(`  Failed:      ${result.failed}`);

  if (result.failed > 0) {
    console.log('\nFailed downloads:');
    for (const d of result.details.filter((d) => d.status === 'failed')) {
      console.log(`  ${d.id}: ${d.error}`);
    }
  }

  console.log('');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
