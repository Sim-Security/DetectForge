#!/usr/bin/env bun
/**
 * Bulk CISA advisory fetcher — downloads threat intelligence advisories
 * and converts them to markdown for benchmarking.
 *
 * Run:  bun run scripts/fetch-cisa-advisories.ts
 *
 * Fetches advisories from CISA's public website, extracts the main content,
 * and saves as markdown files in data/benchmark-reports/.
 */

import { writeFileSync, mkdirSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';
import chalk from 'chalk';

// ---------------------------------------------------------------------------
// Known CISA advisories with rich IOCs and ATT&CK mappings
// ---------------------------------------------------------------------------

const ADVISORIES = [
  // Ransomware advisories (most IOC/TTP rich)
  { id: 'aa24-131a', title: 'StopRansomware: Black Basta' },
  { id: 'aa25-203a', title: 'StopRansomware: Interlock' },
  { id: 'aa24-242a', title: 'StopRansomware: RansomHub' },
  { id: 'aa24-060a', title: 'StopRansomware: Phobos' },
  { id: 'aa24-109a', title: 'StopRansomware: Akira' },
  { id: 'aa23-353a', title: 'StopRansomware: ALPHV Blackcat' },
  { id: 'aa23-319a', title: 'StopRansomware: Rhysida' },
  { id: 'aa23-284a', title: 'StopRansomware: AvosLocker' },
  { id: 'aa23-352a', title: 'StopRansomware: Play' },
  { id: 'aa23-158a', title: 'StopRansomware: CL0P' },
  { id: 'aa23-165a', title: 'StopRansomware: LockBit 3.0' },
  { id: 'aa23-075a', title: 'StopRansomware: Royal' },
  { id: 'aa23-061a', title: 'StopRansomware: BianLian' },
  { id: 'aa23-136a', title: 'StopRansomware: Snatch' },
  { id: 'aa24-207a', title: 'StopRansomware: Trinity' },

  // APT/Nation-state advisories
  { id: 'aa24-057a', title: 'SVR Cloud Access Tactics' },
  { id: 'aa25-239a', title: 'Chinese State-Sponsored Actors Global Espionage' },
  { id: 'aa24-241a', title: 'Iran-based Actors Enabling Ransomware' },
  { id: 'aa23-108',  title: 'APT28 Cisco Router Exploitation' },
  { id: 'aa22-110a', title: 'Russian State-Sponsored Threats' },
  { id: 'aa25-338a', title: 'BRICKSTORM Backdoor' },

  // Malware-specific advisories
  { id: 'aa24-016a', title: 'Androxgh0st Malware' },
  { id: 'aa25-022a', title: 'Ivanti Cloud Service Exploitation' },
  { id: 'aa24-290a', title: 'Iranian Cyber Actors Brute Force' },

  // Additional 2023 advisories
  { id: 'aa23-250a', title: 'Scattered Spider' },
  { id: 'aa23-209a', title: 'Volt Typhoon' },
  { id: 'aa23-187a', title: 'IRGC-Affiliated Cyber Actors' },
  { id: 'aa23-144a', title: 'PRC State-Sponsored Cyber Actor Barracuda' },
  { id: 'aa23-129a', title: 'Snake Malware' },
  { id: 'aa23-040a', title: 'Ransomware Attacks on Critical Infrastructure' },

  // 2024-2025 advisories with rich technical content
  { id: 'aa24-038a', title: 'PRC State-Sponsored Actors Compromise US Infrastructure' },
  { id: 'aa25-266a', title: 'CISA Incident Response Lessons Learned' },
];

// ---------------------------------------------------------------------------
// Fetch and convert
// ---------------------------------------------------------------------------

async function fetchAdvisory(id: string, title: string): Promise<string | null> {
  const url = `https://www.cisa.gov/news-events/cybersecurity-advisories/${id}`;

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'DetectForge-Benchmark/1.0 (Security Research)',
        'Accept': 'text/html',
      },
    });

    if (!response.ok) {
      console.log(chalk.red(`  FAIL ${id}: HTTP ${response.status}`));
      return null;
    }

    const html = await response.text();

    // Extract main content from HTML — CISA pages have structured content
    const content = extractContent(html, title, id);

    if (content.length < 500) {
      console.log(chalk.yellow(`  SKIP ${id}: Content too short (${content.length} chars)`));
      return null;
    }

    console.log(chalk.green(`  OK   ${id}: ${title} (${content.length} chars)`));
    return content;
  } catch (err) {
    console.log(chalk.red(`  ERR  ${id}: ${err instanceof Error ? err.message : String(err)}`));
    return null;
  }
}

function extractContent(html: string, title: string, id: string): string {
  // Remove script/style tags
  let text = html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<nav[\s\S]*?<\/nav>/gi, '')
    .replace(/<footer[\s\S]*?<\/footer>/gi, '')
    .replace(/<header[\s\S]*?<\/header>/gi, '');

  // Convert common HTML to markdown
  text = text
    .replace(/<h1[^>]*>(.*?)<\/h1>/gi, '\n# $1\n')
    .replace(/<h2[^>]*>(.*?)<\/h2>/gi, '\n## $1\n')
    .replace(/<h3[^>]*>(.*?)<\/h3>/gi, '\n### $1\n')
    .replace(/<h4[^>]*>(.*?)<\/h4>/gi, '\n#### $1\n')
    .replace(/<li[^>]*>(.*?)<\/li>/gi, '- $1')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<p[^>]*>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<strong>(.*?)<\/strong>/gi, '**$1**')
    .replace(/<em>(.*?)<\/em>/gi, '*$1*')
    .replace(/<code>(.*?)<\/code>/gi, '`$1`')
    .replace(/<a[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '$2')
    .replace(/<table[\s\S]*?<\/table>/gi, (match) => convertTable(match));

  // Strip remaining HTML tags
  text = text.replace(/<[^>]+>/g, '');

  // Clean up entities
  text = text
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/\[.\]/g, '[.]'); // Preserve defanging

  // Clean up whitespace
  text = text
    .replace(/\n{4,}/g, '\n\n\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n +/g, '\n')
    .trim();

  // Add header
  const header = `# ${title} (CISA ${id.toUpperCase()})\n\nSource: https://www.cisa.gov/news-events/cybersecurity-advisories/${id}\n\n`;
  return header + text;
}

function convertTable(tableHtml: string): string {
  const rows: string[][] = [];
  const rowRegex = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
  let rowMatch;

  while ((rowMatch = rowRegex.exec(tableHtml)) !== null) {
    const cells: string[] = [];
    const cellRegex = /<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi;
    let cellMatch;

    while ((cellMatch = cellRegex.exec(rowMatch[1])) !== null) {
      cells.push(cellMatch[1].replace(/<[^>]+>/g, '').trim());
    }

    if (cells.length > 0) {
      rows.push(cells);
    }
  }

  if (rows.length === 0) return '';

  const lines: string[] = [];
  for (let i = 0; i < rows.length; i++) {
    lines.push('| ' + rows[i].join(' | ') + ' |');
    if (i === 0) {
      lines.push('|' + rows[0].map(() => '---').join('|') + '|');
    }
  }

  return '\n' + lines.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const outputDir = join(import.meta.dirname, '..', 'data', 'benchmark-reports');

  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  // Check which advisories we already have
  const existing = new Set(
    readdirSync(outputDir)
      .filter(f => f.endsWith('.md'))
      .map(f => f.replace('.md', '')),
  );

  console.log(chalk.cyan.bold('\n=== CISA Advisory Fetcher ===\n'));
  console.log(chalk.gray(`  Target: ${ADVISORIES.length} advisories`));
  console.log(chalk.gray(`  Existing: ${existing.size} already downloaded`));
  console.log('');

  let fetched = 0;
  let skipped = 0;
  let failed = 0;

  // Process in batches of 5 to be polite to CISA's servers
  const BATCH_SIZE = 5;
  const BATCH_DELAY_MS = 2000;

  for (let i = 0; i < ADVISORIES.length; i += BATCH_SIZE) {
    const batch = ADVISORIES.slice(i, i + BATCH_SIZE);

    const results = await Promise.all(
      batch.map(async (advisory) => {
        const fileName = `cisa-${advisory.id}`;

        if (existing.has(fileName)) {
          skipped++;
          return;
        }

        const content = await fetchAdvisory(advisory.id, advisory.title);

        if (content) {
          writeFileSync(join(outputDir, `${fileName}.md`), content, 'utf-8');
          fetched++;
        } else {
          failed++;
        }
      }),
    );

    // Polite delay between batches
    if (i + BATCH_SIZE < ADVISORIES.length) {
      await new Promise(resolve => setTimeout(resolve, BATCH_DELAY_MS));
    }
  }

  console.log('');
  console.log(chalk.cyan.bold('=== Fetch Complete ==='));
  console.log(`  Fetched: ${fetched}`);
  console.log(`  Skipped: ${skipped} (already exist)`);
  console.log(`  Failed:  ${failed}`);
  console.log(`  Total files: ${fetched + skipped}`);
  console.log('');
  console.log(chalk.gray('Now run: bun run scripts/run-benchmarks.ts'));
}

main().catch((err) => {
  console.error(chalk.red.bold('\nFetch FAILED:'));
  console.error(err);
  process.exit(1);
});
