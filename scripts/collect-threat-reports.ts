#!/usr/bin/env bun
/**
 * collect-threat-reports.ts
 * Downloads public threat intelligence reports for testing and benchmarking.
 * Reports are saved as markdown in data/threat-reports/reports/
 */

import { mkdir, writeFile, access } from 'node:fs/promises';
import { join } from 'node:path';

const DATA_DIR = join(import.meta.dirname ?? '.', '..', 'data', 'threat-reports');
const REPORTS_DIR = join(DATA_DIR, 'reports');

interface ReportSource {
  id: string;
  title: string;
  source: string;
  url: string;
  threatActor?: string;
  campaign?: string;
  date: string;
  format: 'html' | 'pdf' | 'markdown';
  quality: 'high' | 'medium' | 'low';
  tags: string[];
}

const REPORT_SOURCES: ReportSource[] = [
  {
    id: 'cisa-aa22-277a',
    title: 'Impacket and Exfiltration Tool Used to Steal Sensitive Information',
    source: 'CISA',
    url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-277a',
    date: '2022-10-04',
    format: 'html',
    quality: 'high',
    tags: ['apt', 'lateral-movement', 'credential-access', 'exfiltration'],
  },
  {
    id: 'cisa-aa23-347a',
    title: 'Russian FSB Cyber Actor Star Blizzard Continues Worldwide Spear-Phishing Campaigns',
    source: 'CISA',
    url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a',
    threatActor: 'Star Blizzard / COLDRIVER',
    date: '2023-12-07',
    format: 'html',
    quality: 'high',
    tags: ['apt', 'spear-phishing', 'credential-harvesting', 'russia'],
  },
  {
    id: 'cisa-aa24-131a',
    title: 'Black Basta Ransomware',
    source: 'CISA',
    url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a',
    threatActor: 'Black Basta',
    campaign: 'Black Basta Ransomware',
    date: '2024-05-10',
    format: 'html',
    quality: 'high',
    tags: ['ransomware', 'initial-access', 'lateral-movement', 'exfiltration'],
  },
  {
    id: 'microsoft-midnight-blizzard-2024',
    title: 'Midnight Blizzard: Guidance for responders on nation-state attack',
    source: 'Microsoft',
    url: 'https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/',
    threatActor: 'Midnight Blizzard / APT29 / Cozy Bear',
    campaign: 'Microsoft Corporate Email Compromise',
    date: '2024-01-25',
    format: 'html',
    quality: 'high',
    tags: ['apt29', 'nation-state', 'oauth-abuse', 'password-spray'],
  },
  {
    id: 'mandiant-apt29-diplomatic-phishing',
    title: 'APT29 Uses BMW Car Ad Phishing Lure to Target Diplomats',
    source: 'Unit 42 / Palo Alto',
    url: 'https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/',
    threatActor: 'APT29 / Cloaked Ursa',
    campaign: 'Diplomatic Phishing 2023',
    date: '2023-07-13',
    format: 'html',
    quality: 'high',
    tags: ['apt29', 'spear-phishing', 'html-smuggling', 'diplomats'],
  },
  {
    id: 'crowdstrike-scattered-spider',
    title: 'Scattered Spider: A Closer Look at the Threat Actor',
    source: 'CrowdStrike',
    url: 'https://www.crowdstrike.com/blog/scattered-spider-attempt-to-avoid-detection/',
    threatActor: 'Scattered Spider / UNC3944',
    date: '2023-01-11',
    format: 'html',
    quality: 'high',
    tags: ['scattered-spider', 'social-engineering', 'sim-swapping', 'identity'],
  },
  {
    id: 'elastic-ref-icedid-gziploader',
    title: 'Elastic catches DPRK passing out KANDYKORN',
    source: 'Elastic Security Labs',
    url: 'https://www.elastic.co/security-labs/elastic-catches-dprk-passing-out-kandykorn',
    threatActor: 'Lazarus Group / DPRK',
    campaign: 'KANDYKORN',
    date: '2023-10-31',
    format: 'html',
    quality: 'high',
    tags: ['lazarus', 'dprk', 'crypto', 'supply-chain', 'macos'],
  },
  {
    id: 'dfir-report-icedid-to-dagon-locker',
    title: 'IcedID Brings ScreenConnect and CSharp Streamer to ALPHV Affiliate',
    source: 'The DFIR Report',
    url: 'https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion/',
    campaign: 'IcedID to Ransomware',
    date: '2024-04-01',
    format: 'html',
    quality: 'high',
    tags: ['icedid', 'ransomware', 'cobalt-strike', 'lateral-movement'],
  },
  {
    id: 'dfir-report-bumblebee-to-cobalt',
    title: 'BumbleBee Zeros in on Meterpreter',
    source: 'The DFIR Report',
    url: 'https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/',
    threatActor: 'Bumblebee loader operators',
    campaign: 'BumbleBee to Domain Admin',
    date: '2022-08-08',
    format: 'html',
    quality: 'high',
    tags: ['bumblebee', 'cobalt-strike', 'domain-admin', 'kerberoasting'],
  },
  {
    id: 'sophos-akira-ransomware',
    title: 'Akira Ransomware is "bringin 1988 back"',
    source: 'Sophos',
    url: 'https://news.sophos.com/en-us/2023/05/09/akira-ransomware-is-bringin-1988-back/',
    threatActor: 'Akira',
    campaign: 'Akira Ransomware',
    date: '2023-05-09',
    format: 'html',
    quality: 'medium',
    tags: ['akira', 'ransomware', 'vpn-exploitation', 'encryption'],
  },
  {
    id: 'trendmicro-earth-lusca',
    title: 'Earth Lusca Uses Geopolitical Lure to Target Taiwan',
    source: 'Trend Micro',
    url: 'https://www.trendmicro.com/en_us/research/23/h/earth-lusca-employs-new-linux-backdoor.html',
    threatActor: 'Earth Lusca',
    date: '2023-08-09',
    format: 'html',
    quality: 'medium',
    tags: ['earth-lusca', 'china', 'linux-backdoor', 'geopolitical'],
  },
  {
    id: 'cisa-aa23-136a',
    title: '#StopRansomware: BianLian Ransomware Group',
    source: 'CISA',
    url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a',
    threatActor: 'BianLian',
    campaign: 'BianLian Ransomware',
    date: '2023-05-16',
    format: 'html',
    quality: 'high',
    tags: ['bianlian', 'ransomware', 'rdp', 'extortion'],
  },
  {
    id: 'volexity-ivanti-zero-day-2024',
    title: 'Ivanti Connect Secure VPN Exploitation Goes Global',
    source: 'Volexity',
    url: 'https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/',
    campaign: 'Ivanti VPN Zero-Day',
    date: '2024-01-10',
    format: 'html',
    quality: 'high',
    tags: ['zero-day', 'vpn', 'webshell', 'initial-access'],
  },
  {
    id: 'mandiant-apt28-outlook-ntlm',
    title: 'APT28 Exploits Known Vulnerability To Carry Out Reconnaissance',
    source: 'Microsoft',
    url: 'https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/',
    threatActor: 'APT28 / Forest Blizzard',
    campaign: 'Outlook NTLM Relay',
    date: '2023-03-24',
    format: 'html',
    quality: 'high',
    tags: ['apt28', 'cve-2023-23397', 'ntlm-relay', 'outlook'],
  },
  {
    id: 'sentinelone-alphv-blackcat',
    title: 'ALPHV BlackCat Ransomware Analysis',
    source: 'SentinelOne',
    url: 'https://www.sentinelone.com/labs/blackcat-ransomware/',
    threatActor: 'ALPHV / BlackCat',
    campaign: 'BlackCat Ransomware',
    date: '2022-02-04',
    format: 'html',
    quality: 'medium',
    tags: ['alphv', 'blackcat', 'ransomware', 'rust-malware'],
  },
];

async function ensureDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function downloadReport(source: ReportSource): Promise<void> {
  const outputPath = join(REPORTS_DIR, `${source.id}.txt`);

  if (await fileExists(outputPath)) {
    console.log(`  [skip] ${source.id} — already exists`);
    return;
  }

  try {
    console.log(`  [download] ${source.id} from ${source.source}...`);
    const response = await fetch(source.url, {
      headers: {
        'User-Agent': 'DetectForge/0.1.0 (Security Research Tool)',
        Accept: 'text/html,application/xhtml+xml,text/plain',
      },
      redirect: 'follow',
    });

    if (!response.ok) {
      console.error(`  [error] ${source.id}: HTTP ${response.status}`);
      return;
    }

    const html = await response.text();

    // Basic HTML → text conversion (strip tags, decode entities)
    const text = htmlToText(html);

    const header = [
      `# ${source.title}`,
      '',
      `**Source:** ${source.source}`,
      `**URL:** ${source.url}`,
      `**Date:** ${source.date}`,
      source.threatActor ? `**Threat Actor:** ${source.threatActor}` : '',
      source.campaign ? `**Campaign:** ${source.campaign}` : '',
      '',
      '---',
      '',
    ]
      .filter(Boolean)
      .join('\n');

    await writeFile(outputPath, header + text, 'utf-8');
    console.log(`  [saved] ${source.id} (${text.length} chars)`);
  } catch (err) {
    console.error(`  [error] ${source.id}: ${err instanceof Error ? err.message : err}`);
  }
}

function htmlToText(html: string): string {
  return html
    // Remove script and style blocks
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    // Convert headings to markdown
    .replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, '\n# $1\n')
    .replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, '\n## $1\n')
    .replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, '\n### $1\n')
    .replace(/<h4[^>]*>([\s\S]*?)<\/h4>/gi, '\n#### $1\n')
    // Convert lists
    .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, '- $1\n')
    // Convert paragraphs to newlines
    .replace(/<p[^>]*>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    // Convert code blocks
    .replace(/<pre[^>]*>([\s\S]*?)<\/pre>/gi, '\n```\n$1\n```\n')
    .replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, '`$1`')
    // Convert tables roughly
    .replace(/<tr[^>]*>([\s\S]*?)<\/tr>/gi, '$1\n')
    .replace(/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi, '$1 | ')
    // Strip remaining tags
    .replace(/<[^>]+>/g, '')
    // Decode HTML entities
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    // Clean up whitespace
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

async function main(): Promise<void> {
  console.log('DetectForge — Threat Report Collector');
  console.log('=====================================\n');

  await ensureDir(DATA_DIR);
  await ensureDir(REPORTS_DIR);

  // Save source registry
  const registryPath = join(DATA_DIR, 'sources.json');
  await writeFile(registryPath, JSON.stringify(REPORT_SOURCES, null, 2), 'utf-8');
  console.log(`Saved ${REPORT_SOURCES.length} sources to sources.json\n`);

  // Download reports
  console.log('Downloading reports...');
  for (const source of REPORT_SOURCES) {
    await downloadReport(source);
    // Small delay to be respectful
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  console.log('\nDone!');
}

main().catch(console.error);
