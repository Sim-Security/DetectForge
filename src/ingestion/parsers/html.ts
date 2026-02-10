/**
 * HTML parser for threat intelligence reports.
 * Extracts structured content from HTML pages (blogs, advisories, etc.).
 */

import * as cheerio from 'cheerio';
import { randomUUID } from 'node:crypto';
import type { ThreatReport, ReportSection, SectionType } from '../../types/threat-report.js';

/**
 * Parse HTML content into a structured ThreatReport.
 * Strips navigation/chrome, extracts main content, and structures by headings.
 */
export async function parseHtml(html: string, url?: string): Promise<ThreatReport> {
  if (!html || html.trim().length === 0) {
    return createEmptyReport(url || 'unknown.html');
  }

  try {
    const $ = cheerio.load(html);

    // Remove navigation, headers, footers, sidebars
    $('nav, header, footer, .sidebar, .nav, #sidebar, .navigation, .menu, .header, .footer').remove();
    $('script, style, noscript, iframe').remove();

    // Find main content area
    const mainContent = findMainContent($);

    if (!mainContent || mainContent.trim().length === 0) {
      return createEmptyReport(url || 'unknown.html');
    }

    // Extract sections based on heading hierarchy
    const sections = extractSections($, mainContent);
    const metadata = extractMetadata($);
    const title = extractTitle($, sections);
    const rawText = $(mainContent).text().trim();

    return {
      id: randomUUID(),
      title,
      source: url || 'html',
      date: metadata.date || new Date().toISOString(),
      rawText,
      sections,
      metadata: {
        threatActor: metadata.threatActor,
        campaign: metadata.campaign,
        targetSectors: metadata.targetSectors,
        targetRegions: metadata.targetRegions,
        malwareFamilies: metadata.malwareFamilies,
        cveIds: metadata.cveIds,
        reportUrl: url,
      },
      inputFormat: 'html',
    };
  } catch (error) {
    console.error('HTML parsing error:', error);
    return createEmptyReport(url || 'unknown.html');
  }
}

/**
 * Find the main content area in the HTML.
 * Tries common selectors for article/blog content.
 */
function findMainContent($: cheerio.CheerioAPI): string {
  const contentSelectors = [
    'article',
    'main',
    '[role="main"]',
    '.post-content',
    '.entry-content',
    '.article-body',
    '.article-content',
    '.content',
    '.post',
    '.article',
    '#content',
    '#main-content',
  ];

  for (const selector of contentSelectors) {
    const element = $(selector);
    if (element.length > 0) {
      return element.html() || '';
    }
  }

  // Fallback: use body
  return $('body').html() || '';
}

/**
 * Extract sections from HTML based on heading hierarchy (h1-h4).
 */
function extractSections(_$: cheerio.CheerioAPI, html: string): ReportSection[] {
  const $content = cheerio.load(html);
  const sections: ReportSection[] = [];
  const headings = $content('h1, h2, h3, h4');

  if (headings.length === 0) {
    // No headings found, treat entire content as one section
    const text = $content.text().trim();
    if (text.length > 0) {
      sections.push({
        heading: 'Content',
        content: text,
        type: classifySection('Content', text),
      });
    }
    return sections;
  }

  headings.each((_i, elem) => {
    const heading = $content(elem).text().trim();
    const contentParts: string[] = [];

    // Collect content until next heading
    let current = $content(elem).next();
    while (current.length > 0 && !current.is('h1, h2, h3, h4')) {
      const text = extractElementText($content, current);
      if (text.trim().length > 0) {
        contentParts.push(text);
      }
      current = current.next();
    }

    const content = contentParts.join('\n\n').trim();
    if (heading.length > 0 || content.length > 0) {
      sections.push({
        heading: heading || 'Section',
        content,
        type: classifySection(heading, content),
      });
    }
  });

  return sections.length > 0 ? sections : [{
    heading: 'Content',
    content: $content.text().trim(),
    type: 'other',
  }];
}

/**
 * Extract text from an element, preserving structure for code blocks and lists.
 */
function extractElementText($: cheerio.CheerioAPI, element: cheerio.Cheerio<any>): string {
  if (element.is('pre, code')) {
    return `\`\`\`\n${element.text()}\n\`\`\``;
  }

  if (element.is('ul, ol')) {
    const items: string[] = [];
    element.find('li').each((_i, li) => {
      items.push(`- ${$(li).text().trim()}`);
    });
    return items.join('\n');
  }

  if (element.is('table')) {
    return `[Table: ${element.find('tr').length} rows]`;
  }

  return element.text().trim();
}

/**
 * Classify a section based on its heading and content.
 */
function classifySection(heading: string, content: string): SectionType {
  const combined = `${heading} ${content}`.toLowerCase();

  if (/overview|summary|executive|introduction|background|abstract/i.test(combined)) {
    return 'overview';
  }
  if (/technical|detail|analysis|execution|lateral|discovery|persistence|defense evasion|command|reconnaissance/i.test(combined)) {
    return 'technical_details';
  }
  if (/indicator|ioc|compromise|observable|artifact|hash|ip address|domain|file hash|c2|command.and.control/i.test(combined)) {
    return 'iocs';
  }
  if (/ttp|technique|tactic|procedure|mitre|att&ck|attack|behavior|kill chain/i.test(combined)) {
    return 'ttps';
  }
  if (/recommend|mitigation|remediation|detection|response|prevention|action/i.test(combined)) {
    return 'recommendations';
  }

  return 'other';
}

/**
 * Extract metadata from HTML meta tags and content.
 */
function extractMetadata($: cheerio.CheerioAPI): {
  threatActor?: string;
  campaign?: string;
  targetSectors?: string[];
  targetRegions?: string[];
  malwareFamilies?: string[];
  cveIds?: string[];
  date?: string;
} {
  const metadata: Record<string, any> = {};
  const text = $.text();

  // Extract date from meta tags
  const dateSelectors = [
    'meta[property="article:published_time"]',
    'meta[name="publish_date"]',
    'meta[name="date"]',
    'time[datetime]',
    '.published-date',
    '.post-date',
  ];

  for (const selector of dateSelectors) {
    const elem = $(selector);
    if (elem.length > 0) {
      const dateStr = elem.attr('content') || elem.attr('datetime') || elem.text();
      if (dateStr) {
        try {
          metadata.date = new Date(dateStr).toISOString();
          break;
        } catch {
          // Invalid date, continue
        }
      }
    }
  }

  // Extract threat actor
  const threatActorMatch = text.match(/threat\s+actor[:\s]+([A-Za-z0-9\s\-_]+?)(?:\n|$|,|\()/i);
  if (threatActorMatch) {
    metadata.threatActor = threatActorMatch[1].trim();
  }

  // Extract campaign
  const campaignMatch = text.match(/campaign[:\s]+([A-Za-z0-9\s\-_]+?)(?:\n|$|,|\()/i);
  if (campaignMatch) {
    metadata.campaign = campaignMatch[1].trim();
  }

  // Extract CVE IDs
  const cveMatches = text.matchAll(/CVE-\d{4}-\d{4,7}/gi);
  const cveIds = [...new Set([...cveMatches].map(m => m[0]))];
  if (cveIds.length > 0) {
    metadata.cveIds = cveIds;
  }

  // Extract malware families
  const malwarePatterns = [
    /malware[:\s]+([A-Za-z0-9\s\-_]+?)(?:\n|$|,|\()/i,
    /ransomware[:\s]+([A-Za-z0-9\s\-_]+?)(?:\n|$|,|\()/i,
  ];
  const malwareFamilies: string[] = [];
  for (const pattern of malwarePatterns) {
    const match = text.match(pattern);
    if (match) {
      malwareFamilies.push(match[1].trim());
    }
  }
  if (malwareFamilies.length > 0) {
    metadata.malwareFamilies = [...new Set(malwareFamilies)];
  }

  return metadata;
}

/**
 * Extract title from HTML.
 */
function extractTitle($: cheerio.CheerioAPI, sections: ReportSection[]): string {
  // Try title tag
  const titleTag = $('title').text().trim();
  if (titleTag && titleTag.length > 0 && titleTag.length < 200) {
    return titleTag;
  }

  // Try h1
  const h1 = $('h1').first().text().trim();
  if (h1 && h1.length > 0) {
    return h1;
  }

  // Try first section heading
  if (sections.length > 0 && sections[0].heading) {
    return sections[0].heading;
  }

  // Try og:title
  const ogTitle = $('meta[property="og:title"]').attr('content');
  if (ogTitle && ogTitle.length > 0) {
    return ogTitle;
  }

  return 'Untitled Report';
}

/**
 * Create an empty report for error cases.
 */
function createEmptyReport(source: string): ThreatReport {
  return {
    id: randomUUID(),
    title: 'Empty Report',
    source,
    date: new Date().toISOString(),
    rawText: '',
    sections: [],
    metadata: {},
    inputFormat: 'html',
  };
}
