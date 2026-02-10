/**
 * Markdown parser for threat intelligence reports.
 * Parses markdown structure using regex patterns.
 */

import yaml from 'yaml';
import { randomUUID } from 'node:crypto';
import type { ThreatReport, ReportSection, SectionType } from '../../types/threat-report.js';

/**
 * Parse markdown text into a structured ThreatReport.
 * Handles YAML frontmatter, heading hierarchy, and preserves code blocks.
 */
export function parseMarkdown(text: string, filename?: string): ThreatReport {
  if (!text || text.trim().length === 0) {
    return createEmptyReport(filename || 'unknown.md');
  }

  try {
    // Extract YAML frontmatter if present
    const { frontmatter, content } = extractFrontmatter(text);

    // Extract sections based on markdown headings
    const sections = extractSections(content);
    const metadata = extractMetadata(content);
    const title = extractTitle(content, sections, frontmatter);

    return {
      id: randomUUID(),
      title,
      source: filename || 'markdown',
      date: metadata.date || frontmatter?.date || new Date().toISOString(),
      rawText: content,
      sections,
      metadata: {
        threatActor: metadata.threatActor || frontmatter?.threatActor,
        campaign: metadata.campaign || frontmatter?.campaign,
        targetSectors: metadata.targetSectors || frontmatter?.targetSectors,
        targetRegions: metadata.targetRegions || frontmatter?.targetRegions,
        malwareFamilies: metadata.malwareFamilies || frontmatter?.malwareFamilies,
        cveIds: metadata.cveIds || frontmatter?.cveIds,
        reportUrl: metadata.reportUrl || frontmatter?.reportUrl || frontmatter?.url,
      },
      inputFormat: 'markdown',
    };
  } catch (error) {
    console.error('Markdown parsing error:', error);
    return createEmptyReport(filename || 'unknown.md');
  }
}

/**
 * Extract YAML frontmatter from markdown.
 * Frontmatter is delimited by --- at the start and end.
 */
function extractFrontmatter(text: string): { frontmatter: Record<string, any> | null; content: string } {
  const frontmatterMatch = text.match(/^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/);

  if (frontmatterMatch) {
    try {
      const frontmatter = yaml.parse(frontmatterMatch[1]);
      return {
        frontmatter,
        content: frontmatterMatch[2],
      };
    } catch {
      // Invalid YAML, treat as regular content
      return { frontmatter: null, content: text };
    }
  }

  return { frontmatter: null, content: text };
}

/**
 * Extract sections from markdown based on heading hierarchy.
 * Headings are lines starting with # (h1), ## (h2), etc.
 */
function extractSections(text: string): ReportSection[] {
  const lines = text.split('\n');
  const sections: ReportSection[] = [];
  let currentHeading = '';
  let currentContent: string[] = [];
  let inCodeBlock = false;

  for (const line of lines) {
    // Track code block state to avoid treating # in code as headings
    if (line.trim().startsWith('```')) {
      inCodeBlock = !inCodeBlock;
      currentContent.push(line);
      continue;
    }

    // Check if this is a heading (only if not in code block)
    const headingMatch = !inCodeBlock && line.match(/^(#{1,6})\s+(.+)$/);

    if (headingMatch) {
      // Save previous section
      if (currentHeading || currentContent.length > 0) {
        sections.push({
          heading: currentHeading || 'Introduction',
          content: currentContent.join('\n').trim(),
          type: classifySection(currentHeading, currentContent.join('\n')),
        });
      }

      // Start new section
      currentHeading = headingMatch[2].trim();
      currentContent = [];
    } else {
      currentContent.push(line);
    }
  }

  // Add final section
  if (currentHeading || currentContent.length > 0) {
    sections.push({
      heading: currentHeading || 'Content',
      content: currentContent.join('\n').trim(),
      type: classifySection(currentHeading, currentContent.join('\n')),
    });
  }

  // Ensure at least one section exists
  if (sections.length === 0) {
    sections.push({
      heading: 'Content',
      content: text.trim(),
      type: 'other',
    });
  }

  return sections;
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
 * Extract metadata from markdown content.
 */
function extractMetadata(text: string): {
  threatActor?: string;
  campaign?: string;
  targetSectors?: string[];
  targetRegions?: string[];
  malwareFamilies?: string[];
  cveIds?: string[];
  reportUrl?: string;
  date?: string;
} {
  const metadata: Record<string, any> = {};

  // Extract threat actor
  const threatActorMatch = text.match(/\*\*threat\s+actor[:\s]*\*\*[:\s]*([A-Za-z0-9\s\-_()\/]+?)(?:\n|$)/i) ||
    text.match(/threat\s+actor[:\s]+([A-Za-z0-9\s\-_()\/]+?)(?:\n|$)/i);
  if (threatActorMatch) {
    metadata.threatActor = threatActorMatch[1].trim();
  }

  // Extract campaign
  const campaignMatch = text.match(/\*\*campaign[:\s]*\*\*[:\s]*([A-Za-z0-9\s\-_]+?)(?:\n|$)/i) ||
    text.match(/campaign[:\s]+([A-Za-z0-9\s\-_]+?)(?:\n|$)/i);
  if (campaignMatch) {
    metadata.campaign = campaignMatch[1].trim();
  }

  // Extract date
  const dateMatch = text.match(/\*\*date[:\s]*\*\*[:\s]*([A-Za-z0-9\s,]+?)(?:\n|$)/i) ||
    text.match(/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b/i);
  if (dateMatch) {
    try {
      metadata.date = new Date(dateMatch[1] || dateMatch[0]).toISOString();
    } catch {
      // Invalid date
    }
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
 * Extract title from markdown.
 */
function extractTitle(text: string, sections: ReportSection[], frontmatter: Record<string, any> | null): string {
  // Try frontmatter title
  if (frontmatter?.title) {
    return frontmatter.title;
  }

  // Try first h1 heading
  const h1Match = text.match(/^#\s+(.+)$/m);
  if (h1Match) {
    return h1Match[1].trim();
  }

  // Try first section heading
  if (sections.length > 0 && sections[0].heading) {
    return sections[0].heading;
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
    inputFormat: 'markdown',
  };
}
