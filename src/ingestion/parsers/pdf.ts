/**
 * PDF parser for threat intelligence reports.
 * Extracts text from PDF and structures it into sections.
 */

import pdf from 'pdf-parse';
import { randomUUID } from 'node:crypto';
import type { ThreatReport, ReportSection, SectionType } from '../../types/threat-report.js';

/**
 * Parse a PDF buffer into a structured ThreatReport.
 * Detects section boundaries from headings and classifies content.
 */
export async function parsePdf(buffer: Buffer, filename?: string): Promise<ThreatReport> {
  if (!buffer || buffer.length === 0) {
    return createEmptyReport('pdf', filename || 'unknown.pdf');
  }

  try {
    const data = await pdf(buffer);
    const rawText = data.text;

    if (!rawText || rawText.trim().length === 0) {
      return createEmptyReport('pdf', filename || 'unknown.pdf');
    }

    const sections = extractSections(rawText);
    const metadata = extractMetadata(rawText);
    const title = extractTitle(rawText, sections);

    return {
      id: randomUUID(),
      title,
      source: filename || 'pdf',
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
        reportUrl: metadata.reportUrl,
      },
      inputFormat: 'pdf',
    };
  } catch (error) {
    console.error('PDF parsing error:', error);
    return createEmptyReport('pdf', filename || 'unknown.pdf');
  }
}

/**
 * Extract sections from text based on heading patterns.
 * Looks for:
 * - ALL CAPS lines (at least 3 words)
 * - Lines starting with common section prefixes
 * - Lines followed by === or --- underlines
 */
function extractSections(text: string): ReportSection[] {
  const lines = text.split('\n');
  const sections: ReportSection[] = [];
  let currentHeading = 'Overview';
  let currentContent: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const nextLine = i + 1 < lines.length ? lines[i + 1].trim() : '';

    // Check if this is a heading
    const isHeading =
      isAllCapsHeading(line) ||
      isUnderlinedHeading(line, nextLine) ||
      isSectionPrefix(line);

    if (isHeading && line.length > 0) {
      // Save previous section
      if (currentContent.length > 0) {
        sections.push({
          heading: currentHeading,
          content: currentContent.join('\n').trim(),
          type: classifySection(currentHeading, currentContent.join('\n')),
        });
      }

      // Start new section
      currentHeading = line;
      currentContent = [];

      // Skip underline if present
      if (isUnderlinedHeading(line, nextLine)) {
        i++;
      }
    } else if (line.length > 0) {
      currentContent.push(line);
    }
  }

  // Add final section
  if (currentContent.length > 0) {
    sections.push({
      heading: currentHeading,
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
 * Check if a line is an ALL CAPS heading (at least 3 uppercase words).
 */
function isAllCapsHeading(line: string): boolean {
  const words = line.split(/\s+/).filter(w => w.length > 0);
  if (words.length < 3) return false;

  const capsWords = words.filter(w => /^[A-Z][A-Z0-9\-_]+$/.test(w));
  return capsWords.length >= 3 && capsWords.length === words.length;
}

/**
 * Check if a line is followed by === or --- underline.
 */
function isUnderlinedHeading(_line: string, nextLine: string): boolean {
  return nextLine.length > 0 && /^[=\-]{3,}$/.test(nextLine);
}

/**
 * Check if a line starts with common section prefixes.
 */
function isSectionPrefix(line: string): boolean {
  const prefixes = [
    /^\d+\.\s+[A-Z]/,  // Numbered sections like "1. Overview"
    /^SECTION\s+\d+/i,
    /^CHAPTER\s+\d+/i,
    /^PART\s+\d+/i,
  ];

  return prefixes.some(pattern => pattern.test(line));
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
 * Extract metadata from the report text.
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
    if (match && match[1]) {
      malwareFamilies.push(match[1].trim());
    }
  }
  if (malwareFamilies.length > 0) {
    metadata.malwareFamilies = [...new Set(malwareFamilies)];
  }

  // Extract date
  const dateMatch = text.match(/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b/i);
  if (dateMatch) {
    metadata.date = new Date(dateMatch[0]).toISOString();
  }

  return metadata;
}

/**
 * Extract title from the first heading or first line.
 */
function extractTitle(text: string, sections: ReportSection[]): string {
  if (sections.length > 0 && sections[0].heading) {
    return sections[0].heading;
  }

  const firstLine = text.split('\n')[0]?.trim();
  if (firstLine && firstLine.length > 0 && firstLine.length < 200) {
    return firstLine;
  }

  return 'Untitled Report';
}

/**
 * Create an empty report for error cases.
 */
function createEmptyReport(format: 'pdf' | 'html' | 'markdown' | 'plaintext', source: string): ThreatReport {
  return {
    id: randomUUID(),
    title: 'Empty Report',
    source,
    date: new Date().toISOString(),
    rawText: '',
    sections: [],
    metadata: {},
    inputFormat: format,
  };
}
