/**
 * Plaintext parser for threat intelligence reports.
 * Handles plain text advisories, especially CISA-style format.
 */

import { randomUUID } from 'node:crypto';
import type { ThreatReport, ReportSection, SectionType } from '../../types/threat-report.js';

/**
 * Parse plaintext content into a structured ThreatReport.
 * Detects section boundaries from various text patterns.
 */
export function parsePlaintext(text: string, filename?: string): ThreatReport {
  if (!text || text.trim().length === 0) {
    return createEmptyReport(filename || 'unknown.txt');
  }

  try {
    const sections = extractSections(text);
    const metadata = extractMetadata(text);
    const title = extractTitle(text, sections);

    return {
      id: randomUUID(),
      title,
      source: filename || 'plaintext',
      date: metadata.date || new Date().toISOString(),
      rawText: text,
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
      inputFormat: 'plaintext',
    };
  } catch (error) {
    console.error('Plaintext parsing error:', error);
    return createEmptyReport(filename || 'unknown.txt');
  }
}

/**
 * Extract sections from plaintext based on various boundary patterns.
 * Handles:
 * - ALL CAPS lines (section headers)
 * - Lines followed by === or --- underlines
 * - Numbered sections (1., 2., etc. or I., II., etc.)
 * - CISA-style sections (SUMMARY, TECHNICAL DETAILS, etc.)
 */
function extractSections(text: string): ReportSection[] {
  const lines = text.split('\n');
  const sections: ReportSection[] = [];
  let currentHeading = '';
  let currentContent: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const nextLine = i + 1 < lines.length ? lines[i + 1].trim() : '';

    // Check if this is a heading
    const isHeading =
      isAllCapsHeading(line) ||
      isUnderlinedHeading(line, nextLine) ||
      isNumberedSection(line) ||
      isCisaStyleSection(line);

    if (isHeading && line.length > 0) {
      // Save previous section
      if (currentContent.length > 0 || currentHeading) {
        sections.push({
          heading: currentHeading || 'Introduction',
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
    } else if (line.length > 0 || currentContent.length > 0) {
      // Add line to current section (preserve blank lines within sections)
      currentContent.push(lines[i]); // Use original line to preserve formatting
    }
  }

  // Add final section
  if (currentContent.length > 0 || currentHeading) {
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
 * Check if a line is an ALL CAPS heading.
 * Must be at least 3 words and all uppercase.
 */
function isAllCapsHeading(line: string): boolean {
  // Remove common punctuation
  const cleaned = line.replace(/[:\-.]/g, ' ');
  const words = cleaned.split(/\s+/).filter(w => w.length > 0);

  if (words.length < 2) return false;

  // Check if at least 80% of words are all caps
  const capsWords = words.filter(w => /^[A-Z][A-Z0-9]*$/.test(w));
  return capsWords.length >= words.length * 0.8 && line.length < 100;
}

/**
 * Check if a line is followed by === or --- underline.
 */
function isUnderlinedHeading(_line: string, nextLine: string): boolean {
  return nextLine.length >= 3 && /^[=\-]{3,}$/.test(nextLine);
}

/**
 * Check if a line is a numbered section heading.
 * Examples: "1. Overview", "I. INTRODUCTION", "Section 1:", "1.1 Background"
 */
function isNumberedSection(line: string): boolean {
  const patterns = [
    /^\d+\.\s+[A-Z]/,           // "1. Overview"
    /^\d+\.\d+\s+[A-Z]/,        // "1.1 Background"
    /^[IVX]+\.\s+[A-Z]/,        // Roman numerals "I. INTRODUCTION"
    /^Section\s+\d+/i,          // "Section 1:"
    /^\[\d+\]/,                 // "[1]"
  ];

  return patterns.some(pattern => pattern.test(line)) && line.length < 100;
}

/**
 * Check if a line is a CISA-style section header.
 * Common sections: SUMMARY, TECHNICAL DETAILS, INDICATORS OF COMPROMISE, etc.
 */
function isCisaStyleSection(line: string): boolean {
  const cisaSections = [
    /^SUMMARY$/i,
    /^TECHNICAL\s+DETAILS$/i,
    /^INDICATORS?\s+OF\s+COMPROMISE$/i,
    /^RECOMMENDED\s+ACTIONS?$/i,
    /^MITIGATIONS?$/i,
    /^BACKGROUND$/i,
    /^OVERVIEW$/i,
    /^THREAT\s+DESCRIPTION$/i,
    /^DETECTION\s+AND\s+RESPONSE$/i,
  ];

  return cisaSections.some(pattern => pattern.test(line));
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
 * Extract metadata from plaintext content.
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
  const threatActorMatch = text.match(/threat\s+actor[:\s]+([A-Za-z0-9\s\-_()\/]+?)(?:\n|$)/i);
  if (threatActorMatch) {
    metadata.threatActor = threatActorMatch[1].trim();
  }

  // Extract campaign
  const campaignMatch = text.match(/campaign[:\s]+([A-Za-z0-9\s\-_]+?)(?:\n|$)/i);
  if (campaignMatch) {
    metadata.campaign = campaignMatch[1].trim();
  }

  // Extract date
  const dateMatch = text.match(/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b/i);
  if (dateMatch) {
    try {
      metadata.date = new Date(dateMatch[0]).toISOString();
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
    if (match && match[1]) {
      malwareFamilies.push(match[1].trim());
    }
  }
  if (malwareFamilies.length > 0) {
    metadata.malwareFamilies = [...new Set(malwareFamilies)];
  }

  // Extract target sectors
  const sectorMatch = text.match(/target(?:ed)?\s+sectors?[:\s]+([A-Za-z0-9\s\-_,]+?)(?:\n\n|$)/i);
  if (sectorMatch) {
    metadata.targetSectors = sectorMatch[1].split(',').map(s => s.trim()).filter(s => s.length > 0);
  }

  return metadata;
}

/**
 * Extract title from plaintext.
 */
function extractTitle(text: string, sections: ReportSection[]): string {
  // Try first non-empty line
  const firstLine = text.split('\n').find(line => line.trim().length > 0);
  if (firstLine && firstLine.trim().length > 0 && firstLine.trim().length < 150) {
    return firstLine.trim();
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
    inputFormat: 'plaintext',
  };
}
