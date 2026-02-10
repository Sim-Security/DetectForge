/**
 * Unified normalizer for threat intelligence reports.
 * Auto-detects format and delegates to appropriate parser.
 */

import type { ThreatReport, InputFormat, SectionType } from '../types/threat-report.js';
import { parsePdf } from './parsers/pdf.js';
import { parseHtml } from './parsers/html.js';
import { parseMarkdown } from './parsers/markdown.js';
import { parsePlaintext } from './parsers/plaintext.js';

export interface NormalizeOptions {
  filename?: string;
  url?: string;
  format?: InputFormat;
}

/**
 * Normalize a report from any format into a ThreatReport.
 * Auto-detects format if not specified.
 */
export async function normalizeReport(
  input: string | Buffer,
  options: NormalizeOptions = {}
): Promise<ThreatReport> {
  const { filename, url, format } = options;

  // Detect format if not specified
  const detectedFormat = format || detectFormat(input, filename);

  // Delegate to appropriate parser
  let report: ThreatReport;

  switch (detectedFormat) {
    case 'pdf':
      if (typeof input === 'string') {
        throw new Error('PDF input must be a Buffer');
      }
      report = await parsePdf(input, filename);
      break;

    case 'html':
      report = await parseHtml(input.toString(), url || filename);
      break;

    case 'markdown':
      report = parseMarkdown(input.toString(), filename);
      break;

    case 'plaintext':
      report = parsePlaintext(input.toString(), filename);
      break;

    case 'stix':
    case 'json':
      throw new Error(`Format ${detectedFormat} not yet implemented`);

    default:
      throw new Error(`Unknown format: ${detectedFormat}`);
  }

  // Validate report
  if (!report.id || typeof report.rawText !== 'string') {
    throw new Error('Invalid report: missing required fields');
  }

  // Classify any unclassified sections
  report.sections = report.sections.map(section => {
    if (section.type === 'other') {
      return {
        ...section,
        type: classifySection(section.heading, section.content),
      };
    }
    return section;
  });

  return report;
}

/**
 * Auto-detect the format of the input.
 * Uses file extension and content sniffing.
 */
export function detectFormat(input: string | Buffer, filename?: string): InputFormat {
  // Try file extension first
  if (filename) {
    const ext = filename.toLowerCase().split('.').pop();
    switch (ext) {
      case 'pdf':
        return 'pdf';
      case 'html':
      case 'htm':
        return 'html';
      case 'md':
      case 'markdown':
        return 'markdown';
      case 'txt':
        return 'plaintext';
      case 'json':
        return 'json';
      case 'stix':
        return 'stix';
    }
  }

  // Content sniffing
  if (Buffer.isBuffer(input)) {
    const header = input.slice(0, 10).toString('utf-8');
    if (header.startsWith('%PDF')) {
      return 'pdf';
    }
    // Convert to string for further checks
    input = input.toString('utf-8');
  }

  const text = input.toString().trim();

  // Check for HTML
  if (text.startsWith('<') || text.includes('<!DOCTYPE') || text.includes('<html')) {
    return 'html';
  }

  // Check for JSON/STIX
  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      const parsed = JSON.parse(text);
      if (parsed.type === 'bundle' || parsed.spec_version) {
        return 'stix';
      }
      return 'json';
    } catch {
      // Not valid JSON
    }
  }

  // Check for markdown (starts with # or has YAML frontmatter)
  if (text.startsWith('#') || text.startsWith('---\n')) {
    return 'markdown';
  }

  // Check for markdown-style headings
  if (/^#{1,6}\s+.+$/m.test(text)) {
    return 'markdown';
  }

  // Default to plaintext
  return 'plaintext';
}

/**
 * Classify a section based on its heading and content.
 * This is the canonical classification function used by all parsers.
 */
export function classifySection(heading: string, content: string): SectionType {
  const combined = `${heading} ${content}`.toLowerCase();

  // Overview/Summary
  if (/overview|summary|executive|introduction|background|abstract/i.test(combined)) {
    return 'overview';
  }

  // Technical details
  if (
    /technical|detail|analysis|execution|lateral|discovery|persistence|defense evasion|command|reconnaissance|initial access|privilege escalation|credential access|exfiltration/i.test(
      combined
    )
  ) {
    return 'technical_details';
  }

  // Indicators of Compromise
  if (
    /indicator|ioc|compromise|observable|artifact|hash|ip address|domain|file hash|c2|command.and.control|command and control|network indicator/i.test(
      combined
    )
  ) {
    return 'iocs';
  }

  // TTPs
  if (
    /ttp|technique|tactic|procedure|mitre|att&ck|attack|behavior|kill chain|attack pattern/i.test(
      combined
    )
  ) {
    return 'ttps';
  }

  // Recommendations
  if (
    /recommend|mitigation|remediation|detection|response|prevention|action|countermeasure|best practice/i.test(
      combined
    )
  ) {
    return 'recommendations';
  }

  return 'other';
}
