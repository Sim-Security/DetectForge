/**
 * DetectForge Ingestion Pipeline
 *
 * Parsers and normalizers for threat intelligence reports.
 */

export { parsePdf } from './parsers/pdf.js';
export { parseHtml } from './parsers/html.js';
export { parseMarkdown } from './parsers/markdown.js';
export { parsePlaintext } from './parsers/plaintext.js';

export {
  normalizeReport,
  detectFormat,
  classifySection,
  type NormalizeOptions,
} from './normalizer.js';

export type {
  ThreatReport,
  ReportSection,
  ReportMetadata,
  SectionType,
  InputFormat,
} from '../types/threat-report.js';
