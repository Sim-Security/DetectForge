/**
 * Core threat intelligence report types.
 * These represent the normalized internal format that all parsers produce.
 */

export interface ThreatReport {
  id: string;
  title: string;
  source: string;
  date: string;
  rawText: string;
  sections: ReportSection[];
  metadata: ReportMetadata;
  inputFormat: InputFormat;
}

export interface ReportSection {
  heading: string;
  content: string;
  type: SectionType;
}

export type SectionType =
  | 'overview'
  | 'technical_details'
  | 'iocs'
  | 'ttps'
  | 'recommendations'
  | 'other';

export interface ReportMetadata {
  threatActor?: string;
  campaign?: string;
  targetSectors?: string[];
  targetRegions?: string[];
  malwareFamilies?: string[];
  cveIds?: string[];
  reportUrl?: string;
}

export type InputFormat =
  | 'pdf'
  | 'html'
  | 'markdown'
  | 'plaintext'
  | 'stix'
  | 'json';
