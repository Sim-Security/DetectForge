/**
 * Types for IOC and TTP extraction results.
 */

export interface ExtractionResult {
  reportId: string;
  iocs: ExtractedIOC[];
  ttps: ExtractedTTP[];
  attackMappings: AttackMappingResult[];
  metadata: ExtractionMetadata;
}

// --- IOC Types ---

export interface ExtractedIOC {
  value: string;
  type: IOCType;
  context: string;               // Surrounding text from report
  confidence: 'high' | 'medium' | 'low';
  defanged: boolean;
  originalValue: string;         // Original as found in report
  relationships: IOCRelationship[];
}

export type IOCType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'email'
  | 'filepath_windows'
  | 'filepath_linux'
  | 'registry_key'
  | 'cve'
  | 'attack_technique';

export interface IOCRelationship {
  relatedIOC: string;
  relationship: string;          // e.g., "hosted on", "downloaded from", "resolved to"
}

// --- TTP Types ---

export interface ExtractedTTP {
  description: string;
  tools: string[];               // e.g., ["Mimikatz", "PsExec"]
  targetPlatforms: string[];
  artifacts: TTTArtifact[];
  detectionOpportunities: string[];
  confidence: 'high' | 'medium' | 'low';
}

export interface TTTArtifact {
  type: 'file' | 'registry' | 'event_log' | 'network' | 'process' | 'other';
  description: string;
  value?: string;                // Specific value if known
}

// --- ATT&CK Mapping Result ---

export interface AttackMappingResult {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  confidence: 'high' | 'medium' | 'low';
  reasoning: string;
  sourceTtp: ExtractedTTP;
  suggestedRuleFormats: ('sigma' | 'yara' | 'suricata')[];
  validated: boolean;            // Cross-referenced against ATT&CK data
}

// --- Metadata ---

export interface ExtractionMetadata {
  processingTimeMs: number;
  aiTokensUsed: number;
  aiCostUsd: number;
  iocExtractionMethod: 'regex' | 'ai' | 'hybrid';
  ttpExtractionMethod: 'ai';
  attackMappingMethod: 'ai_with_validation';
}
