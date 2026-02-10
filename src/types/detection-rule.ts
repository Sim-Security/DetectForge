/**
 * Detection rule types for all three output formats:
 * Sigma (SIEM), YARA (file), Suricata (network).
 */

// --- Sigma Types ---

export interface SigmaRule {
  id: string;
  title: string;
  status: SigmaStatus;
  description: string;
  references: string[];
  author: string;
  date: string;
  modified: string;
  tags: string[];
  logsource: SigmaLogsource;
  detection: SigmaDetection;
  falsepositives: string[];
  level: SigmaLevel;
  fields?: string[];
  raw: string; // The full YAML string
}

export type SigmaStatus = 'experimental' | 'test' | 'stable' | 'deprecated' | 'unsupported';
export type SigmaLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export interface SigmaLogsource {
  category?: string;
  product?: string;
  service?: string;
}

export interface SigmaDetection {
  [key: string]: unknown;
  condition: string;
}

// --- YARA Types ---

export interface YaraRule {
  name: string;
  tags: string[];
  meta: YaraMeta;
  strings: YaraString[];
  condition: string;
  raw: string; // The full YARA rule text
}

export interface YaraMeta {
  description: string;
  author: string;
  date: string;
  reference: string;
  mitre_attack: string;
  hash?: string;
  [key: string]: string | number | boolean | undefined;
}

export interface YaraString {
  identifier: string;
  value: string;
  type: 'text' | 'hex' | 'regex';
  modifiers: string[];
}

// --- Suricata Types ---

export interface SuricataRule {
  action: SuricataAction;
  protocol: string;
  sourceIp: string;
  sourcePort: string;
  direction: '->' | '<>';
  destIp: string;
  destPort: string;
  options: SuricataOption[];
  sid: number;
  rev: number;
  raw: string; // The full Suricata rule text
}

export type SuricataAction = 'alert' | 'pass' | 'drop' | 'reject' | 'rejectsrc' | 'rejectdst' | 'rejectboth';

export interface SuricataOption {
  keyword: string;
  value?: string;
}

// --- Common Types ---

export type RuleFormat = 'sigma' | 'yara' | 'suricata';

export interface GeneratedRule {
  format: RuleFormat;
  sigma?: SigmaRule;
  yara?: YaraRule;
  suricata?: SuricataRule;
  sourceReportId: string;
  sourceTtp?: string;
  attackTechniqueId?: string;
  attackTactic?: string;
  confidence: 'high' | 'medium' | 'low';
  documentation?: RuleDocumentation;
  validation: ValidationResult;
}

export interface RuleDocumentation {
  whatItDetects: string;
  howItWorks: string;
  attackMapping: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    platform: string;
  };
  falsePositives: FalsePositiveScenario[];
  coverageGaps: string[];
  recommendedLogSources: string[];
  tuningRecommendations: string[];
}

export interface FalsePositiveScenario {
  scenario: string;
  likelihood: 'high' | 'medium' | 'low';
  tuningAdvice: string;
}

export interface ValidationResult {
  valid: boolean;
  syntaxValid: boolean;
  schemaValid: boolean;
  errors: string[];
  warnings: string[];
}
