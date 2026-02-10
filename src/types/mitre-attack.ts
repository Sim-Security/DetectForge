/**
 * MITRE ATT&CK types for technique/tactic representation.
 */

export interface AttackTechnique {
  id: string;                    // e.g., "T1059.001"
  name: string;                  // e.g., "PowerShell"
  description: string;
  tactics: string[];             // e.g., ["execution"]
  platforms: string[];           // e.g., ["Windows"]
  dataSources: string[];         // e.g., ["Process: Process Creation"]
  detectionGuidance: string;
  isSubtechnique: boolean;
  parentId?: string;             // e.g., "T1059" for T1059.001
  url: string;                   // ATT&CK URL
  stixId: string;                // STIX object ID
}

export interface AttackTactic {
  id: string;                    // e.g., "TA0002"
  name: string;                  // e.g., "Execution"
  shortName: string;             // e.g., "execution"
  description: string;
  techniques: string[];          // List of technique IDs
}

export interface AttackGroup {
  id: string;                    // e.g., "G0016"
  name: string;                  // e.g., "APT29"
  aliases: string[];
  description: string;
  techniques: string[];
  software: string[];
}

export interface AttackDataSource {
  id: string;
  name: string;
  description: string;
  components: string[];
  techniques: string[];          // Techniques detectable via this source
}

export interface AttackMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  confidence: 'high' | 'medium' | 'low';
  reasoning: string;
  detectionType: RuleFormatType[];
}

type RuleFormatType = 'sigma' | 'yara' | 'suricata';

// Coverage analysis types

export interface CoverageReport {
  totalTechniques: number;
  coveredTechniques: number;
  coveragePercentage: number;
  byTactic: TacticCoverage[];
  gaps: string[];                // Technique IDs without rules
  navigatorLayerJson: object;    // ATT&CK Navigator layer
}

export interface TacticCoverage {
  tactic: string;
  totalTechniques: number;
  coveredTechniques: number;
  coveragePercentage: number;
}
