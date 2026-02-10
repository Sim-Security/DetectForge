/**
 * Sigma rule templates organized by logsource category.
 *
 * Each template provides the logsource block, available detection fields,
 * common false positive patterns, and a skeleton detection block for its
 * category.  The {@link getSuggestedCategory} function maps ATT&CK
 * tactics/techniques to the most appropriate logsource categories so the
 * generator can pick the right template automatically.
 */

import type { ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Template Interface
// ---------------------------------------------------------------------------

/**
 * A pre-built Sigma rule template for a specific logsource category.
 */
export interface SigmaTemplate {
  /** Short identifier for this template (e.g. "process_creation"). */
  category: string;
  /** Sigma logsource block fields. */
  logsource: { product: string; category?: string; service?: string };
  /** Fields the analyst can reference in detection conditions. */
  availableFields: string[];
  /** Frequently encountered false-positive scenarios. */
  commonFalsePositives: string[];
  /** Skeleton detection block showing typical selection + condition. */
  exampleDetection: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Template Definitions
// ---------------------------------------------------------------------------

const templates: ReadonlyMap<string, SigmaTemplate> = new Map([
  [
    'process_creation',
    {
      category: 'process_creation',
      logsource: { product: 'windows', category: 'process_creation' },
      availableFields: [
        'Image',
        'OriginalFileName',
        'CommandLine',
        'ParentImage',
        'ParentCommandLine',
        'User',
        'IntegrityLevel',
        'Hashes',
        'CurrentDirectory',
        'Product',
        'Company',
        'Description',
      ],
      commonFalsePositives: [
        'Legitimate administrative scripts',
        'Software installers and updaters',
        'System management tools (SCCM, Intune)',
        'Developer toolchains',
      ],
      exampleDetection: {
        selection: {
          Image: ['*\\suspicious.exe'],
          CommandLine: ['*-encodedcommand*'],
        },
        condition: 'selection',
      },
    },
  ],
  [
    'image_load',
    {
      category: 'image_load',
      logsource: { product: 'windows', category: 'image_load' },
      availableFields: [
        'Image',
        'ImageLoaded',
        'OriginalFileName',
        'Hashes',
        'Signed',
        'Signature',
        'SignatureStatus',
        'Product',
        'Company',
        'Description',
        'User',
      ],
      commonFalsePositives: [
        'Legitimate DLL loading by trusted applications',
        'Software updates loading new library versions',
        'Third-party security tools',
      ],
      exampleDetection: {
        selection: {
          ImageLoaded: ['*\\malicious.dll'],
        },
        filter_legitimate: {
          Signed: [true],
          SignatureStatus: ['Valid'],
        },
        condition: 'selection and not filter_legitimate',
      },
    },
  ],
  [
    'file_event',
    {
      category: 'file_event',
      logsource: { product: 'windows', category: 'file_event' },
      availableFields: [
        'Image',
        'TargetFilename',
        'CreationUtcTime',
        'User',
      ],
      commonFalsePositives: [
        'Software installations creating expected files',
        'Temporary files from browsers and office applications',
        'Log rotation and backup utilities',
      ],
      exampleDetection: {
        selection: {
          TargetFilename: ['C:\\Users\\*\\AppData\\Local\\Temp\\*.exe'],
        },
        condition: 'selection',
      },
    },
  ],
  [
    'registry_event',
    {
      category: 'registry_event',
      logsource: { product: 'windows', category: 'registry_set' },
      availableFields: [
        'EventType',
        'Image',
        'TargetObject',
        'Details',
        'User',
      ],
      commonFalsePositives: [
        'Software installers modifying Run keys',
        'Group Policy updates',
        'Windows Update modifying system registry keys',
        'Legitimate application configuration changes',
      ],
      exampleDetection: {
        selection: {
          TargetObject: [
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
          ],
        },
        condition: 'selection',
      },
    },
  ],
  [
    'network_connection',
    {
      category: 'network_connection',
      logsource: { product: 'windows', category: 'network_connection' },
      availableFields: [
        'Image',
        'User',
        'Protocol',
        'Initiated',
        'SourceIp',
        'SourcePort',
        'DestinationIp',
        'DestinationHostname',
        'DestinationPort',
        'DestinationPortName',
      ],
      commonFalsePositives: [
        'Legitimate software update connections',
        'Cloud service communications (Azure, AWS, GCP)',
        'Browser network activity',
        'VPN and remote management tools',
      ],
      exampleDetection: {
        selection: {
          Initiated: [true],
          DestinationPort: [4444, 5555, 8888],
        },
        filter_browsers: {
          Image: ['*\\chrome.exe', '*\\firefox.exe', '*\\msedge.exe'],
        },
        condition: 'selection and not filter_browsers',
      },
    },
  ],
  [
    'dns_query',
    {
      category: 'dns_query',
      logsource: { product: 'windows', category: 'dns_query' },
      availableFields: [
        'Image',
        'QueryName',
        'QueryStatus',
        'QueryResults',
        'User',
      ],
      commonFalsePositives: [
        'Legitimate DNS queries to CDN providers',
        'Cloud service DNS resolution',
        'Internal DNS infrastructure queries',
        'Browser prefetch DNS lookups',
      ],
      exampleDetection: {
        selection: {
          QueryName: ['*.evil.com', '*.malware.net'],
        },
        condition: 'selection',
      },
    },
  ],
  [
    'pipe_created',
    {
      category: 'pipe_created',
      logsource: { product: 'windows', category: 'pipe_created' },
      availableFields: [
        'PipeName',
        'Image',
        'User',
      ],
      commonFalsePositives: [
        'Named pipes used by legitimate IPC mechanisms',
        'Database and messaging middleware pipes',
        'Antivirus and EDR tool communication',
      ],
      exampleDetection: {
        selection: {
          PipeName: ['\\MSSE-*', '\\isapi_http', '\\postex_*'],
        },
        condition: 'selection',
      },
    },
  ],
  [
    'wmi_event',
    {
      category: 'wmi_event',
      logsource: { product: 'windows', category: 'wmi_event' },
      availableFields: [
        'EventType',
        'Operation',
        'User',
        'EventNamespace',
        'Name',
        'Query',
        'Type',
        'Destination',
        'Consumer',
        'Filter',
      ],
      commonFalsePositives: [
        'SCCM/ConfigMgr WMI operations',
        'Dell/HP/Lenovo hardware management agents',
        'Monitoring and inventory tools',
      ],
      exampleDetection: {
        selection: {
          EventType: ['WmiConsumerEvent'],
          Destination: ['*powershell*', '*cmd*', '*script*'],
        },
        condition: 'selection',
      },
    },
  ],
  [
    'ps_script',
    {
      category: 'ps_script',
      logsource: { product: 'windows', category: 'ps_script', service: 'powershell' },
      availableFields: [
        'ScriptBlockText',
        'ScriptBlockId',
        'Path',
        'MessageNumber',
        'MessageTotal',
      ],
      commonFalsePositives: [
        'Administrative PowerShell scripts',
        'IT automation and configuration management',
        'Azure/O365 management modules',
        'Software deployment scripts',
      ],
      exampleDetection: {
        selection: {
          ScriptBlockText: [
            '*Invoke-Mimikatz*',
            '*Invoke-Expression*',
            '*Net.WebClient*',
          ],
        },
        condition: 'selection',
      },
    },
  ],
  [
    'security',
    {
      category: 'security',
      logsource: { product: 'windows', service: 'security' },
      availableFields: [
        'EventID',
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'TargetUserSid',
        'TargetUserName',
        'TargetDomainName',
        'LogonType',
        'IpAddress',
        'IpPort',
        'ProcessName',
        'ProcessId',
        'ServiceName',
        'Status',
        'TicketOptions',
        'TicketEncryptionType',
      ],
      commonFalsePositives: [
        'Legitimate logon events from administrators',
        'Service account activity',
        'Scheduled task executions',
        'Automated monitoring systems',
      ],
      exampleDetection: {
        selection: {
          EventID: [4625],
          LogonType: [10],
        },
        filter_known: {
          IpAddress: ['10.0.0.*'],
        },
        condition: 'selection and not filter_known',
      },
    },
  ],
]);

// ---------------------------------------------------------------------------
// Technique-to-Category Mapping
// ---------------------------------------------------------------------------

/**
 * Maps ATT&CK technique IDs (and sub-technique IDs) to the logsource
 * categories most likely to provide detection telemetry.
 *
 * Sub-technique IDs are checked first, then the parent technique ID, and
 * finally the tactic name is used as a fallback heuristic.
 */
const TECHNIQUE_TO_CATEGORIES: ReadonlyMap<string, string[]> = new Map([
  // Execution
  ['T1059', ['ps_script', 'process_creation']],
  ['T1059.001', ['ps_script', 'process_creation']],
  ['T1059.003', ['process_creation']],
  ['T1059.005', ['process_creation']],
  ['T1059.006', ['process_creation']],
  ['T1059.007', ['process_creation']],
  ['T1047', ['wmi_event', 'process_creation']],
  ['T1053', ['security', 'process_creation']],
  ['T1053.005', ['security', 'process_creation']],
  ['T1106', ['process_creation']],
  ['T1129', ['image_load']],
  ['T1204', ['process_creation', 'file_event']],
  ['T1204.002', ['process_creation', 'file_event']],

  // Persistence
  ['T1547', ['registry_event', 'process_creation']],
  ['T1547.001', ['registry_event']],
  ['T1547.004', ['registry_event']],
  ['T1547.009', ['registry_event']],
  ['T1547.010', ['registry_event']],
  ['T1543', ['security', 'process_creation']],
  ['T1543.003', ['security', 'process_creation']],
  ['T1546', ['registry_event', 'wmi_event']],
  ['T1546.003', ['wmi_event']],
  ['T1546.015', ['registry_event']],
  ['T1574', ['image_load', 'file_event', 'process_creation']],
  ['T1574.001', ['image_load']],
  ['T1574.002', ['image_load']],
  ['T1136', ['security']],
  ['T1136.001', ['security']],
  ['T1098', ['security']],
  ['T1053.005', ['security']],

  // Privilege Escalation
  ['T1055', ['process_creation', 'image_load']],
  ['T1055.001', ['process_creation']],
  ['T1055.012', ['process_creation']],
  ['T1134', ['security', 'process_creation']],

  // Defense Evasion
  ['T1070', ['security', 'file_event']],
  ['T1070.001', ['security']],
  ['T1070.004', ['file_event']],
  ['T1036', ['process_creation', 'file_event']],
  ['T1036.003', ['process_creation']],
  ['T1036.005', ['process_creation']],
  ['T1027', ['ps_script', 'process_creation']],
  ['T1027.010', ['ps_script', 'process_creation']],
  ['T1218', ['process_creation', 'image_load']],
  ['T1218.001', ['process_creation']],
  ['T1218.003', ['process_creation']],
  ['T1218.005', ['process_creation']],
  ['T1218.010', ['process_creation']],
  ['T1218.011', ['process_creation']],
  ['T1562', ['security', 'registry_event']],
  ['T1562.001', ['security', 'registry_event', 'process_creation']],
  ['T1112', ['registry_event']],
  ['T1140', ['process_creation', 'ps_script']],

  // Credential Access
  ['T1003', ['process_creation', 'security']],
  ['T1003.001', ['process_creation', 'security']],
  ['T1003.006', ['security']],
  ['T1110', ['security']],
  ['T1558', ['security']],
  ['T1558.003', ['security']],
  ['T1552', ['file_event', 'ps_script']],
  ['T1552.001', ['file_event']],

  // Discovery
  ['T1087', ['process_creation', 'security']],
  ['T1082', ['process_creation']],
  ['T1083', ['process_creation']],
  ['T1057', ['process_creation']],
  ['T1018', ['process_creation', 'dns_query']],
  ['T1046', ['network_connection', 'process_creation']],
  ['T1016', ['process_creation']],
  ['T1049', ['process_creation']],
  ['T1069', ['process_creation', 'security']],
  ['T1135', ['process_creation']],
  ['T1482', ['process_creation']],

  // Lateral Movement
  ['T1021', ['security', 'network_connection']],
  ['T1021.001', ['security', 'network_connection']],
  ['T1021.002', ['security', 'network_connection']],
  ['T1021.003', ['security']],
  ['T1021.006', ['network_connection', 'process_creation']],
  ['T1570', ['network_connection', 'file_event']],

  // Collection
  ['T1560', ['process_creation', 'file_event']],

  // Command and Control
  ['T1071', ['network_connection', 'dns_query']],
  ['T1071.001', ['network_connection']],
  ['T1071.004', ['dns_query']],
  ['T1105', ['network_connection', 'file_event']],
  ['T1572', ['network_connection']],
  ['T1573', ['network_connection']],
  ['T1095', ['network_connection']],
  ['T1568', ['dns_query']],
  ['T1568.002', ['dns_query']],
  ['T1571', ['network_connection']],
  ['T1102', ['network_connection', 'dns_query']],
  ['T1090', ['network_connection']],
  ['T1219', ['network_connection', 'process_creation']],

  // Exfiltration
  ['T1041', ['network_connection']],
  ['T1048', ['network_connection']],

  // Impact
  ['T1486', ['file_event', 'process_creation']],
  ['T1490', ['process_creation']],
  ['T1489', ['process_creation', 'security']],
]);

/**
 * Fallback mapping from ATT&CK tactic names to logsource categories.
 */
const TACTIC_TO_CATEGORIES: ReadonlyMap<string, string[]> = new Map([
  ['initial-access', ['network_connection', 'file_event']],
  ['execution', ['process_creation', 'ps_script']],
  ['persistence', ['registry_event', 'file_event', 'security']],
  ['privilege-escalation', ['process_creation', 'security']],
  ['defense-evasion', ['process_creation', 'ps_script', 'registry_event']],
  ['credential-access', ['security', 'process_creation']],
  ['discovery', ['process_creation']],
  ['lateral-movement', ['security', 'network_connection']],
  ['collection', ['process_creation', 'file_event']],
  ['command-and-control', ['network_connection', 'dns_query']],
  ['exfiltration', ['network_connection']],
  ['impact', ['process_creation', 'file_event']],
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Retrieve a Sigma template by its category identifier.
 *
 * @param category - The logsource category (e.g. "process_creation").
 * @returns The matching template, or `undefined` when no template exists.
 */
export function getTemplate(category: string): SigmaTemplate | undefined {
  return templates.get(category);
}

/**
 * Return every registered Sigma template.
 */
export function getAllTemplates(): SigmaTemplate[] {
  return [...templates.values()];
}

/**
 * Suggest which Sigma logsource categories are best suited for detecting
 * a given TTP based on its ATT&CK mapping.
 *
 * The function checks (in order):
 * 1. The specific sub-technique ID (e.g. T1547.001)
 * 2. The parent technique ID (e.g. T1547)
 * 3. The ATT&CK tactic (e.g. "persistence")
 * 4. Heuristics from artifact types in the TTP
 *
 * @param ttp     - The extracted TTP from a threat report.
 * @param mapping - The ATT&CK technique mapping for this TTP.
 * @returns An array of category strings, ordered by relevance.
 */
export function getSuggestedCategory(
  ttp: ExtractedTTP,
  mapping: AttackMappingResult,
): string[] {
  const categories = new Set<string>();

  // 1. Check full technique ID (may include sub-technique)
  const techniqueId = mapping.techniqueId;
  const directMatch = TECHNIQUE_TO_CATEGORIES.get(techniqueId);
  if (directMatch) {
    for (const cat of directMatch) {
      categories.add(cat);
    }
  }

  // 2. Check parent technique if we have a sub-technique
  if (techniqueId.includes('.')) {
    const parentId = techniqueId.split('.')[0];
    const parentMatch = TECHNIQUE_TO_CATEGORIES.get(parentId);
    if (parentMatch) {
      for (const cat of parentMatch) {
        categories.add(cat);
      }
    }
  }

  // 3. Tactic-based fallback
  const normalizedTactic = mapping.tactic
    .toLowerCase()
    .replace(/\s+/g, '-');
  const tacticMatch = TACTIC_TO_CATEGORIES.get(normalizedTactic);
  if (tacticMatch) {
    for (const cat of tacticMatch) {
      categories.add(cat);
    }
  }

  // 4. Artifact heuristic — if no techniques matched, derive from artifacts
  if (categories.size === 0) {
    for (const artifact of ttp.artifacts) {
      switch (artifact.type) {
        case 'process':
          categories.add('process_creation');
          break;
        case 'file':
          categories.add('file_event');
          break;
        case 'registry':
          categories.add('registry_event');
          break;
        case 'network':
          categories.add('network_connection');
          break;
        case 'event_log':
          categories.add('security');
          break;
        default:
          categories.add('process_creation');
          break;
      }
    }
  }

  // If still empty, default to process_creation
  if (categories.size === 0) {
    categories.add('process_creation');
  }

  return [...categories];
}
