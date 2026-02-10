/**
 * Sysmon event ID mappings (1-29) for Sigma rule generation.
 *
 * Sysmon (System Monitor) is a Windows system service that logs detailed
 * system activity to the Windows event log.  These mappings are essential
 * for generating Sigma rules that target Sysmon telemetry.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SysmonEventMapping {
  eventId: number;
  name: string;
  description: string;
  sigmaCategory: string;
  fields: string[];
}

// ---------------------------------------------------------------------------
// Event Mappings
// ---------------------------------------------------------------------------

const sysmonEventMappings: ReadonlyMap<number, SysmonEventMapping> = new Map([
  [
    1,
    {
      eventId: 1,
      name: 'ProcessCreate',
      description: 'Process creation',
      sigmaCategory: 'process_creation',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'FileVersion',
        'Description',
        'Product',
        'Company',
        'OriginalFileName',
        'CommandLine',
        'CurrentDirectory',
        'User',
        'LogonGuid',
        'LogonId',
        'TerminalSessionId',
        'IntegrityLevel',
        'Hashes',
        'ParentProcessGuid',
        'ParentProcessId',
        'ParentImage',
        'ParentCommandLine',
        'ParentUser',
      ],
    },
  ],
  [
    2,
    {
      eventId: 2,
      name: 'FileCreateTime',
      description: 'A process changed a file creation time',
      sigmaCategory: 'file_change',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'TargetFilename',
        'CreationUtcTime',
        'PreviousCreationUtcTime',
        'User',
      ],
    },
  ],
  [
    3,
    {
      eventId: 3,
      name: 'NetworkConnect',
      description: 'Network connection detected',
      sigmaCategory: 'network_connection',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'User',
        'Protocol',
        'Initiated',
        'SourceIsIpv6',
        'SourceIp',
        'SourceHostname',
        'SourcePort',
        'SourcePortName',
        'DestinationIsIpv6',
        'DestinationIp',
        'DestinationHostname',
        'DestinationPort',
        'DestinationPortName',
      ],
    },
  ],
  [
    4,
    {
      eventId: 4,
      name: 'SysmonServiceStateChanged',
      description: 'Sysmon service state changed',
      sigmaCategory: 'sysmon_status',
      fields: [
        'UtcTime',
        'State',
        'Version',
        'SchemaVersion',
      ],
    },
  ],
  [
    5,
    {
      eventId: 5,
      name: 'ProcessTerminate',
      description: 'Process terminated',
      sigmaCategory: 'process_termination',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'User',
      ],
    },
  ],
  [
    6,
    {
      eventId: 6,
      name: 'DriverLoad',
      description: 'Driver loaded',
      sigmaCategory: 'driver_load',
      fields: [
        'UtcTime',
        'ImageLoaded',
        'Hashes',
        'Signed',
        'Signature',
        'SignatureStatus',
      ],
    },
  ],
  [
    7,
    {
      eventId: 7,
      name: 'ImageLoad',
      description: 'Image loaded',
      sigmaCategory: 'image_load',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'ImageLoaded',
        'FileVersion',
        'Description',
        'Product',
        'Company',
        'OriginalFileName',
        'Hashes',
        'Signed',
        'Signature',
        'SignatureStatus',
        'User',
      ],
    },
  ],
  [
    8,
    {
      eventId: 8,
      name: 'CreateRemoteThread',
      description: 'CreateRemoteThread detected',
      sigmaCategory: 'create_remote_thread',
      fields: [
        'UtcTime',
        'SourceProcessGuid',
        'SourceProcessId',
        'SourceImage',
        'TargetProcessGuid',
        'TargetProcessId',
        'TargetImage',
        'NewThreadId',
        'StartAddress',
        'StartModule',
        'StartFunction',
        'SourceUser',
        'TargetUser',
      ],
    },
  ],
  [
    9,
    {
      eventId: 9,
      name: 'RawAccessRead',
      description: 'Raw access read detected',
      sigmaCategory: 'raw_access_thread',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'Device',
        'User',
      ],
    },
  ],
  [
    10,
    {
      eventId: 10,
      name: 'ProcessAccess',
      description: 'Process accessed',
      sigmaCategory: 'process_access',
      fields: [
        'UtcTime',
        'SourceProcessGUID',
        'SourceProcessId',
        'SourceThreadId',
        'SourceImage',
        'TargetProcessGUID',
        'TargetProcessId',
        'TargetImage',
        'GrantedAccess',
        'CallTrace',
        'SourceUser',
        'TargetUser',
      ],
    },
  ],
  [
    11,
    {
      eventId: 11,
      name: 'FileCreate',
      description: 'File created',
      sigmaCategory: 'file_event',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'TargetFilename',
        'CreationUtcTime',
        'User',
      ],
    },
  ],
  [
    12,
    {
      eventId: 12,
      name: 'RegistryAddDelete',
      description: 'Registry object added or deleted',
      sigmaCategory: 'registry_add',
      fields: [
        'EventType',
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'TargetObject',
        'User',
      ],
    },
  ],
  [
    13,
    {
      eventId: 13,
      name: 'RegistryValueSet',
      description: 'Registry value set',
      sigmaCategory: 'registry_set',
      fields: [
        'EventType',
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'TargetObject',
        'Details',
        'User',
      ],
    },
  ],
  [
    14,
    {
      eventId: 14,
      name: 'RegistryRename',
      description: 'Registry object renamed',
      sigmaCategory: 'registry_rename',
      fields: [
        'EventType',
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'TargetObject',
        'NewName',
        'User',
      ],
    },
  ],
  [
    15,
    {
      eventId: 15,
      name: 'FileCreateStreamHash',
      description: 'File stream created (alternate data streams)',
      sigmaCategory: 'file_event',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'TargetFilename',
        'CreationUtcTime',
        'Hash',
        'Contents',
        'User',
      ],
    },
  ],
  [
    16,
    {
      eventId: 16,
      name: 'SysmonConfigStateChanged',
      description: 'Sysmon config state changed',
      sigmaCategory: 'sysmon_status',
      fields: [
        'UtcTime',
        'Configuration',
        'ConfigurationFileHash',
      ],
    },
  ],
  [
    17,
    {
      eventId: 17,
      name: 'PipeCreated',
      description: 'Named pipe created',
      sigmaCategory: 'pipe_created',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'PipeName',
        'Image',
        'User',
      ],
    },
  ],
  [
    18,
    {
      eventId: 18,
      name: 'PipeConnected',
      description: 'Named pipe connected',
      sigmaCategory: 'pipe_connected',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'PipeName',
        'Image',
        'User',
      ],
    },
  ],
  [
    19,
    {
      eventId: 19,
      name: 'WmiEventFilter',
      description: 'WMI event filter activity detected',
      sigmaCategory: 'wmi_event',
      fields: [
        'EventType',
        'UtcTime',
        'Operation',
        'User',
        'EventNamespace',
        'Name',
        'Query',
      ],
    },
  ],
  [
    20,
    {
      eventId: 20,
      name: 'WmiEventConsumer',
      description: 'WMI event consumer activity detected',
      sigmaCategory: 'wmi_event',
      fields: [
        'EventType',
        'UtcTime',
        'Operation',
        'User',
        'Name',
        'Type',
        'Destination',
      ],
    },
  ],
  [
    21,
    {
      eventId: 21,
      name: 'WmiEventConsumerToFilter',
      description: 'WMI event consumer to filter activity detected',
      sigmaCategory: 'wmi_event',
      fields: [
        'EventType',
        'UtcTime',
        'Operation',
        'User',
        'Consumer',
        'Filter',
      ],
    },
  ],
  [
    22,
    {
      eventId: 22,
      name: 'DnsQuery',
      description: 'DNS query',
      sigmaCategory: 'dns_query',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'QueryName',
        'QueryStatus',
        'QueryResults',
        'Image',
        'User',
      ],
    },
  ],
  [
    23,
    {
      eventId: 23,
      name: 'FileDelete',
      description: 'File delete archived',
      sigmaCategory: 'file_delete',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'User',
        'Image',
        'TargetFilename',
        'Hashes',
        'IsExecutable',
        'Archived',
      ],
    },
  ],
  [
    24,
    {
      eventId: 24,
      name: 'ClipboardChange',
      description: 'New content in the clipboard',
      sigmaCategory: 'clipboard_change',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'Session',
        'ClientInfo',
        'Hashes',
        'Archived',
        'User',
      ],
    },
  ],
  [
    25,
    {
      eventId: 25,
      name: 'ProcessTampering',
      description: 'Process image change',
      sigmaCategory: 'process_tampering',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'Image',
        'Type',
        'User',
      ],
    },
  ],
  [
    26,
    {
      eventId: 26,
      name: 'FileDeleteDetected',
      description: 'File delete logged',
      sigmaCategory: 'file_delete',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'User',
        'Image',
        'TargetFilename',
        'Hashes',
        'IsExecutable',
      ],
    },
  ],
  [
    27,
    {
      eventId: 27,
      name: 'FileBlockExecutable',
      description: 'File block executable',
      sigmaCategory: 'file_block_executable',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'User',
        'Image',
        'TargetFilename',
        'Hashes',
      ],
    },
  ],
  [
    28,
    {
      eventId: 28,
      name: 'FileBlockShredding',
      description: 'File block shredding',
      sigmaCategory: 'file_block_shredding',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'User',
        'Image',
        'TargetFilename',
        'Hashes',
      ],
    },
  ],
  [
    29,
    {
      eventId: 29,
      name: 'FileExecutableDetected',
      description: 'File executable detected',
      sigmaCategory: 'file_executable_detected',
      fields: [
        'UtcTime',
        'ProcessGuid',
        'ProcessId',
        'User',
        'Image',
        'TargetFilename',
        'Hashes',
      ],
    },
  ],
]);

// ---------------------------------------------------------------------------
// Category index  (sigma category -> event ID)
// Some categories map to multiple event IDs (e.g. file_delete -> 23, 26)
// We return the primary / most-used mapping.
// ---------------------------------------------------------------------------

const categoryToEventId: ReadonlyMap<string, number> = new Map([
  ['process_creation', 1],
  ['file_change', 2],
  ['network_connection', 3],
  ['sysmon_status', 4],
  ['process_termination', 5],
  ['driver_load', 6],
  ['image_load', 7],
  ['create_remote_thread', 8],
  ['raw_access_thread', 9],
  ['process_access', 10],
  ['file_event', 11],
  ['registry_add', 12],
  ['registry_delete', 12],
  ['registry_set', 13],
  ['registry_rename', 14],
  ['pipe_created', 17],
  ['pipe_connected', 18],
  ['wmi_event', 19],
  ['dns_query', 22],
  ['file_delete', 23],
  ['clipboard_change', 24],
  ['process_tampering', 25],
  ['file_block_executable', 27],
  ['file_block_shredding', 28],
  ['file_executable_detected', 29],
]);

// ---------------------------------------------------------------------------
// Lookup Functions
// ---------------------------------------------------------------------------

/**
 * Retrieve the full mapping for a given Sysmon event ID (1-29).
 */
export function getSysmonEventMapping(
  eventId: number,
): SysmonEventMapping | undefined {
  return sysmonEventMappings.get(eventId);
}

/**
 * Find a Sysmon event mapping by its Sigma category name.
 * Returns the primary mapping when multiple event IDs share a category.
 */
export function getSysmonEventByCategory(
  sigmaCategory: string,
): SysmonEventMapping | undefined {
  const eventId = categoryToEventId.get(sigmaCategory);
  if (eventId === undefined) return undefined;
  return sysmonEventMappings.get(eventId);
}

/**
 * Return the list of Sysmon-specific fields for a given event ID.
 * Returns an empty array when the event ID is unknown.
 */
export function getSysmonFields(eventId: number): string[] {
  const mapping = sysmonEventMappings.get(eventId);
  return mapping ? mapping.fields : [];
}

/**
 * Return all distinct Sigma category names covered by the Sysmon mappings.
 */
export function getAllSigmaCategories(): string[] {
  const categories = new Set<string>();
  for (const mapping of sysmonEventMappings.values()) {
    categories.add(mapping.sigmaCategory);
  }
  return [...categories];
}

/**
 * Return all registered Sysmon event mappings (1-29).
 */
export function getAllSysmonEventMappings(): SysmonEventMapping[] {
  return [...sysmonEventMappings.values()];
}
