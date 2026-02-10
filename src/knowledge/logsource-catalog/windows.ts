/**
 * Windows Security Event Log mappings for Sigma rule generation.
 *
 * Maps Windows event IDs to their corresponding Sigma logsource fields,
 * available event fields, and descriptions.  These mappings are critical
 * for producing syntactically and semantically correct Sigma rules.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EventLogMapping {
  eventId: number;
  channel: string;
  description: string;
  category: string;
  fields: string[];
  sigmaProduct: string;
  sigmaService: string;
}

// ---------------------------------------------------------------------------
// Event Mappings
// ---------------------------------------------------------------------------

const windowsEventMappings: ReadonlyMap<number, EventLogMapping> = new Map([
  [
    4688,
    {
      eventId: 4688,
      channel: 'Security',
      description: 'A new process has been created',
      category: 'process_creation',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'NewProcessId',
        'NewProcessName',
        'TokenElevationType',
        'ProcessId',
        'CommandLine',
        'TargetUserSid',
        'TargetUserName',
        'TargetDomainName',
        'TargetLogonId',
        'ParentProcessName',
        'MandatoryLabel',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4624,
    {
      eventId: 4624,
      channel: 'Security',
      description: 'An account was successfully logged on',
      category: 'logon',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'TargetUserSid',
        'TargetUserName',
        'TargetDomainName',
        'TargetLogonId',
        'LogonType',
        'LogonProcessName',
        'AuthenticationPackageName',
        'WorkstationName',
        'LogonGuid',
        'TransmittedServices',
        'LmPackageName',
        'KeyLength',
        'ProcessId',
        'ProcessName',
        'IpAddress',
        'IpPort',
        'ImpersonationLevel',
        'ElevatedToken',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4625,
    {
      eventId: 4625,
      channel: 'Security',
      description: 'An account failed to log on',
      category: 'logon',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'TargetUserSid',
        'TargetUserName',
        'TargetDomainName',
        'Status',
        'FailureReason',
        'SubStatus',
        'LogonType',
        'LogonProcessName',
        'AuthenticationPackageName',
        'WorkstationName',
        'TransmittedServices',
        'LmPackageName',
        'KeyLength',
        'ProcessId',
        'ProcessName',
        'IpAddress',
        'IpPort',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4672,
    {
      eventId: 4672,
      channel: 'Security',
      description: 'Special privileges assigned to new logon',
      category: 'logon',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'PrivilegeList',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4720,
    {
      eventId: 4720,
      channel: 'Security',
      description: 'A user account was created',
      category: 'account_management',
      fields: [
        'TargetUserName',
        'TargetDomainName',
        'TargetSid',
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'PrivilegeList',
        'SamAccountName',
        'DisplayName',
        'UserPrincipalName',
        'HomeDirectory',
        'HomePath',
        'ScriptPath',
        'ProfilePath',
        'UserWorkstations',
        'PasswordLastSet',
        'AccountExpires',
        'PrimaryGroupId',
        'AllowedToDelegateTo',
        'OldUacValue',
        'NewUacValue',
        'UserAccountControl',
        'UserParameters',
        'SidHistory',
        'LogonHours',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4732,
    {
      eventId: 4732,
      channel: 'Security',
      description: 'A member was added to a security-enabled local group',
      category: 'account_management',
      fields: [
        'MemberName',
        'MemberSid',
        'TargetUserName',
        'TargetDomainName',
        'TargetSid',
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'PrivilegeList',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4648,
    {
      eventId: 4648,
      channel: 'Security',
      description: 'A logon was attempted using explicit credentials',
      category: 'logon',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'LogonGuid',
        'TargetUserName',
        'TargetDomainName',
        'TargetLogonGuid',
        'TargetServerName',
        'TargetInfo',
        'ProcessId',
        'ProcessName',
        'IpAddress',
        'IpPort',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4663,
    {
      eventId: 4663,
      channel: 'Security',
      description: 'An attempt was made to access an object',
      category: 'object_access',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'ObjectServer',
        'ObjectType',
        'ObjectName',
        'HandleId',
        'AccessList',
        'AccessMask',
        'ProcessId',
        'ProcessName',
        'ResourceAttributes',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4670,
    {
      eventId: 4670,
      channel: 'Security',
      description: 'Permissions on an object were changed',
      category: 'object_access',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'ObjectServer',
        'ObjectType',
        'ObjectName',
        'HandleId',
        'OldSd',
        'NewSd',
        'ProcessId',
        'ProcessName',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4697,
    {
      eventId: 4697,
      channel: 'Security',
      description: 'A service was installed in the system',
      category: 'system',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'ServiceName',
        'ServiceFileName',
        'ServiceType',
        'ServiceStartType',
        'ServiceAccount',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4698,
    {
      eventId: 4698,
      channel: 'Security',
      description: 'A scheduled task was created',
      category: 'other',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'TaskName',
        'TaskContent',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4699,
    {
      eventId: 4699,
      channel: 'Security',
      description: 'A scheduled task was deleted',
      category: 'other',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'TaskName',
        'TaskContent',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4700,
    {
      eventId: 4700,
      channel: 'Security',
      description: 'A scheduled task was enabled',
      category: 'other',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'TaskName',
        'TaskContent',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4703,
    {
      eventId: 4703,
      channel: 'Security',
      description: 'A token right was adjusted',
      category: 'other',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'TargetUserSid',
        'TargetUserName',
        'TargetDomainName',
        'TargetLogonId',
        'ProcessName',
        'ProcessId',
        'EnabledPrivilegeList',
        'DisabledPrivilegeList',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4719,
    {
      eventId: 4719,
      channel: 'Security',
      description: 'System audit policy was changed',
      category: 'policy_change',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
        'CategoryId',
        'SubcategoryId',
        'SubcategoryGuid',
        'AuditPolicyChanges',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4768,
    {
      eventId: 4768,
      channel: 'Security',
      description: 'A Kerberos authentication ticket (TGT) was requested',
      category: 'logon',
      fields: [
        'TargetUserName',
        'TargetDomainName',
        'TargetSid',
        'ServiceName',
        'ServiceSid',
        'TicketOptions',
        'Status',
        'TicketEncryptionType',
        'PreAuthType',
        'IpAddress',
        'IpPort',
        'CertIssuerName',
        'CertSerialNumber',
        'CertThumbprint',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4769,
    {
      eventId: 4769,
      channel: 'Security',
      description: 'A Kerberos service ticket was requested',
      category: 'logon',
      fields: [
        'TargetUserName',
        'TargetDomainName',
        'ServiceName',
        'ServiceSid',
        'TicketOptions',
        'TicketEncryptionType',
        'IpAddress',
        'IpPort',
        'Status',
        'LogonGuid',
        'TransmittedServices',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    4771,
    {
      eventId: 4771,
      channel: 'Security',
      description: 'Kerberos pre-authentication failed',
      category: 'logon',
      fields: [
        'TargetUserName',
        'TargetSid',
        'ServiceName',
        'TicketOptions',
        'Status',
        'PreAuthType',
        'IpAddress',
        'IpPort',
        'CertIssuerName',
        'CertSerialNumber',
        'CertThumbprint',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
  [
    7045,
    {
      eventId: 7045,
      channel: 'System',
      description: 'A new service was installed in the system',
      category: 'system',
      fields: [
        'ServiceName',
        'ImagePath',
        'ServiceType',
        'StartType',
        'AccountName',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'system',
    },
  ],
  [
    1102,
    {
      eventId: 1102,
      channel: 'Security',
      description: 'The audit log was cleared',
      category: 'audit_log_cleared',
      fields: [
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'SubjectLogonId',
      ],
      sigmaProduct: 'windows',
      sigmaService: 'security',
    },
  ],
]);

// ---------------------------------------------------------------------------
// Lookup Functions
// ---------------------------------------------------------------------------

/**
 * Retrieve the full mapping for a given Windows Event ID.
 */
export function getWindowsEventMapping(
  eventId: number,
): EventLogMapping | undefined {
  return windowsEventMappings.get(eventId);
}

/**
 * Retrieve all event mappings that belong to a given category
 * (e.g. "logon", "process_creation", "account_management").
 */
export function getWindowsEventsByCategory(
  category: string,
): EventLogMapping[] {
  const results: EventLogMapping[] = [];
  for (const mapping of windowsEventMappings.values()) {
    if (mapping.category === category) {
      results.push(mapping);
    }
  }
  return results;
}

/**
 * Return the list of available fields for a given Windows Event ID.
 * Returns an empty array when the event ID is unknown.
 */
export function getWindowsFieldsForEvent(eventId: number): string[] {
  const mapping = windowsEventMappings.get(eventId);
  return mapping ? mapping.fields : [];
}

/**
 * Derive the Sigma logsource block values for a given Windows Event ID.
 * Returns product and service (always), plus an optional category when the
 * event maps cleanly to a well-known Sigma category.
 */
export function getSigmaLogsourceForEvent(
  eventId: number,
): { product: string; service: string; category?: string } {
  const mapping = windowsEventMappings.get(eventId);
  if (!mapping) {
    return { product: 'windows', service: 'security' };
  }

  const result: { product: string; service: string; category?: string } = {
    product: mapping.sigmaProduct,
    service: mapping.sigmaService,
  };

  // Only include category for well-known Sigma categories
  const sigmaCategories = new Set([
    'process_creation',
    'logon',
    'account_management',
    'object_access',
    'policy_change',
    'audit_log_cleared',
  ]);

  if (sigmaCategories.has(mapping.category)) {
    result.category = mapping.category;
  }

  return result;
}

/**
 * Return all registered Windows event mappings.
 */
export function getAllWindowsEventMappings(): EventLogMapping[] {
  return [...windowsEventMappings.values()];
}
