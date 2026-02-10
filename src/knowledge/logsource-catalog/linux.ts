/**
 * Linux log source mappings for Sigma rule generation.
 *
 * Maps common Linux log sources (auditd, syslog, auth.log, journal) to
 * their Sigma logsource fields and available event fields.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LinuxLogMapping {
  source: string;
  description: string;
  sigmaProduct: string;
  sigmaService: string;
  sigmaCategory?: string;
  fields: string[];
}

// ---------------------------------------------------------------------------
// Log Source Mappings
// ---------------------------------------------------------------------------

const linuxLogMappings: ReadonlyMap<string, LinuxLogMapping> = new Map([
  [
    'auditd',
    {
      source: 'auditd',
      description:
        'Linux Audit daemon — records SYSCALL, EXECVE, PATH, CWD events for process execution and file access',
      sigmaProduct: 'linux',
      sigmaService: 'auditd',
      sigmaCategory: 'process_creation',
      fields: [
        'type',
        'msg',
        'arch',
        'syscall',
        'success',
        'exit',
        'a0',
        'a1',
        'a2',
        'a3',
        'items',
        'ppid',
        'pid',
        'auid',
        'uid',
        'gid',
        'euid',
        'suid',
        'fsuid',
        'egid',
        'sgid',
        'fsgid',
        'tty',
        'ses',
        'comm',
        'exe',
        'key',
        'subj',
      ],
    },
  ],
  [
    'auditd_auth',
    {
      source: 'auditd_auth',
      description:
        'Linux Audit daemon authentication events — USER_AUTH, USER_ACCT, CRED_ACQ records',
      sigmaProduct: 'linux',
      sigmaService: 'auditd',
      fields: [
        'type',
        'msg',
        'pid',
        'uid',
        'auid',
        'ses',
        'op',
        'acct',
        'hostname',
        'addr',
        'terminal',
        'res',
        'exe',
        'subj',
      ],
    },
  ],
  [
    'syslog',
    {
      source: 'syslog',
      description:
        'General system logging via rsyslog/syslog-ng — /var/log/syslog or /var/log/messages',
      sigmaProduct: 'linux',
      sigmaService: 'syslog',
      fields: [
        'timestamp',
        'hostname',
        'program',
        'pid',
        'message',
        'facility',
        'severity',
      ],
    },
  ],
  [
    'auth',
    {
      source: 'auth',
      description:
        'Authentication log — /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS)',
      sigmaProduct: 'linux',
      sigmaService: 'auth',
      fields: [
        'timestamp',
        'hostname',
        'program',
        'pid',
        'message',
        'user',
        'uid',
        'rhost',
        'tty',
      ],
    },
  ],
  [
    'journal',
    {
      source: 'journal',
      description:
        'Systemd journal — structured logging for modern Linux systems via journalctl',
      sigmaProduct: 'linux',
      sigmaService: 'journal',
      fields: [
        '__REALTIME_TIMESTAMP',
        '_HOSTNAME',
        '_COMM',
        '_PID',
        '_UID',
        '_GID',
        '_SYSTEMD_UNIT',
        '_SYSTEMD_CGROUP',
        '_TRANSPORT',
        'MESSAGE',
        'PRIORITY',
        'SYSLOG_IDENTIFIER',
        'SYSLOG_FACILITY',
        '_EXE',
        '_CMDLINE',
        '_MACHINE_ID',
        '_BOOT_ID',
      ],
    },
  ],
  [
    'cron',
    {
      source: 'cron',
      description:
        'Cron daemon log — /var/log/cron or entries in syslog from CRON',
      sigmaProduct: 'linux',
      sigmaService: 'cron',
      fields: [
        'timestamp',
        'hostname',
        'program',
        'pid',
        'user',
        'command',
        'message',
      ],
    },
  ],
  [
    'sudo',
    {
      source: 'sudo',
      description:
        'Sudo command log — privilege escalation events in auth.log or journal',
      sigmaProduct: 'linux',
      sigmaService: 'sudo',
      fields: [
        'timestamp',
        'hostname',
        'user',
        'tty',
        'pwd',
        'command',
        'runas_user',
        'message',
      ],
    },
  ],
  [
    'dpkg',
    {
      source: 'dpkg',
      description:
        'Package management log — /var/log/dpkg.log (Debian/Ubuntu)',
      sigmaProduct: 'linux',
      sigmaService: 'dpkg',
      fields: [
        'timestamp',
        'action',
        'package',
        'version',
        'status',
        'message',
      ],
    },
  ],
  [
    'apache',
    {
      source: 'apache',
      description:
        'Apache HTTP Server access and error logs',
      sigmaProduct: 'linux',
      sigmaService: 'apache',
      fields: [
        'remote_host',
        'ident',
        'authuser',
        'timestamp',
        'request',
        'method',
        'uri',
        'protocol',
        'status',
        'bytes',
        'referer',
        'user_agent',
        'message',
      ],
    },
  ],
  [
    'sshd',
    {
      source: 'sshd',
      description:
        'OpenSSH server daemon logs — authentication, session, and key exchange events',
      sigmaProduct: 'linux',
      sigmaService: 'sshd',
      fields: [
        'timestamp',
        'hostname',
        'pid',
        'message',
        'user',
        'rhost',
        'port',
        'method',
        'key_type',
        'key_fingerprint',
      ],
    },
  ],
]);

// ---------------------------------------------------------------------------
// Lookup Functions
// ---------------------------------------------------------------------------

/**
 * Retrieve the full mapping for a given Linux log source name.
 */
export function getLinuxLogMapping(
  source: string,
): LinuxLogMapping | undefined {
  return linuxLogMappings.get(source);
}

/**
 * Return the list of available fields for a given Linux log source.
 * Returns an empty array when the source is unknown.
 */
export function getLinuxFieldsForSource(source: string): string[] {
  const mapping = linuxLogMappings.get(source);
  return mapping ? mapping.fields : [];
}

/**
 * Derive the Sigma logsource block values for a given Linux log source.
 */
export function getLinuxSigmaLogsource(
  source: string,
): { product: string; service?: string; category?: string } {
  const mapping = linuxLogMappings.get(source);
  if (!mapping) {
    return { product: 'linux' };
  }

  const result: { product: string; service?: string; category?: string } = {
    product: mapping.sigmaProduct,
    service: mapping.sigmaService,
  };

  if (mapping.sigmaCategory) {
    result.category = mapping.sigmaCategory;
  }

  return result;
}

/**
 * Return all registered Linux log source mappings.
 */
export function getAllLinuxSources(): LinuxLogMapping[] {
  return [...linuxLogMappings.values()];
}
