/**
 * Normalizes OTRF Security-Datasets log entries into flat LogEntry objects
 * compatible with the DetectForge sigma-tester evaluation engine.
 *
 * OTRF logs are nested Windows Event Log JSON structures. This module:
 * 1. Extracts the Sysmon/Security EventID from each entry
 * 2. Maps EventID → Sigma logsource category
 * 3. Flattens nested fields (EventData.*, System.*) to top-level
 * 4. Groups logs by category and separates attack vs benign entries
 */

import type { LogEntry } from '@/testing/sigma-tester.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface NormalizedLogSet {
  /** Sigma logsource category */
  category: string;
  /** Logs from attack activity */
  attackLogs: LogEntry[];
  /** Background noise / benign logs from the same dataset */
  benignLogs: LogEntry[];
}

// ---------------------------------------------------------------------------
// EventID → Sigma Category Mapping
// ---------------------------------------------------------------------------

/** Sysmon EventID → Sigma logsource category */
const SYSMON_CATEGORY_MAP: Record<number, string> = {
  1: 'process_creation',
  2: 'file_change',                // File creation time changed
  3: 'network_connection',
  5: 'process_termination',
  6: 'driver_loaded',
  7: 'image_load',
  8: 'create_remote_thread',
  9: 'raw_access_read',
  10: 'process_access',
  11: 'file_event',
  12: 'registry_event',
  13: 'registry_set',
  14: 'registry_rename',
  15: 'file_event',                // FileCreateStreamHash
  17: 'pipe_created',
  18: 'pipe_connected',
  22: 'dns_query',
  23: 'file_delete',
  25: 'process_tampering',
  26: 'file_delete',               // FileDeleteDetected
};

/** Windows Security EventID → Sigma logsource category */
const SECURITY_CATEGORY_MAP: Record<number, string> = {
  4624: 'authentication',          // Successful logon
  4625: 'authentication',          // Failed logon
  4648: 'authentication',          // Logon using explicit credentials
  4672: 'authentication',          // Special privileges assigned
  4688: 'process_creation',        // Process creation (command-line auditing)
  4689: 'process_termination',
  4698: 'process_creation',        // Scheduled task created
  4699: 'process_creation',        // Scheduled task deleted
  4700: 'process_creation',        // Scheduled task enabled
  4702: 'process_creation',        // Scheduled task updated
  4720: 'authentication',          // User account created
  4732: 'authentication',          // Member added to security-enabled local group
  4768: 'authentication',          // Kerberos TGT request
  4769: 'authentication',          // Kerberos service ticket
  4776: 'authentication',          // NTLM authentication
  5140: 'network_connection',      // Network share accessed
  5145: 'network_connection',      // Network share object checked
};

/** PowerShell EventIDs (Microsoft-Windows-PowerShell) */
const POWERSHELL_CATEGORY_MAP: Record<number, string> = {
  800: 'ps_script',                // Pipeline execution (HostApplication field)
  4103: 'ps_script',               // Module logging
  4104: 'ps_script',               // Script block logging
  4105: 'ps_script',               // Script block start
  4106: 'ps_script',               // Script block stop
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Normalize raw OTRF log entries into categorized, flat LogEntry sets.
 *
 * @param rawLogs           Array of raw JSON log objects from OTRF dataset
 * @param targetCategories  Only return log sets matching these categories
 * @param attackPatterns    Optional patterns to identify attack-related entries
 */
export function normalizeOTRFLogs(
  rawLogs: unknown[],
  targetCategories: string[],
  attackPatterns?: AttackPattern[],
): NormalizedLogSet[] {
  // Step 1: Flatten and categorize each log entry
  const categorized = new Map<string, LogEntry[]>();

  for (const raw of rawLogs) {
    if (typeof raw !== 'object' || raw === null) continue;

    const entry = raw as Record<string, unknown>;
    const flat = flattenLogEntry(entry);
    const category = determineCategory(entry, flat);

    if (!category) continue;
    if (!targetCategories.includes(category)) continue;

    if (!categorized.has(category)) {
      categorized.set(category, []);
    }
    categorized.get(category)!.push(flat);
  }

  // Step 2: Deduplicate EID 1 (Sysmon) vs EID 4688 (Security) for process_creation.
  // When both exist for the same process, keep only the Sysmon event (richer fields
  // including ParentCommandLine). This prevents 50% automatic failure rate for rules
  // that need ParentCommandLine.
  const processCreationLogs = categorized.get('process_creation');
  if (processCreationLogs && processCreationLogs.length > 1) {
    categorized.set('process_creation', deduplicateProcessCreation(processCreationLogs));
  }

  // Step 3: Split each category into attack vs benign logs
  const results: NormalizedLogSet[] = [];

  for (const [category, logs] of categorized) {
    const { attack, benign } = splitAttackBenign(logs, attackPatterns, category);

    results.push({
      category,
      attackLogs: attack,
      benignLogs: benign,
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// EID 1 / EID 4688 Deduplication
// ---------------------------------------------------------------------------

/**
 * Deduplicate Sysmon EID 1 and Security EID 4688 process_creation logs.
 *
 * Both event sources record process creation, but Sysmon has richer fields
 * (ParentCommandLine, Hashes, etc.). When both exist for the same process,
 * keep only the event with more populated fields.
 *
 * Groups by (Image, CommandLine, approximate timestamp) and picks the winner.
 */
function deduplicateProcessCreation(logs: LogEntry[]): LogEntry[] {
  // Build dedup key: Image + CommandLine + timestamp rounded to 2-second window
  function dedupKey(log: LogEntry): string {
    const image = String(log['Image'] ?? '').toLowerCase();
    const cmd = String(log['CommandLine'] ?? '').toLowerCase();
    const ts = String(log['UtcTime'] ?? log['TimeCreated'] ?? '');
    // Round timestamp to 2s window to catch near-simultaneous events
    const tsRounded = ts.substring(0, 18); // "YYYY-MM-DD HH:MM:S" — drops last digit of seconds
    return `${image}|${cmd}|${tsRounded}`;
  }

  function fieldCount(log: LogEntry): number {
    return Object.values(log).filter(v => v !== null && v !== undefined && v !== '').length;
  }

  const groups = new Map<string, LogEntry>();
  const unique: LogEntry[] = [];

  for (const log of logs) {
    const key = dedupKey(log);
    const existing = groups.get(key);

    if (!existing) {
      groups.set(key, log);
      unique.push(log);
    } else if (fieldCount(log) > fieldCount(existing)) {
      // Replace with richer event
      const idx = unique.indexOf(existing);
      if (idx >= 0) unique[idx] = log;
      groups.set(key, log);
    }
    // else: keep existing (already richer or equal)
  }

  return unique;
}

// ---------------------------------------------------------------------------
// Attack Pattern Matching
// ---------------------------------------------------------------------------

export interface AttackPattern {
  /** Field to check */
  field: string;
  /** Substring to match (case-insensitive) */
  contains?: string;
  /** Regex to match */
  regex?: RegExp;
  /** Only apply this pattern to logs from this category. Omit = all categories. */
  category?: string;
}

/**
 * Default patterns that indicate attack-related activity.
 *
 * DESIGN PRINCIPLE: Behavioral, not tool-specific.
 * These patterns identify OS-level attack behaviors (LSASS access,
 * service-spawned shells, encoded commands, credential store targeting)
 * rather than specific tool names (mimikatz, empire, covenant).
 *
 * This ensures novel tools performing the same technique are still
 * classified as attack activity.
 */
const DEFAULT_ATTACK_PATTERNS: AttackPattern[] = [
  // === 1. LSASS access (any tool accessing LSASS memory) ===
  { field: 'TargetImage', contains: 'lsass.exe' },

  // === 2. Suspicious access masks (OS constants, not tool-specific) ===
  { field: 'GrantedAccess', contains: '0x1010' },
  { field: 'GrantedAccess', contains: '0x1038' },
  { field: 'GrantedAccess', contains: '0x1438' },
  { field: 'GrantedAccess', contains: '0x143a' },
  { field: 'GrantedAccess', contains: '0x1fffff' },

  // === 3. Process injection indicators (OS-level behavior) ===
  { field: 'CallTrace', contains: 'UNKNOWN' },
  { field: 'StartFunction', contains: 'LoadLibrary' },

  // === 4. Encoded commands (any framework using encoding) ===
  { field: 'CommandLine', contains: '-enc' },
  { field: 'CommandLine', contains: '-encodedcommand' },
  { field: 'CommandLine', contains: 'FromBase64String' },
  { field: 'CommandLine', contains: 'downloadstring' },
  { field: 'CommandLine', contains: 'iex' },
  { field: 'CommandLine', contains: 'bypass' },
  { field: 'ParentCommandLine', contains: '-enc' },
  { field: 'ParentCommandLine', contains: '-encodedcommand' },
  { field: 'ParentCommandLine', contains: 'bypass' },
  { field: 'ParentCommandLine', contains: 'invoke-' },

  // === 5. PowerShell cmdlet patterns (language-level, not tool-specific) ===
  { field: 'CommandLine', contains: 'invoke-' },
  { field: 'ScriptBlockText', contains: 'invoke-' },
  { field: 'ScriptBlockText', contains: 'downloadstring' },

  // === 6. Credential store targeting (behavioral, not tool-name) ===
  { field: 'CommandLine', contains: 'reg save' },
  { field: 'CommandLine', contains: 'ntds.dit' },
  { field: 'CommandLine', contains: 'comsvcs' },
  { field: 'TargetObject', contains: 'WDigest' },
  { field: 'TargetObject', contains: 'SecurityProviders' },
  { field: 'TargetObject', contains: 'SAM' },

  // === 7. Registry persistence (OS path, not tool-specific) ===
  { field: 'TargetObject', contains: 'CurrentVersion\\Run' },
  { field: 'TargetObject', contains: 'CurrentVersion\\RunOnce' },

  // === 8. LOLBin execution patterns (the binary IS the behavior) ===
  { field: 'Image', contains: 'rundll32' },
  { field: 'Image', contains: 'regsvr32' },
  { field: 'Image', contains: 'mshta' },
  { field: 'Image', contains: 'cmstp' },
  { field: 'Image', contains: 'certutil' },
  { field: 'Image', contains: 'cscript' },
  { field: 'Image', contains: 'wscript' },

  // === 9. OS utilities used for attack (the OS capability IS the detection) ===
  { field: 'CommandLine', contains: 'schtasks' },
  { field: 'CommandLine', contains: 'vssadmin' },
  { field: 'CommandLine', contains: 'bcdedit' },
  { field: 'CommandLine', contains: 'wbadmin' },
  { field: 'CommandLine', contains: 'sc.exe' },
  { field: 'CommandLine', contains: 'wmic' },

  // === 10. Service-spawned shells (lateral movement behavioral indicator) ===
  { field: 'ParentImage', contains: 'services.exe' },

  // === 11. Child processes spawned by suspicious LOLBin parents ===
  { field: 'ParentImage', contains: 'mshta' },
  { field: 'ParentImage', contains: 'wscript' },
  { field: 'ParentImage', contains: 'cscript' },

  // === 12. Injection source processes (OS binaries as injection sources) ===
  { field: 'SourceImage', contains: 'powershell' },
  { field: 'SourceImage', contains: 'cmd.exe' },
  { field: 'SourceImage', contains: 'wscript' },
  { field: 'SourceImage', contains: 'cscript' },
  { field: 'SourceImage', contains: 'mshta' },

  // === 13. Credential dumping utilities (behavioral patterns, not tool names) ===
  { field: 'CommandLine', contains: 'minidump' },
  { field: 'CommandLine', contains: 'MiniDump' },
  { field: 'CommandLine', contains: 'dcsync' },
  { field: 'CommandLine', contains: 'lsadump' },

  // === 14. Network discovery/enumeration ===
  { field: 'Image', contains: 'seatbelt' },
  { field: 'CommandLine', contains: 'net view' },
  { field: 'CommandLine', contains: 'net share' },
];

/**
 * Split logs into attack and benign sets based on pattern matching.
 *
 * For OTRF datasets where all logs come from attack simulations, we use
 * pattern matching to identify the core attack indicators (the entries
 * our Sigma rules should detect) vs background system noise.
 */
function splitAttackBenign(
  logs: LogEntry[],
  patterns?: AttackPattern[],
  category?: string,
): { attack: LogEntry[]; benign: LogEntry[] } {
  // When a dataset has specific attackPatterns, those describe exactly what
  // the simulation did. Use them exclusively to avoid inflating TP by
  // classifying unrelated logs as "attack" via broad defaults.
  const activePatterns = patterns && patterns.length > 0
    ? patterns
    : DEFAULT_ATTACK_PATTERNS;
  const attack: LogEntry[] = [];
  const benign: LogEntry[] = [];

  for (const log of logs) {
    if (matchesAnyPattern(log, activePatterns, category)) {
      attack.push(log);
    } else {
      benign.push(log);
    }
  }

  // If no logs matched any pattern, we can't identify the attack signal.
  // Return empty attack set — the rule gets "no-data" for this category
  // rather than a garbage TP rate from arbitrary log slicing.
  if (attack.length === 0 && logs.length > 0) {
    return { attack: [], benign: logs };
  }

  return { attack, benign };
}

function matchesAnyPattern(
  log: LogEntry,
  patterns: AttackPattern[],
  category?: string,
): boolean {
  for (const pattern of patterns) {
    // Skip patterns constrained to a different category
    if (pattern.category && category && pattern.category !== category) continue;

    const value = log[pattern.field];
    if (value === null || value === undefined) continue;

    const str = String(value).toLowerCase();

    if (pattern.contains && str.includes(pattern.contains.toLowerCase())) {
      return true;
    }
    if (pattern.regex && pattern.regex.test(str)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Log Flattening
// ---------------------------------------------------------------------------

/**
 * Flatten a nested OTRF log entry into a flat LogEntry, then apply
 * field alias mapping so Sigma rules can match regardless of whether
 * the source was Sysmon (EventID 1) or Windows Security (EventID 4688).
 */
function flattenLogEntry(raw: Record<string, unknown>): LogEntry {
  const flat: LogEntry = {};

  for (const [key, value] of Object.entries(raw)) {
    if (value === null || value === undefined) continue;

    if (typeof value === 'object' && !Array.isArray(value)) {
      // Flatten nested objects (EventData, System, UserData, etc.)
      const nested = value as Record<string, unknown>;
      for (const [nestedKey, nestedValue] of Object.entries(nested)) {
        if (nestedKey === 'EventID' && typeof nestedValue === 'object' && nestedValue !== null) {
          const eid = nestedValue as Record<string, unknown>;
          flat['EventID'] = toPrimitive(eid['#text'] ?? eid['value'] ?? eid);
        } else {
          flat[nestedKey] = toPrimitive(nestedValue);
        }
      }
    } else {
      flat[key] = toPrimitive(value);
    }
  }

  // --- Field alias mapping ---
  // Windows Security EventID 4688 uses different field names than Sysmon.
  // Map them to Sigma-standard names so rules work against both sources.
  applyFieldAliases(flat);

  // --- Registry path normalization ---
  // Real logs use HKU\<SID>\... but Sigma rules use HKCU\...
  normalizeRegistryPaths(flat);

  return flat;
}

/**
 * Windows Security audit logs use different field names than Sysmon.
 * Sigma rules expect Sysmon-style names.  Map aliases so rules match.
 *
 * Only sets the alias if the canonical field is NOT already present,
 * to avoid overwriting Sysmon data with Security data in mixed logs.
 */
const FIELD_ALIASES: [string, string][] = [
  // Windows Security 4688 → Sigma process_creation fields
  ['NewProcessName', 'Image'],
  ['ParentProcessName', 'ParentImage'],
  ['SubjectUserName', 'User'],
  ['TargetUserName', 'TargetUser'],
  ['IpAddress', 'SourceIp'],
  ['IpPort', 'SourcePort'],
  ['WorkstationName', 'Workstation'],
  // PowerShell script block logging
  ['Payload', 'ScriptBlockText'],
];

function applyFieldAliases(flat: LogEntry): void {
  for (const [source, target] of FIELD_ALIASES) {
    if (flat[source] !== undefined && flat[source] !== null && flat[target] === undefined) {
      flat[target] = flat[source];
    }
  }

  // Composite User field: "DOMAIN\Username" if both parts available
  if (flat['User'] === undefined && flat['SubjectUserName'] !== undefined) {
    const domain = flat['SubjectDomainName'];
    const user = flat['SubjectUserName'];
    flat['User'] = domain ? `${domain}\\${user}` : String(user);
  }
}

/**
 * Normalize Windows registry paths for Sigma matching.
 *
 * Real Sysmon logs record user-hive paths as:
 *   HKU\S-1-5-21-XXXXX\Software\Microsoft\...
 * But Sigma rules use the shorthand:
 *   HKCU\Software\Microsoft\...
 *
 * Map the SID-based paths to HKCU so rules can match.
 */
function normalizeRegistryPaths(flat: LogEntry): void {
  const targetObject = flat['TargetObject'];
  if (typeof targetObject !== 'string') return;

  // HKU\<SID>\ → HKCU\  (SIDs start with S-1-5-)
  const normalized = targetObject.replace(
    /^HKU\\S-1-5-\d+-\d+-\d+-\d+-\d+\\/i,
    'HKCU\\',
  );

  if (normalized !== targetObject) {
    flat['TargetObject'] = normalized;
  }
}

/**
 * Convert a value to a LogEntry-compatible primitive.
 */
function toPrimitive(
  value: unknown,
): string | number | boolean | null | undefined {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return value;
  if (typeof value === 'boolean') return value;
  return String(value);
}

// ---------------------------------------------------------------------------
// Category Detection
// ---------------------------------------------------------------------------

/**
 * Determine the Sigma logsource category for a log entry.
 */
function determineCategory(
  raw: Record<string, unknown>,
  flat: LogEntry,
): string | null {
  const eventId = extractEventId(raw, flat);
  if (eventId === null) return null;

  const channel = String(
    flat['Channel'] ?? raw['Channel'] ?? '',
  ).toLowerCase();

  // Sysmon events
  if (channel.includes('sysmon')) {
    return SYSMON_CATEGORY_MAP[eventId] ?? null;
  }

  // PowerShell events
  if (channel.includes('powershell')) {
    return POWERSHELL_CATEGORY_MAP[eventId] ?? null;
  }

  // Windows Security events
  if (channel.includes('security')) {
    return SECURITY_CATEGORY_MAP[eventId] ?? null;
  }

  // If no channel, try Sysmon mapping first (most OTRF data is Sysmon),
  // then Security
  return (
    SYSMON_CATEGORY_MAP[eventId] ??
    SECURITY_CATEGORY_MAP[eventId] ??
    POWERSHELL_CATEGORY_MAP[eventId] ??
    null
  );
}

/**
 * Extract the numeric EventID from various OTRF log formats.
 */
function extractEventId(
  raw: Record<string, unknown>,
  flat: LogEntry,
): number | null {
  // Check flat version first
  const flatId = flat['EventID'];
  if (flatId !== null && flatId !== undefined) {
    const num = Number(flatId);
    if (!isNaN(num)) return num;
  }

  // Check nested System.EventID
  const system = raw['System'] as Record<string, unknown> | undefined;
  if (system) {
    const sysEventId = system['EventID'];
    if (typeof sysEventId === 'number') return sysEventId;
    if (typeof sysEventId === 'string') {
      const num = Number(sysEventId);
      if (!isNaN(num)) return num;
    }
    // Nested { "#text": "1" } format
    if (typeof sysEventId === 'object' && sysEventId !== null) {
      const eid = sysEventId as Record<string, unknown>;
      const text = eid['#text'] ?? eid['value'];
      if (text !== undefined) {
        const num = Number(text);
        if (!isNaN(num)) return num;
      }
    }
  }

  // Direct EventID field
  const directId = raw['EventID'];
  if (directId !== null && directId !== undefined) {
    const num = Number(directId);
    if (!isNaN(num)) return num;
  }

  return null;
}
