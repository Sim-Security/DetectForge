/**
 * Synthetic log generator for Sigma rule testing.
 *
 * Parses a Sigma rule's detection block to extract field / value pairs,
 * then produces:
 * - **Attack logs** that satisfy the rule's condition.
 * - **Benign logs** that populate the same fields with non-matching values
 *   (some partial-match for edge-case coverage).
 */

import type { SigmaRule } from '@/types/detection-rule.js';
import type { LogEntry } from './sigma-tester.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface GeneratedLogSet {
  attackLogs: LogEntry[];
  benignLogs: LogEntry[];
  ruleId: string;
  ruleTitle: string;
}

export interface LogGenerationOptions {
  attackLogCount?: number;
  benignLogCount?: number;
}

// ---------------------------------------------------------------------------
// Constants — realistic benign values for common Sigma fields
// ---------------------------------------------------------------------------

const BENIGN_PROCESSES: string[] = [
  'C:\\Windows\\System32\\svchost.exe',
  'C:\\Windows\\System32\\lsass.exe',
  'C:\\Windows\\explorer.exe',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
  'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
  'C:\\Windows\\System32\\taskhostw.exe',
  'C:\\Windows\\System32\\RuntimeBroker.exe',
  'C:\\Windows\\System32\\SearchIndexer.exe',
  'C:\\Windows\\System32\\spoolsv.exe',
];

const BENIGN_COMMAND_LINES: string[] = [
  'svchost.exe -k netsvcs',
  'chrome.exe --type=renderer',
  '"C:\\Program Files\\Mozilla Firefox\\firefox.exe" -contentproc',
  'taskhostw.exe SYSTEM',
  'SearchIndexer.exe /Embedding',
  'RuntimeBroker.exe -Embedding',
  'spoolsv.exe',
  'explorer.exe',
];

const BENIGN_USERS: string[] = [
  'SYSTEM',
  'LOCAL SERVICE',
  'NETWORK SERVICE',
  'Administrator',
  'john.doe',
  'jane.smith',
  'svc_backup',
];

const BENIGN_PARENTS: string[] = [
  'C:\\Windows\\System32\\services.exe',
  'C:\\Windows\\System32\\svchost.exe',
  'C:\\Windows\\explorer.exe',
  'C:\\Windows\\System32\\wininit.exe',
  'C:\\Windows\\System32\\winlogon.exe',
];

const BENIGN_TARGET_FILES: string[] = [
  'C:\\Users\\john\\Documents\\report.docx',
  'C:\\Windows\\Temp\\install_log.txt',
  'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Chrome.lnk',
  'C:\\Users\\john\\AppData\\Local\\Temp\\tmp1234.tmp',
  'C:\\Windows\\System32\\config\\system.log',
];

const BENIGN_REGISTRY_KEYS: string[] = [
  'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer',
  'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip',
  'HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word',
];

const BENIGN_REGISTRY_VALUES: string[] = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Windows\\System32\\svchost.exe -k netsvcs',
  '1',
  '0',
  'Enabled',
];

const BENIGN_DNS_QUERIES: string[] = [
  'www.google.com',
  'login.microsoftonline.com',
  'update.microsoft.com',
  'cdn.jsdelivr.net',
  'fonts.googleapis.com',
  'api.github.com',
];

const BENIGN_DEST_IPS: string[] = [
  '10.0.0.1',
  '192.168.1.1',
  '172.16.0.1',
  '8.8.8.8',
  '1.1.1.1',
];

const BENIGN_DEST_PORTS: string[] = [
  '80',
  '443',
  '53',
  '8080',
  '3389',
];

/**
 * Map from common Sigma field names (lowercase) to pools of realistic
 * benign values.
 */
const BENIGN_VALUE_POOLS: Record<string, string[]> = {
  image: BENIGN_PROCESSES,
  parentimage: BENIGN_PARENTS,
  originalfilename: BENIGN_PROCESSES.map((p) => p.split('\\').pop() ?? p),
  commandline: BENIGN_COMMAND_LINES,
  parentcommandline: BENIGN_COMMAND_LINES,
  user: BENIGN_USERS,
  targetfilename: BENIGN_TARGET_FILES,
  targetobject: BENIGN_REGISTRY_KEYS,
  details: BENIGN_REGISTRY_VALUES,
  queryname: BENIGN_DNS_QUERIES,
  destinationip: BENIGN_DEST_IPS,
  destinationport: BENIGN_DEST_PORTS,
  sourceip: BENIGN_DEST_IPS,
  sourceport: BENIGN_DEST_PORTS,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate attack + benign logs for a Sigma rule.
 */
export function generateTestLogs(
  rule: SigmaRule,
  options?: LogGenerationOptions,
): GeneratedLogSet {
  const attackLogCount = options?.attackLogCount ?? 5;
  const benignLogCount = options?.benignLogCount ?? 10;

  const detection = rule.detection;
  const condition = detection.condition;

  // Extract all selection blocks from the detection
  const selections = extractSelections(detection);

  // Determine which selections are "positive" (should match) vs "filters"
  // (should NOT match) based on condition keywords.
  const { positive, filters } = classifySelections(
    selections,
    condition,
  );

  const attackLogs: LogEntry[] = [];
  for (let i = 0; i < attackLogCount; i++) {
    attackLogs.push(
      buildAttackLog(positive, filters, selections, i),
    );
  }

  const benignLogs: LogEntry[] = [];
  for (let i = 0; i < benignLogCount; i++) {
    benignLogs.push(
      buildBenignLog(positive, filters, selections, i, benignLogCount),
    );
  }

  return {
    attackLogs,
    benignLogs,
    ruleId: rule.id,
    ruleTitle: rule.title,
  };
}

// ---------------------------------------------------------------------------
// Selection Extraction
// ---------------------------------------------------------------------------

interface FieldSpec {
  fieldName: string;
  modifiers: string[];
  values: string[];
}

interface SelectionBlock {
  name: string;
  fields: FieldSpec[];
}

/**
 * Extract structured selection blocks from a Sigma detection object.
 */
function extractSelections(
  detection: Record<string, unknown>,
): SelectionBlock[] {
  const blocks: SelectionBlock[] = [];

  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;

    const fields = extractFieldSpecs(value);
    blocks.push({ name: key, fields });
  }

  return blocks;
}

/**
 * Extract field specifications from a selection value.
 */
function extractFieldSpecs(value: unknown): FieldSpec[] {
  if (typeof value !== 'object' || value === null) {
    return [];
  }

  // Handle array-of-maps (Sigma list selection)
  if (Array.isArray(value)) {
    const allFields: FieldSpec[] = [];
    for (const item of value) {
      allFields.push(...extractFieldSpecs(item));
    }
    return allFields;
  }

  const fields: FieldSpec[] = [];
  const obj = value as Record<string, unknown>;

  for (const [rawKey, rawValues] of Object.entries(obj)) {
    const parts = rawKey.split('|');
    const fieldName = parts[0];
    const modifiers = parts.slice(1);

    const values = normalizeToStringArray(rawValues);
    fields.push({ fieldName, modifiers, values });
  }

  return fields;
}

// ---------------------------------------------------------------------------
// Selection Classification
// ---------------------------------------------------------------------------

interface SelectionClassification {
  positive: string[];
  filters: string[];
}

/**
 * Classify selections as positive or filter based on the condition string.
 *
 * Simple heuristic: if a selection name appears after "not" in the condition,
 * or starts with "filter", it is a filter.  Everything else is positive.
 */
function classifySelections(
  selections: SelectionBlock[],
  condition: string,
): SelectionClassification {
  const condLower = condition.toLowerCase();

  const positive: string[] = [];
  const filters: string[] = [];

  for (const sel of selections) {
    const name = sel.name;
    const nameLower = name.toLowerCase();

    const isNegated =
      condLower.includes(`not ${nameLower}`) ||
      condLower.includes(`not 1 of ${nameLower}`) ||
      condLower.includes(`not all of ${nameLower}`);

    if (isNegated || nameLower.startsWith('filter')) {
      filters.push(name);
    } else {
      positive.push(name);
    }
  }

  return { positive, filters };
}

// ---------------------------------------------------------------------------
// Attack Log Generation
// ---------------------------------------------------------------------------

/**
 * Build an attack log that should trigger the rule.
 *
 * Strategy: populate all positive-selection fields with matching values,
 * and all filter-selection fields with NON-matching values.
 */
function buildAttackLog(
  positiveNames: string[],
  filterNames: string[],
  selections: SelectionBlock[],
  index: number,
): LogEntry {
  const log: LogEntry = {};

  // Add matching values for every positive selection
  for (const name of positiveNames) {
    const sel = selections.find((s) => s.name === name);
    if (!sel) continue;

    for (const field of sel.fields) {
      const value = pickMatchingValue(field, index);
      log[field.fieldName] = value;
    }
  }

  // Add NON-matching values for filter selections so the filter does not
  // fire (the condition uses "not filter", so filter not matching = good).
  for (const name of filterNames) {
    const sel = selections.find((s) => s.name === name);
    if (!sel) continue;

    for (const field of sel.fields) {
      // Only set if not already set by a positive selection
      if (!(field.fieldName in log)) {
        log[field.fieldName] = pickNonMatchingBenignValue(field, index);
      }
    }
  }

  // Add filler fields for realism
  addRealisticFillerFields(log, index);

  // Apply field correlations for realistic inter-field relationships
  applyFieldCorrelations(log);

  return log;
}

/**
 * Pick a value from the selection's expected values that would match.
 *
 * For wildcard patterns we generate a concrete string that satisfies the
 * pattern.
 */
function pickMatchingValue(field: FieldSpec, index: number): string {
  if (field.values.length === 0) return '';

  const value = field.values[index % field.values.length];
  return expandWildcard(value);
}

/**
 * Expand a Sigma wildcard pattern into a concrete matching string.
 *
 * Examples:
 *   "*\\cmd.exe"          -> "C:\\Windows\\System32\\cmd.exe"
 *   "*-encodedcommand*"   -> "powershell -encodedcommand ZW5j"
 *   "*.evil.com"          -> "malware.evil.com"
 */
function expandWildcard(pattern: string): string {
  if (!pattern.includes('*') && !pattern.includes('?')) {
    return pattern;
  }

  // Replace leading * with a realistic prefix
  let result = pattern;

  // Replace leading `*\` (common Windows path wildcard)
  if (result.startsWith('*\\')) {
    result = 'C:\\Windows\\System32' + result.slice(1);
  } else if (result.startsWith('*/')) {
    result = '/usr/bin' + result.slice(1);
  } else if (result.startsWith('*.')) {
    result = 'malicious' + result.slice(1);
  } else if (result.startsWith('*')) {
    result = 'prefix_' + result.slice(1);
  }

  // Replace trailing *
  if (result.endsWith('*')) {
    result = result.slice(0, -1) + '_suffix';
  }

  // Replace internal *
  result = result.replace(/\*/g, '_mid_');

  // Replace ? with a single character
  result = result.replace(/\?/g, 'x');

  return result;
}

// ---------------------------------------------------------------------------
// Benign Log Generation
// ---------------------------------------------------------------------------

/**
 * Build a benign log that should NOT trigger the rule.
 *
 * Strategy:
 * - Most logs use completely non-matching values.
 * - A few logs (index-based) include partial matches to test edge cases:
 *   they match some fields of a selection but not all.
 */
function buildBenignLog(
  positiveNames: string[],
  _filterNames: string[],
  selections: SelectionBlock[],
  index: number,
  totalCount: number,
): LogEntry {
  const log: LogEntry = {};

  // Collect all field names used across all selections
  const allFields = new Set<string>();
  for (const sel of selections) {
    for (const field of sel.fields) {
      allFields.add(field.fieldName);
    }
  }

  // Use template-based benign logs for ~30% of entries (every 3rd log)
  if (index % 3 === 0 && BENIGN_LOG_TEMPLATES.length > 0) {
    const template = BENIGN_LOG_TEMPLATES[index % BENIGN_LOG_TEMPLATES.length];
    for (const [key, value] of Object.entries(template)) {
      log[key] = value;
    }
    // Add any remaining detection fields not covered by template
    for (const fieldName of allFields) {
      if (!(fieldName in log)) {
        log[fieldName] = pickBenignValue(fieldName, index);
      }
    }
    addRealisticFillerFields(log, index);
    return log;
  }

  // Determine if this log should be a partial-match edge case
  // (roughly 20% of benign logs)
  const isPartialMatch = index < Math.ceil(totalCount * 0.2);

  if (isPartialMatch && positiveNames.length > 0) {
    // Pick a positive selection and match SOME fields but not all
    const selName = positiveNames[index % positiveNames.length];
    const sel = selections.find((s) => s.name === selName);
    if (sel && sel.fields.length > 1) {
      // Match the first field, use benign for the rest
      const firstField = sel.fields[0];
      log[firstField.fieldName] = pickMatchingValue(firstField, index);

      for (let f = 1; f < sel.fields.length; f++) {
        const field = sel.fields[f];
        log[field.fieldName] = pickBenignValue(field.fieldName, index + f);
      }
    }
  }

  // Fill remaining fields with benign values
  for (const fieldName of allFields) {
    if (!(fieldName in log)) {
      log[fieldName] = pickBenignValue(fieldName, index);
    }
  }

  addRealisticFillerFields(log, index);

  return log;
}

/**
 * Pick a realistic benign value for a given field name.
 */
function pickBenignValue(fieldName: string, index: number): string {
  const pool = BENIGN_VALUE_POOLS[fieldName.toLowerCase()];
  if (pool && pool.length > 0) {
    return pool[index % pool.length];
  }
  // Generic fallback
  return `benign_value_${index}`;
}

/**
 * Pick a benign value for a filter field that does NOT match any of the
 * filter's expected values (case-insensitive).  This prevents attack logs
 * from accidentally triggering the filter they should bypass.
 */
function pickNonMatchingBenignValue(field: FieldSpec, index: number): string {
  const lowerValues = field.values.map((v) => v.toLowerCase());
  const pool = BENIGN_VALUE_POOLS[field.fieldName.toLowerCase()];
  if (pool && pool.length > 0) {
    // Try cycling through the pool starting at `index`
    for (let i = 0; i < pool.length; i++) {
      const candidate = pool[(index + i) % pool.length];
      if (!lowerValues.includes(candidate.toLowerCase())) {
        return candidate;
      }
    }
  }
  // Fallback: a value guaranteed not to collide with the filter
  return `non_filter_value_${index}`;
}

// ---------------------------------------------------------------------------
// Filler Fields
// ---------------------------------------------------------------------------

const FILLER_FIELDS: Array<{ key: string; values: string[] }> = [
  {
    key: 'EventID',
    values: ['1', '3', '7', '11', '13', '4688', '4624'],
  },
  {
    key: 'Computer',
    values: [
      'WORKSTATION01',
      'SERVER-DC01',
      'LAPTOP-HR03',
      'DESKTOP-DEV42',
    ],
  },
  {
    key: 'LogonId',
    values: ['0x3e7', '0x1a2b3c', '0x44556', '0x9f8e7d'],
  },
  {
    key: 'IntegrityLevel',
    values: ['System', 'High', 'Medium', 'Low'],
  },
];

/**
 * Add a few non-detection filler fields for realism.
 */
function addRealisticFillerFields(log: LogEntry, index: number): void {
  for (const filler of FILLER_FIELDS) {
    if (!(filler.key in log)) {
      log[filler.key] = filler.values[index % filler.values.length];
    }
  }
}

// ---------------------------------------------------------------------------
// Field Correlations — ensure synthetic logs have realistic field relationships
// ---------------------------------------------------------------------------

interface FieldCorrelation {
  triggerField: string;
  triggerContains: string;
  dependentField: string;
  action: 'prefix-commandline' | 'set-value';
  value: string;
}

const FIELD_CORRELATIONS: FieldCorrelation[] = [
  // CommandLine should reference the Image binary
  { triggerField: 'Image', triggerContains: 'powershell.exe', dependentField: 'CommandLine', action: 'prefix-commandline', value: 'powershell.exe' },
  { triggerField: 'Image', triggerContains: 'cmd.exe', dependentField: 'CommandLine', action: 'prefix-commandline', value: 'cmd.exe' },
  { triggerField: 'Image', triggerContains: 'rundll32.exe', dependentField: 'CommandLine', action: 'prefix-commandline', value: 'rundll32.exe' },
  { triggerField: 'Image', triggerContains: 'reg.exe', dependentField: 'CommandLine', action: 'prefix-commandline', value: 'reg.exe' },
  { triggerField: 'Image', triggerContains: 'schtasks.exe', dependentField: 'CommandLine', action: 'prefix-commandline', value: 'schtasks.exe' },
  { triggerField: 'Image', triggerContains: 'net.exe', dependentField: 'CommandLine', action: 'prefix-commandline', value: 'net.exe' },
  { triggerField: 'Image', triggerContains: 'wmic.exe', dependentField: 'CommandLine', action: 'prefix-commandline', value: 'wmic.exe' },
  // services.exe parent implies SYSTEM user
  { triggerField: 'ParentImage', triggerContains: 'services.exe', dependentField: 'User', action: 'set-value', value: 'NT AUTHORITY\\SYSTEM' },
  // wmiprvse.exe parent implies NETWORK SERVICE user
  { triggerField: 'ParentImage', triggerContains: 'wmiprvse.exe', dependentField: 'User', action: 'set-value', value: 'NT AUTHORITY\\NETWORK SERVICE' },
];

/**
 * Apply field correlations to make synthetic logs more realistic.
 *
 * For 'prefix-commandline': if CommandLine exists but doesn't start with
 * the binary name, prepend it.
 * For 'set-value': override the dependent field with the correlated value.
 */
function applyFieldCorrelations(log: LogEntry): void {
  for (const corr of FIELD_CORRELATIONS) {
    const triggerVal = log[corr.triggerField];
    if (typeof triggerVal !== 'string') continue;
    if (!triggerVal.toLowerCase().includes(corr.triggerContains.toLowerCase())) continue;

    if (corr.action === 'prefix-commandline') {
      const depVal = log[corr.dependentField];
      if (typeof depVal !== 'string') continue;
      const depLower = depVal.toLowerCase();
      const prefixLower = corr.value.toLowerCase().replace('.exe', '');
      // Don't double-prefix if already starts with the binary name
      if (!depLower.startsWith(prefixLower)) {
        log[corr.dependentField] = corr.value + ' ' + depVal;
      }
    } else if (corr.action === 'set-value') {
      log[corr.dependentField] = corr.value;
    }
  }
}

// ---------------------------------------------------------------------------
// Benign Log Templates — coherent realistic log entries
// ---------------------------------------------------------------------------

const BENIGN_LOG_TEMPLATES: LogEntry[] = [
  {
    Image: 'C:\\Windows\\System32\\svchost.exe',
    CommandLine: 'svchost.exe -k netsvcs -p -s Schedule',
    ParentImage: 'C:\\Windows\\System32\\services.exe',
    User: 'NT AUTHORITY\\SYSTEM',
    IntegrityLevel: 'System',
  },
  {
    Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    CommandLine: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer --lang=en-US',
    ParentImage: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    User: 'WORKSTATION\\john.doe',
    IntegrityLevel: 'Medium',
  },
  {
    Image: 'C:\\Windows\\System32\\svchost.exe',
    CommandLine: 'svchost.exe -k LocalServiceNetworkRestricted -p -s WinHttpAutoProxySvc',
    ParentImage: 'C:\\Windows\\System32\\services.exe',
    User: 'NT AUTHORITY\\LOCAL SERVICE',
    IntegrityLevel: 'System',
  },
  {
    Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    CommandLine: 'powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\maintenance.ps1',
    ParentImage: 'C:\\Windows\\System32\\svchost.exe',
    User: 'WORKSTATION\\admin',
    IntegrityLevel: 'High',
  },
  {
    Image: 'C:\\Windows\\System32\\reg.exe',
    CommandLine: 'reg.exe query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies',
    ParentImage: 'C:\\Windows\\System32\\svchost.exe',
    User: 'NT AUTHORITY\\SYSTEM',
    IntegrityLevel: 'System',
  },
  {
    Image: 'C:\\Windows\\System32\\schtasks.exe',
    CommandLine: 'schtasks.exe /Run /TN "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start"',
    ParentImage: 'C:\\Windows\\System32\\svchost.exe',
    User: 'NT AUTHORITY\\SYSTEM',
    IntegrityLevel: 'System',
  },
  {
    Image: 'C:\\Windows\\explorer.exe',
    CommandLine: 'C:\\Windows\\explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}',
    ParentImage: 'C:\\Windows\\System32\\userinit.exe',
    User: 'WORKSTATION\\john.doe',
    IntegrityLevel: 'Medium',
  },
  {
    Image: 'C:\\Windows\\System32\\SearchIndexer.exe',
    CommandLine: 'C:\\Windows\\System32\\SearchIndexer.exe /Embedding',
    ParentImage: 'C:\\Windows\\System32\\services.exe',
    User: 'NT AUTHORITY\\SYSTEM',
    IntegrityLevel: 'System',
  },
];

// ---------------------------------------------------------------------------
// Evasion Variant Generation
// ---------------------------------------------------------------------------

export interface EvasionResult {
  originalTpRate: number;
  evasionTpRate: number;
  resilienceScore: number;  // evasionTpRate / originalTpRate (0-1)
  mutationsApplied: string[];
}

/**
 * Known Windows system binary filenames.
 * Detecting execution FROM these is behavioral detection (the OS capability
 * is the indicator, not a third-party tool). These should NOT be renamed
 * during evasion testing.
 */
const SYSTEM_BINARIES = new Set([
  'cmd.exe', 'powershell.exe', 'pwsh.exe', 'rundll32.exe', 'regsvr32.exe',
  'mshta.exe', 'cscript.exe', 'wscript.exe', 'schtasks.exe', 'reg.exe',
  'net.exe', 'net1.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe',
  'msiexec.exe', 'cmstp.exe', 'vssadmin.exe', 'ntdsutil.exe', 'fsutil.exe',
  'taskmgr.exe', 'services.exe', 'svchost.exe', 'lsass.exe', 'explorer.exe',
  'taskhostw.exe', 'dllhost.exe', 'wmiprvse.exe', 'conhost.exe',
  'systeminfo.exe', 'hostname.exe', 'ipconfig.exe', 'whoami.exe',
  'netstat.exe', 'sc.exe', 'tasklist.exe', 'wininit.exe', 'winlogon.exe',
  'spoolsv.exe', 'searchindexer.exe', 'runtimebroker.exe',
]);

/** Evasion replacement names for renamed tools */
const EVASION_TOOL_NAMES = [
  'updater.exe', 'svc_helper.exe', 'custom_tool.exe',
  'maintenance.exe', 'health_check.exe',
];

/** Evasion paths to replace well-known tool directories */
const EVASION_PATHS = [
  'C:\\Users\\Public\\',
  'C:\\Windows\\Temp\\',
  'C:\\ProgramData\\',
  'C:\\Users\\admin\\AppData\\Local\\Temp\\',
];

/** Environment variable path substitutions for evasion */
const ENV_SUBSTITUTIONS: [string, string][] = [
  ['C:\\Windows\\System32\\', '%SystemRoot%\\System32\\'],
  ['C:\\Windows\\', '%WINDIR%\\'],
];

/** Keywords for caret insertion evasion */
const CARET_KEYWORDS = ['powershell', 'invoke', 'bypass', 'hidden', 'downloadstring', 'iex'];

/** Behavioral fields that represent OS-level indicators — never mutated */
const BEHAVIORAL_FIELDS = new Set([
  'GrantedAccess', 'CallTrace', 'TargetImage', 'SourceImage', 'StartFunction',
]);

/** PowerShell argument format variations */
const PS_ARG_VARIANTS: [string, string[]][] = [
  ['-encodedcommand', ['-enc', '-e', '-EncodedCommand', '-EC']],
  ['-executionpolicy', ['-ep', '-exec', '-ExecutionPolicy']],
  ['-windowstyle', ['-w', '-WindowStyle']],
  ['-noprofile', ['-noP', '-NoProfile', '-nop']],
];

/**
 * Generate evasion variants of attack logs by mutating tool-specific fields
 * while preserving behavioral indicators.
 *
 * Returns mutated copies of the original attack logs plus a list of which
 * mutations were applied.
 */
export function generateEvasionVariants(
  attackLogs: LogEntry[],
): { mutatedLogs: LogEntry[]; mutationsApplied: string[] } {
  const mutatedLogs: LogEntry[] = [];
  const mutationsApplied = new Set<string>();

  for (const log of attackLogs) {
    const mutated = { ...log };
    let anyMutation = false;

    // 1. Rename executables in Image field
    if (typeof mutated.Image === 'string') {
      const renamed = renameExecutable(mutated.Image);
      if (renamed !== mutated.Image) {
        mutated.Image = renamed;
        mutationsApplied.add('rename-executable');
        anyMutation = true;
      }
    }

    // 2. Rename executables in OriginalFileName
    if (typeof mutated.OriginalFileName === 'string') {
      const renamed = renameExecutable(
        mutated.OriginalFileName,
      );
      if (renamed !== mutated.OriginalFileName) {
        mutated.OriginalFileName = renamed;
        mutationsApplied.add('rename-original-filename');
        anyMutation = true;
      }
    }

    // 3. Change paths in Image (keep filename, change directory)
    if (typeof mutated.Image === 'string') {
      const pathChanged = changeToolPath(mutated.Image);
      if (pathChanged !== mutated.Image) {
        mutated.Image = pathChanged;
        mutationsApplied.add('change-path');
        anyMutation = true;
      }
    }

    // 4. Vary PowerShell argument format in CommandLine
    if (typeof mutated.CommandLine === 'string') {
      const varied = varyArgumentFormat(mutated.CommandLine);
      if (varied !== mutated.CommandLine) {
        mutated.CommandLine = varied;
        mutationsApplied.add('vary-argument-format');
        anyMutation = true;
      }
    }

    // 5. Rename tool references in CommandLine (but not system binaries)
    if (typeof mutated.CommandLine === 'string') {
      const renamed = renameToolInCommandLine(mutated.CommandLine);
      if (renamed !== mutated.CommandLine) {
        mutated.CommandLine = renamed;
        mutationsApplied.add('rename-tool-in-commandline');
        anyMutation = true;
      }
    }

    // 6. Environment variable substitution in CommandLine paths
    if (typeof mutated.CommandLine === 'string') {
      const envSubbed = applyEnvSubstitution(mutated.CommandLine);
      if (envSubbed !== mutated.CommandLine) {
        mutated.CommandLine = envSubbed;
        mutationsApplied.add('env-var-substitution');
        anyMutation = true;
      }
    }

    // 7. Caret insertion in CommandLine keywords (cmd.exe evasion)
    if (typeof mutated.CommandLine === 'string') {
      const careted = applyCaretInsertion(mutated.CommandLine);
      if (careted !== mutated.CommandLine) {
        mutated.CommandLine = careted;
        mutationsApplied.add('caret-insertion');
        anyMutation = true;
      }
    }

    // 8. Case randomization in CommandLine (~20% of chars)
    if (typeof mutated.CommandLine === 'string') {
      const caseRandom = applyCaseRandomization(mutated.CommandLine);
      if (caseRandom !== mutated.CommandLine) {
        mutated.CommandLine = caseRandom;
        mutationsApplied.add('case-randomization');
        anyMutation = true;
      }
    }

    // Only include if at least one mutation was applied
    if (anyMutation) {
      mutatedLogs.push(mutated);
    } else {
      // No mutation possible — include original to keep log count stable
      mutatedLogs.push(mutated);
    }
  }

  return {
    mutatedLogs,
    mutationsApplied: [...mutationsApplied],
  };
}

/**
 * Extract the filename from a Windows path.
 */
function extractFilename(imagePath: string): string {
  const parts = imagePath.split('\\');
  return parts[parts.length - 1].toLowerCase();
}

/**
 * Rename an executable if it's a tool (not a system binary).
 */
function renameExecutable(imagePath: string): string {
  const filename = extractFilename(imagePath);
  if (SYSTEM_BINARIES.has(filename)) return imagePath;

  // It's a tool binary — rename it
  const dir = imagePath.substring(0, imagePath.lastIndexOf('\\') + 1);
  const newName = EVASION_TOOL_NAMES[
    Math.abs(hashString(imagePath)) % EVASION_TOOL_NAMES.length
  ];
  return dir + newName;
}

/**
 * Change the directory path of a tool binary (not system binaries).
 */
function changeToolPath(imagePath: string): string {
  const filename = extractFilename(imagePath);
  if (SYSTEM_BINARIES.has(filename)) return imagePath;

  // Replace the directory with an evasion path
  const newDir = EVASION_PATHS[
    Math.abs(hashString(imagePath)) % EVASION_PATHS.length
  ];
  return newDir + filename;
}

/**
 * Vary PowerShell argument format abbreviations.
 */
function varyArgumentFormat(cmdLine: string): string {
  let result = cmdLine;
  for (const [canonical, variants] of PS_ARG_VARIANTS) {
    const lowerCmd = result.toLowerCase();
    const idx = lowerCmd.indexOf(canonical);
    if (idx >= 0) {
      const variant = variants[Math.abs(hashString(cmdLine)) % variants.length];
      result = result.substring(0, idx) + variant + result.substring(idx + canonical.length);
    }
  }
  return result;
}

/**
 * Rename tool name references in CommandLine (not system binaries).
 */
function renameToolInCommandLine(cmdLine: string): string {
  // Find .exe references that are tool names
  const exePattern = /([a-zA-Z0-9_-]+)\.exe/gi;
  return cmdLine.replace(exePattern, (match, name) => {
    const lower = (name + '.exe').toLowerCase();
    if (SYSTEM_BINARIES.has(lower)) return match;
    // Replace with evasion name
    const newName = EVASION_TOOL_NAMES[
      Math.abs(hashString(name)) % EVASION_TOOL_NAMES.length
    ];
    return newName;
  });
}

/**
 * Replace well-known path prefixes in CommandLine with environment variable
 * equivalents. Does NOT touch the Image field.
 */
function applyEnvSubstitution(cmdLine: string): string {
  let result = cmdLine;
  for (const [literal, envVar] of ENV_SUBSTITUTIONS) {
    // Case-insensitive replacement in CommandLine text
    const idx = result.toLowerCase().indexOf(literal.toLowerCase());
    if (idx >= 0) {
      result = result.substring(0, idx) + envVar + result.substring(idx + literal.length);
      return result; // Apply one substitution per log for clarity
    }
  }
  return result;
}

/**
 * Insert carets (^) into known keywords in CommandLine to evade string-match
 * detection. This is a common cmd.exe evasion technique.
 */
function applyCaretInsertion(cmdLine: string): string {
  let result = cmdLine;
  for (const keyword of CARET_KEYWORDS) {
    const lowerResult = result.toLowerCase();
    const idx = lowerResult.indexOf(keyword);
    if (idx >= 0) {
      const original = result.substring(idx, idx + keyword.length);
      // Insert caret at deterministic positions (after 2nd and 5th char)
      let careted = '';
      for (let i = 0; i < original.length; i++) {
        careted += original[i];
        if (i === 1 || i === 4) {
          careted += '^';
        }
      }
      result = result.substring(0, idx) + careted + result.substring(idx + keyword.length);
      return result; // Apply one caret insertion per log
    }
  }
  return result;
}

/**
 * Deterministically toggle case of ~20% of alphabetic characters in CommandLine.
 * Tests whether rules use case-insensitive matching properly.
 * Preserves system binary names (e.g. rundll32.exe) to avoid breaking other mutations.
 */
function applyCaseRandomization(cmdLine: string): string {
  // Find positions of system binary names to protect them
  const protectedRanges: [number, number][] = [];
  const lowerCmd = cmdLine.toLowerCase();
  for (const binary of SYSTEM_BINARIES) {
    let searchFrom = 0;
    while (true) {
      const idx = lowerCmd.indexOf(binary, searchFrom);
      if (idx < 0) break;
      protectedRanges.push([idx, idx + binary.length]);
      searchFrom = idx + binary.length;
    }
  }

  const h = Math.abs(hashString(cmdLine));
  const chars = cmdLine.split('');
  let changed = false;
  for (let i = 0; i < chars.length; i++) {
    // Skip characters inside protected system binary names
    if (protectedRanges.some(([start, end]) => i >= start && i < end)) continue;

    const ch = chars[i];
    if (/[a-zA-Z]/.test(ch)) {
      // Toggle ~20% of alpha chars using hash-derived determinism
      if ((h + i * 7) % 5 === 0) {
        chars[i] = ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase();
        changed = true;
      }
    }
  }
  return changed ? chars.join('') : cmdLine;
}

/**
 * Simple deterministic hash for consistent mutations.
 */
function hashString(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return hash;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeToStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((v) => String(v));
  }
  if (value === null || value === undefined) return [];
  return [String(value)];
}
