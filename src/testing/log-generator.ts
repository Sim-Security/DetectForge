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
// Helpers
// ---------------------------------------------------------------------------

function normalizeToStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((v) => String(v));
  }
  if (value === null || value === undefined) return [];
  return [String(value)];
}
