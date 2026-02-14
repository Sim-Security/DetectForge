/**
 * Sigma rule evaluation engine.
 *
 * Implements Sigma detection logic in TypeScript so rules can be tested
 * against log entries WITHOUT needing a SIEM.  Supports field matching,
 * wildcards, modifiers, named selections, and condition parsing
 * (AND / OR / NOT / parentheses / "1 of ..." / "all of ...").
 */

import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface LogEntry {
  [key: string]: string | number | boolean | null | undefined;
}

export interface SigmaTestResult {
  ruleId: string;
  ruleTitle: string;
  matched: boolean;
  matchedSelections: string[];
  failedSelections: string[];
  evaluationDetails: string;
  aggregationSkipped?: boolean;
}

export interface SigmaTestSuiteResult {
  ruleId: string;
  ruleTitle: string;
  truePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  falsePositives: number;
  tpRate: number;
  fpRate: number;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Test a single Sigma rule against a single log entry.
 */
export function evaluateSigmaRule(
  rule: SigmaRule,
  log: LogEntry,
): SigmaTestResult {
  const detection = rule.detection;
  const condition = detection.condition;

  // Identify all named selections (everything in detection except "condition")
  const selectionNames = Object.keys(detection).filter(
    (k) => k !== 'condition',
  );

  // Evaluate every selection against the log
  const selectionResults = new Map<string, boolean>();
  for (const name of selectionNames) {
    const selectionDef = detection[name];
    const matches = evaluateSelection(selectionDef, log);
    selectionResults.set(name, matches);
  }

  const matchedSelections: string[] = [];
  const failedSelections: string[] = [];
  for (const [name, result] of selectionResults) {
    if (result) {
      matchedSelections.push(name);
    } else {
      failedSelections.push(name);
    }
  }

  // Parse and evaluate the condition expression
  const matched = evaluateCondition(condition, selectionResults);

  // Detect if an aggregation pipe was present
  const aggregationSkipped = typeof condition === 'string' && condition.includes('|');

  const details = buildEvaluationDetails(
    selectionResults,
    condition,
    matched,
  );

  return {
    ruleId: rule.id,
    ruleTitle: rule.title,
    matched,
    matchedSelections,
    failedSelections,
    evaluationDetails: details,
    ...(aggregationSkipped ? { aggregationSkipped: true } : {}),
  };
}

/**
 * Test a rule against attack and benign log sets.
 */
export function evaluateSigmaRuleSuite(
  rule: SigmaRule,
  attackLogs: LogEntry[],
  benignLogs: LogEntry[],
): SigmaTestSuiteResult {
  let truePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;
  let falsePositives = 0;

  for (const log of attackLogs) {
    const result = evaluateSigmaRule(rule, log);
    if (result.matched) {
      truePositives++;
    } else {
      falseNegatives++;
    }
  }

  for (const log of benignLogs) {
    const result = evaluateSigmaRule(rule, log);
    if (result.matched) {
      falsePositives++;
    } else {
      trueNegatives++;
    }
  }

  const tpRate =
    truePositives + falseNegatives === 0
      ? 0
      : truePositives / (truePositives + falseNegatives);

  const fpRate =
    falsePositives + trueNegatives === 0
      ? 0
      : falsePositives / (falsePositives + trueNegatives);

  return {
    ruleId: rule.id,
    ruleTitle: rule.title,
    truePositives,
    falseNegatives,
    trueNegatives,
    falsePositives,
    tpRate,
    fpRate,
  };
}

// ---------------------------------------------------------------------------
// Selection Evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate a single selection block against a log entry.
 *
 * A selection is a mapping of field names (possibly with modifiers) to
 * expected values.  All field conditions within a selection use AND logic.
 * When a field maps to an array of values those values use OR logic.
 */
function evaluateSelection(selectionDef: unknown, log: LogEntry): boolean {
  if (typeof selectionDef !== 'object' || selectionDef === null) {
    return false;
  }

  // Handle list-of-maps (Sigma "selection as list"): each map entry in the
  // array is an OR-alternative.
  if (Array.isArray(selectionDef)) {
    return selectionDef.some((item) => evaluateSelection(item, log));
  }

  const fields = selectionDef as Record<string, unknown>;
  // AND across all field conditions
  for (const [rawField, expectedValues] of Object.entries(fields)) {
    const { fieldName, modifiers } = parseFieldKey(rawField);
    const logValue = getLogField(log, fieldName);

    if (!matchFieldValue(logValue, expectedValues, modifiers)) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Field & Value Matching
// ---------------------------------------------------------------------------

interface ParsedFieldKey {
  fieldName: string;
  modifiers: string[];
}

/**
 * Parse a Sigma field key which may contain pipe-delimited modifiers.
 *
 * Examples:
 *   "CommandLine|contains"     -> { fieldName: "CommandLine", modifiers: ["contains"] }
 *   "TargetFilename|endswith"  -> { fieldName: "TargetFilename", modifiers: ["endswith"] }
 */
function parseFieldKey(key: string): ParsedFieldKey {
  const parts = key.split('|');
  return {
    fieldName: parts[0],
    modifiers: parts.slice(1),
  };
}

/**
 * Case-insensitive field lookup in log entries.
 */
function getLogField(
  log: LogEntry,
  fieldName: string,
): string | number | boolean | null | undefined {
  // Try exact match first
  if (fieldName in log) {
    return log[fieldName];
  }
  // Case-insensitive fallback
  const lowerField = fieldName.toLowerCase();
  for (const key of Object.keys(log)) {
    if (key.toLowerCase() === lowerField) {
      return log[key];
    }
  }
  return undefined;
}

/**
 * Check whether a log field value matches the expected Sigma detection values.
 *
 * @param logValue       - The value from the log entry.
 * @param expectedValues - The expected value(s) from the Sigma rule.
 * @param modifiers      - Any Sigma modifiers applied to the field.
 */
function matchFieldValue(
  logValue: string | number | boolean | null | undefined,
  expectedValues: unknown,
  modifiers: string[],
): boolean {
  // Normalise expected values into an array (OR logic)
  const valueList = normalizeToArray(expectedValues);

  if (valueList.length === 0) {
    return false;
  }

  // "all" modifier changes OR to AND for multi-value matching
  const useAllLogic = modifiers.includes('all');

  if (useAllLogic) {
    return valueList.every((expected) =>
      matchSingleValue(logValue, expected, modifiers),
    );
  }

  // Default: any value in the list matches -> true (OR)
  return valueList.some((expected) =>
    matchSingleValue(logValue, expected, modifiers),
  );
}

/**
 * Match a single expected value against a log value, applying modifiers.
 */
function matchSingleValue(
  logValue: string | number | boolean | null | undefined,
  expected: unknown,
  modifiers: string[],
): boolean {
  if (logValue === null || logValue === undefined) {
    return expected === null || expected === undefined;
  }

  const logStr = String(logValue);
  const expectedStr = String(expected);

  // Check for "cidr" modifier (IP range matching)
  if (modifiers.includes('cidr')) {
    return matchCidr(logStr, expectedStr);
  }

  // Check for "re" modifier (regex)
  if (modifiers.includes('re')) {
    try {
      const re = new RegExp(expectedStr, 'i');
      return re.test(logStr);
    } catch {
      return false;
    }
  }

  // Check for "base64" modifier — compare against base64-encoded log value
  if (modifiers.includes('base64')) {
    try {
      const decoded = atob(logStr);
      return matchWithModifiers(decoded, expectedStr, modifiers);
    } catch {
      return false;
    }
  }

  return matchWithModifiers(logStr, expectedStr, modifiers);
}

/**
 * Apply contains / startswith / endswith modifiers, or fall back to
 * wildcard-aware comparison.
 */
function matchWithModifiers(
  logStr: string,
  expectedStr: string,
  modifiers: string[],
): boolean {
  const logLower = logStr.toLowerCase();
  const expectedLower = expectedStr.toLowerCase();

  if (modifiers.includes('contains')) {
    return logLower.includes(expectedLower);
  }
  if (modifiers.includes('startswith')) {
    return logLower.startsWith(expectedLower);
  }
  if (modifiers.includes('endswith')) {
    return logLower.endsWith(expectedLower);
  }

  // Default: wildcard-aware, case-insensitive comparison
  return wildcardMatch(logLower, expectedLower);
}

// ---------------------------------------------------------------------------
// Wildcard Matching
// ---------------------------------------------------------------------------

/**
 * Match a string against a pattern that may contain `*` (any chars) and
 * `?` (single char) wildcards.  Comparison is performed on already
 * lowercased inputs.
 */
function wildcardMatch(value: string, pattern: string): boolean {
  // Fast paths
  if (pattern === '*') return true;
  if (!pattern.includes('*') && !pattern.includes('?')) {
    return value === pattern;
  }

  // Convert wildcard pattern to regex
  const regexStr = wildcardToRegex(pattern);
  const re = new RegExp(`^${regexStr}$`, 'i');
  return re.test(value);
}

/**
 * Convert a Sigma wildcard pattern to a regex source string.
 *
 * `*` -> `.*`
 * `?` -> `.`
 * All other regex metacharacters are escaped.
 */
function wildcardToRegex(pattern: string): string {
  let result = '';
  for (const ch of pattern) {
    if (ch === '*') {
      result += '.*';
    } else if (ch === '?') {
      result += '.';
    } else if ('.+^${}()|[]\\'.includes(ch)) {
      result += `\\${ch}`;
    } else {
      result += ch;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// CIDR Matching
// ---------------------------------------------------------------------------

/**
 * Match an IP address against a CIDR range (e.g. "10.0.0.0/24").
 */
function matchCidr(ip: string, cidr: string): boolean {
  const [subnet, prefixStr] = cidr.split('/');
  if (!prefixStr) return ip === cidr;
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;
  const ipNum = ipToNumber(ip);
  const subnetNum = ipToNumber(subnet);
  if (ipNum === null || subnetNum === null) return false;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (subnetNum & mask);
}

/**
 * Convert an IPv4 address string to a 32-bit unsigned integer.
 */
function ipToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const p of parts) {
    const octet = parseInt(p, 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return null;
    num = (num << 8) | octet;
  }
  return num >>> 0;
}

// ---------------------------------------------------------------------------
// Condition Parsing & Evaluation
// ---------------------------------------------------------------------------

/**
 * Token types for the condition mini-language.
 */
type TokenType =
  | 'AND'
  | 'OR'
  | 'NOT'
  | 'LPAREN'
  | 'RPAREN'
  | 'ONE_OF'
  | 'ALL_OF'
  | 'IDENTIFIER'
  | 'PATTERN'
  | 'THEM';

interface Token {
  type: TokenType;
  value: string;
}

/**
 * Tokenize a Sigma condition string.
 */
function tokenize(condition: string): Token[] {
  const tokens: Token[] = [];

  // Pre-process: insert spaces around parentheses so they become
  // standalone tokens, then split on whitespace.
  const spaced = condition
    .replace(/\(/g, ' ( ')
    .replace(/\)/g, ' ) ');
  const words = spaced.trim().split(/\s+/).filter((w) => w.length > 0);

  let i = 0;
  while (i < words.length) {
    const word = words[i];
    const lower = word.toLowerCase();

    // Parentheses
    if (word === '(') {
      tokens.push({ type: 'LPAREN', value: '(' });
      i++;
      continue;
    }
    if (word === ')') {
      tokens.push({ type: 'RPAREN', value: ')' });
      i++;
      continue;
    }

    // Boolean operators
    if (lower === 'and') {
      tokens.push({ type: 'AND', value: 'and' });
      i++;
      continue;
    }
    if (lower === 'or') {
      tokens.push({ type: 'OR', value: 'or' });
      i++;
      continue;
    }
    if (lower === 'not') {
      tokens.push({ type: 'NOT', value: 'not' });
      i++;
      continue;
    }

    // "1 of ...", "all of ..."
    if ((lower === '1' || lower === 'all') && i + 1 < words.length) {
      const next = words[i + 1]?.toLowerCase();
      if (next === 'of') {
        const quantifier = lower === 'all' ? 'ALL_OF' : 'ONE_OF';
        // Consume "of" and the target
        i += 2;
        if (i < words.length) {
          const target = words[i].toLowerCase();
          if (target === 'them') {
            tokens.push({
              type: quantifier as TokenType,
              value: 'them',
            });
          } else {
            tokens.push({
              type: quantifier as TokenType,
              value: words[i],
            });
          }
        }
        i++;
        continue;
      }
    }

    // Wildcard pattern (e.g. "selection_*")
    if (word.includes('*')) {
      tokens.push({ type: 'PATTERN', value: word });
      i++;
      continue;
    }

    // Plain identifier
    tokens.push({ type: 'IDENTIFIER', value: word });
    i++;
  }

  return tokens;
}

/**
 * Evaluate a Sigma condition string against pre-computed selection results.
 *
 * Supports: AND, OR, NOT, parentheses, "1 of ...", "all of ...", named
 * identifiers, and wildcard patterns.
 */
function evaluateCondition(
  condition: string,
  selectionResults: Map<string, boolean>,
): boolean {
  // Detect aggregation pipe — evaluate only the boolean selection part
  const pipeIdx = condition.indexOf('|');
  const booleanPart = pipeIdx >= 0 ? condition.substring(0, pipeIdx).trim() : condition;

  const tokens = tokenize(booleanPart);
  let pos = 0;

  function peek(): Token | undefined {
    return tokens[pos];
  }

  function consume(): Token {
    return tokens[pos++];
  }

  /**
   * Parse OR expressions (lowest precedence).
   */
  function parseOr(): boolean {
    let result = parseAnd();
    while (peek()?.type === 'OR') {
      consume(); // eat 'or'
      const right = parseAnd();
      result = result || right;
    }
    return result;
  }

  /**
   * Parse AND expressions.
   */
  function parseAnd(): boolean {
    let result = parseNot();
    while (peek()?.type === 'AND') {
      consume(); // eat 'and'
      const right = parseNot();
      result = result && right;
    }
    return result;
  }

  /**
   * Parse NOT expressions.
   */
  function parseNot(): boolean {
    if (peek()?.type === 'NOT') {
      consume(); // eat 'not'
      return !parseNot();
    }
    return parsePrimary();
  }

  /**
   * Parse primary expressions: identifiers, quantified expressions,
   * patterns, and parenthesised sub-expressions.
   */
  function parsePrimary(): boolean {
    const token = peek();
    if (!token) return false;

    // Parenthesised expression
    if (token.type === 'LPAREN') {
      consume(); // eat '('
      const result = parseOr();
      if (peek()?.type === 'RPAREN') {
        consume(); // eat ')'
      }
      return result;
    }

    // "1 of ..." / "all of ..."
    if (token.type === 'ONE_OF' || token.type === 'ALL_OF') {
      consume();
      const target = token.value;
      const matchingKeys = resolveTarget(target, selectionResults);
      const values = matchingKeys.map(
        (k) => selectionResults.get(k) ?? false,
      );

      if (token.type === 'ONE_OF') {
        return values.some(Boolean);
      }
      return values.length > 0 && values.every(Boolean);
    }

    // Plain identifier
    if (token.type === 'IDENTIFIER') {
      consume();
      return selectionResults.get(token.value) ?? false;
    }

    // Wildcard pattern used as a bare identifier (rare but valid)
    if (token.type === 'PATTERN') {
      consume();
      const matchingKeys = resolveTarget(token.value, selectionResults);
      // Bare pattern without quantifier acts like "1 of pattern"
      return matchingKeys.some((k) => selectionResults.get(k) ?? false);
    }

    // Unrecognised token — skip and return false
    consume();
    return false;
  }

  return parseOr();
}

/**
 * Resolve a target pattern to matching selection keys.
 *
 * - `"them"` matches all selection keys.
 * - A wildcard like `"selection_*"` matches keys starting with "selection_".
 * - A plain name returns that single key if it exists.
 */
function resolveTarget(
  target: string,
  selectionResults: Map<string, boolean>,
): string[] {
  if (target === 'them') {
    return [...selectionResults.keys()];
  }

  if (target.includes('*')) {
    const prefix = target.replace(/\*/g, '');
    return [...selectionResults.keys()].filter((k) => k.startsWith(prefix));
  }

  if (selectionResults.has(target)) {
    return [target];
  }

  return [];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Normalise a Sigma detection value into an array.
 */
function normalizeToArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (value === null || value === undefined) return [];
  return [value];
}

/**
 * Build a human-readable explanation of the evaluation.
 */
function buildEvaluationDetails(
  selectionResults: Map<string, boolean>,
  condition: string,
  matched: boolean,
): string {
  const parts: string[] = [];

  parts.push(`Condition: "${condition}"`);
  parts.push(`Overall result: ${matched ? 'MATCHED' : 'NO MATCH'}`);
  parts.push('');
  parts.push('Selection results:');

  for (const [name, result] of selectionResults) {
    parts.push(`  ${name}: ${result ? 'MATCHED' : 'no match'}`);
  }

  return parts.join('\n');
}
