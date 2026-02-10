/**
 * Suricata rule validation.
 *
 * Validates individual rules (structured and raw text) as well as rule sets
 * (e.g. duplicate SID detection). Checks cover:
 *   - Action, protocol, direction validity
 *   - Source/destination IP and port format
 *   - Required options (msg, sid, rev)
 *   - Raw text structural format
 *   - Content keyword escaping
 *   - Semicolon-terminated options
 */

import type { SuricataRule, ValidationResult } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Valid Suricata rule actions. */
const VALID_ACTIONS = new Set([
  'alert',
  'pass',
  'drop',
  'reject',
  'rejectsrc',
  'rejectdst',
  'rejectboth',
]);

/** Valid Suricata protocol keywords. */
const VALID_PROTOCOLS = new Set([
  'tcp',
  'udp',
  'icmp',
  'ip',
  'http',
  'dns',
  'tls',
  'ssh',
  'ftp',
  'smtp',
  'http2',
  'pkthdr',
  'nfs',
  'smb',
  'dcerpc',
  'dhcp',
  'krb5',
  'snmp',
  'sip',
  'rfb',
  'mqtt',
  'pgsql',
]);

/** Valid Suricata variable names for IP addresses. */
const VALID_IP_VARIABLES = new Set([
  '$HOME_NET',
  '$EXTERNAL_NET',
  '$DNS_SERVERS',
  '$SMTP_SERVERS',
  '$HTTP_SERVERS',
  '$SQL_SERVERS',
  '$TELNET_SERVERS',
  'any',
]);

/** Valid Suricata variable names for ports. */
const VALID_PORT_VARIABLES = new Set([
  '$HTTP_PORTS',
  '$SHELLCODE_PORTS',
  '$ORACLE_PORTS',
  '$SSH_PORTS',
  '$DNP3_PORTS',
  '$MODBUS_PORTS',
  '$FTP_PORTS',
  '$GENEVE_PORTS',
  '$VXLAN_PORTS',
  '$TEREDO_PORTS',
  'any',
]);

/** Valid direction operators. */
const VALID_DIRECTIONS = new Set(['->', '<>']);

/** SID range used by DetectForge custom rules. */
const SID_MIN = 1;
const SID_MAX = 9_999_999;

// ---------------------------------------------------------------------------
// IP and port validation helpers
// ---------------------------------------------------------------------------

/** Return true if the string is a valid IPv4 address. */
function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

/** Return true if the string is a plausible IPv6 address (simplified check). */
function isValidIpv6(ip: string): boolean {
  // Quick heuristic: at least two colons, hex groups
  return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':');
}

/** Return true if the string is valid CIDR notation (v4 or v6). */
function isValidCidr(value: string): boolean {
  const slashIdx = value.indexOf('/');
  if (slashIdx === -1) return false;
  const ip = value.substring(0, slashIdx);
  const prefix = Number(value.substring(slashIdx + 1));
  if (!Number.isInteger(prefix) || prefix < 0) return false;
  if (isValidIpv4(ip)) return prefix <= 32;
  if (isValidIpv6(ip)) return prefix <= 128;
  return false;
}

/**
 * Validate a Suricata IP field.
 *
 * Accepts:
 * - Suricata variables ($HOME_NET, etc.)
 * - 'any'
 * - IPv4 or IPv6 addresses
 * - CIDR notation
 * - Negation (!)
 * - Groups ([addr1,addr2,...])
 */
function isValidIpField(value: string): boolean {
  const trimmed = value.trim();

  // Negation prefix
  const inner = trimmed.startsWith('!') ? trimmed.substring(1) : trimmed;

  // Group notation [addr1,addr2]
  if (inner.startsWith('[') && inner.endsWith(']')) {
    const members = inner.substring(1, inner.length - 1).split(',');
    return members.every(m => isValidIpField(m.trim()));
  }

  if (VALID_IP_VARIABLES.has(inner)) return true;
  if (inner.startsWith('$')) return true; // allow custom variables
  if (isValidIpv4(inner)) return true;
  if (isValidIpv6(inner)) return true;
  if (isValidCidr(inner)) return true;

  return false;
}

/**
 * Validate a Suricata port field.
 *
 * Accepts:
 * - 'any'
 * - Suricata port variables ($HTTP_PORTS, etc.)
 * - Single port number (0-65535)
 * - Port range (e.g. 1024:65535)
 * - Negation (!)
 * - Groups ([port1,port2,...])
 */
function isValidPortField(value: string): boolean {
  const trimmed = value.trim();

  const inner = trimmed.startsWith('!') ? trimmed.substring(1) : trimmed;

  if (inner.startsWith('[') && inner.endsWith(']')) {
    const members = inner.substring(1, inner.length - 1).split(',');
    return members.every(m => isValidPortField(m.trim()));
  }

  if (VALID_PORT_VARIABLES.has(inner)) return true;
  if (inner.startsWith('$')) return true; // custom variable

  // Single port
  const portNum = Number(inner);
  if (Number.isInteger(portNum) && portNum >= 0 && portNum <= 65535) return true;

  // Port range 1024:65535
  if (inner.includes(':')) {
    const parts = inner.split(':');
    if (parts.length !== 2) return false;
    const lo = parts[0] === '' ? 0 : Number(parts[0]);
    const hi = parts[1] === '' ? 65535 : Number(parts[1]);
    return (
      Number.isInteger(lo) &&
      Number.isInteger(hi) &&
      lo >= 0 &&
      hi <= 65535 &&
      lo <= hi
    );
  }

  return false;
}

// ---------------------------------------------------------------------------
// Single-rule validator (structured)
// ---------------------------------------------------------------------------

/**
 * Validate a structured SuricataRule object.
 *
 * @param rule - The SuricataRule to validate.
 * @returns A ValidationResult with errors and warnings.
 */
export function validateSuricataRule(rule: SuricataRule): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // --- Action ---
  if (!VALID_ACTIONS.has(rule.action)) {
    errors.push(`Invalid action "${rule.action}". Expected one of: ${[...VALID_ACTIONS].join(', ')}`);
  }

  // --- Protocol ---
  if (!VALID_PROTOCOLS.has(rule.protocol)) {
    errors.push(
      `Invalid protocol "${rule.protocol}". Expected one of: ${[...VALID_PROTOCOLS].join(', ')}`,
    );
  }

  // --- Source IP ---
  if (!isValidIpField(rule.sourceIp)) {
    errors.push(`Invalid source IP "${rule.sourceIp}".`);
  }

  // --- Source Port ---
  if (!isValidPortField(rule.sourcePort)) {
    errors.push(`Invalid source port "${rule.sourcePort}".`);
  }

  // --- Direction ---
  if (!VALID_DIRECTIONS.has(rule.direction)) {
    errors.push(`Invalid direction "${rule.direction}". Expected -> or <>.`);
  }

  // --- Dest IP ---
  if (!isValidIpField(rule.destIp)) {
    errors.push(`Invalid destination IP "${rule.destIp}".`);
  }

  // --- Dest Port ---
  if (!isValidPortField(rule.destPort)) {
    errors.push(`Invalid destination port "${rule.destPort}".`);
  }

  // --- Options: msg ---
  const hasMsg = rule.options.some(o => o.keyword === 'msg');
  if (!hasMsg) {
    errors.push('Rule is missing required "msg" option.');
  }

  // --- SID ---
  if (!Number.isInteger(rule.sid) || rule.sid < SID_MIN || rule.sid > SID_MAX) {
    errors.push(`SID must be an integer between ${SID_MIN} and ${SID_MAX}. Got: ${rule.sid}`);
  }

  // --- rev ---
  if (!Number.isInteger(rule.rev) || rule.rev < 1) {
    errors.push(`rev must be a positive integer. Got: ${rule.rev}`);
  }

  // --- Options: sid in options should match ---
  const sidOption = rule.options.find(o => o.keyword === 'sid');
  if (sidOption && sidOption.value !== undefined) {
    const optionSid = Number(sidOption.value);
    if (optionSid !== rule.sid) {
      warnings.push(
        `SID in options (${sidOption.value}) does not match rule.sid (${rule.sid}).`,
      );
    }
  }

  // --- Options: rev in options should match ---
  const revOption = rule.options.find(o => o.keyword === 'rev');
  if (revOption && revOption.value !== undefined) {
    const optionRev = Number(revOption.value);
    if (optionRev !== rule.rev) {
      warnings.push(
        `rev in options (${revOption.value}) does not match rule.rev (${rule.rev}).`,
      );
    }
  }

  // --- Content escaping check ---
  for (const opt of rule.options) {
    if (opt.keyword === 'content' && opt.value !== undefined) {
      // Content value should be quoted
      const val = opt.value.trim();
      if (!val.startsWith('"') || !val.endsWith('"')) {
        warnings.push(`Content value should be enclosed in double quotes: ${val}`);
      }
    }
  }

  // --- Raw text format check ---
  if (rule.raw) {
    const rawResult = validateSuricataRaw(rule.raw);
    if (!rawResult.syntaxValid) {
      for (const err of rawResult.errors) {
        warnings.push(`Raw text issue: ${err}`);
      }
    }
  }

  const syntaxValid = errors.length === 0;
  const schemaValid = syntaxValid;

  return {
    valid: syntaxValid,
    syntaxValid,
    schemaValid,
    errors,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Raw text validator
// ---------------------------------------------------------------------------

/**
 * Validate a raw Suricata rule string.
 *
 * Expected format:
 *   action protocol src_ip src_port direction dest_ip dest_port (options;)
 *
 * @param raw - Raw rule text string.
 * @returns A ValidationResult.
 */
export function validateSuricataRaw(raw: string): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const trimmed = raw.trim();

  // Must have an options block in parentheses
  const parenOpen = trimmed.indexOf('(');
  const parenClose = trimmed.lastIndexOf(')');

  if (parenOpen === -1 || parenClose === -1 || parenClose <= parenOpen) {
    errors.push('Rule must contain options block enclosed in parentheses: (options;)');
    return { valid: false, syntaxValid: false, schemaValid: false, errors, warnings };
  }

  // Parse header: everything before the '('
  const header = trimmed.substring(0, parenOpen).trim();
  const headerParts = header.split(/\s+/);

  if (headerParts.length < 7) {
    errors.push(
      `Rule header must have 7 parts (action protocol src_ip src_port direction dest_ip dest_port). Found ${headerParts.length}.`,
    );
  } else {
    const [action, protocol, srcIp, srcPort, direction, destIp, destPort] = headerParts;

    if (!VALID_ACTIONS.has(action)) {
      errors.push(`Invalid action "${action}" in raw rule.`);
    }
    if (!VALID_PROTOCOLS.has(protocol)) {
      errors.push(`Invalid protocol "${protocol}" in raw rule.`);
    }
    if (!isValidIpField(srcIp)) {
      errors.push(`Invalid source IP "${srcIp}" in raw rule.`);
    }
    if (!isValidPortField(srcPort)) {
      errors.push(`Invalid source port "${srcPort}" in raw rule.`);
    }
    if (!VALID_DIRECTIONS.has(direction)) {
      errors.push(`Invalid direction "${direction}" in raw rule. Expected -> or <>.`);
    }
    if (!isValidIpField(destIp)) {
      errors.push(`Invalid destination IP "${destIp}" in raw rule.`);
    }
    if (!isValidPortField(destPort)) {
      errors.push(`Invalid destination port "${destPort}" in raw rule.`);
    }
  }

  // Parse options block
  const optionsBlock = trimmed.substring(parenOpen + 1, parenClose).trim();

  // Check for msg
  if (!optionsBlock.includes('msg:')) {
    errors.push('Raw rule is missing "msg" option.');
  }

  // Check for sid
  const sidMatch = optionsBlock.match(/sid\s*:\s*(\d+)/);
  if (!sidMatch) {
    errors.push('Raw rule is missing "sid" option.');
  } else {
    const sid = Number(sidMatch[1]);
    if (sid < SID_MIN || sid > SID_MAX) {
      errors.push(`SID ${sid} is out of valid range (${SID_MIN}-${SID_MAX}).`);
    }
  }

  // Check for rev
  const revMatch = optionsBlock.match(/rev\s*:\s*(\d+)/);
  if (!revMatch) {
    errors.push('Raw rule is missing "rev" option.');
  } else {
    const rev = Number(revMatch[1]);
    if (rev < 1) {
      errors.push(`rev must be a positive integer. Got: ${rev}`);
    }
  }

  // Options should end with a semicolon (the final option before ')')
  if (optionsBlock.length > 0 && !optionsBlock.trimEnd().endsWith(';')) {
    warnings.push('Options block should end with a semicolon before the closing parenthesis.');
  }

  // Check individual options are semicolon-terminated
  // Split by ';' and verify each non-empty segment looks reasonable
  const segments = optionsBlock.split(';').map(s => s.trim()).filter(s => s.length > 0);
  for (const segment of segments) {
    // content keywords should have quoted values
    if (segment.startsWith('content:')) {
      const contentVal = segment.substring('content:'.length).trim();
      if (!contentVal.startsWith('"') || !contentVal.endsWith('"')) {
        warnings.push(`Content value should be enclosed in double quotes: ${contentVal}`);
      }
    }
    // msg keyword should have quoted value
    if (segment.startsWith('msg:')) {
      const msgVal = segment.substring('msg:'.length).trim();
      if (!msgVal.startsWith('"') || !msgVal.endsWith('"')) {
        warnings.push(`msg value should be enclosed in double quotes: ${msgVal}`);
      }
    }
  }

  const syntaxValid = errors.length === 0;

  return {
    valid: syntaxValid,
    syntaxValid,
    schemaValid: syntaxValid,
    errors,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Rule set (batch) validator
// ---------------------------------------------------------------------------

/**
 * Validate an array of Suricata rules, including cross-rule checks
 * such as duplicate SID detection.
 *
 * @param rules - Array of SuricataRule objects to validate.
 * @returns Object with overall validity flag and aggregated error messages.
 */
export function validateSuricataRuleSet(
  rules: SuricataRule[],
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Validate each rule individually
  for (let i = 0; i < rules.length; i++) {
    const result = validateSuricataRule(rules[i]);
    for (const err of result.errors) {
      errors.push(`Rule ${i + 1} (SID ${rules[i].sid}): ${err}`);
    }
  }

  // Check for duplicate SIDs
  const sidCounts = new Map<number, number[]>();
  for (let i = 0; i < rules.length; i++) {
    const sid = rules[i].sid;
    const indices = sidCounts.get(sid);
    if (indices) {
      indices.push(i + 1);
    } else {
      sidCounts.set(sid, [i + 1]);
    }
  }

  for (const [sid, indices] of sidCounts) {
    if (indices.length > 1) {
      errors.push(
        `Duplicate SID ${sid} found in rules: ${indices.join(', ')}`,
      );
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
