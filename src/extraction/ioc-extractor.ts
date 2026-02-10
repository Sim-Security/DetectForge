/**
 * IOC Extractor — regex-based + AI-enhanced indicator extraction.
 *
 * Extracts indicators of compromise from threat report text using:
 * 1. Regex patterns for all IOC types (including defanged variants)
 * 2. Optional AI disambiguation to filter benign references
 *
 * Supported IOC types:
 *   IPv4, IPv6, domains, URLs, emails, MD5, SHA1, SHA256,
 *   Windows/Linux file paths, registry keys, CVE IDs
 */

import { refang } from '../utils/defang.js';
import { isValidIPv4, isPrivateIP, isValidDomain, isValidEmail } from '../utils/network.js';
import { detectHashType } from '../utils/hash.js';
import type { ExtractedIOC, IOCType } from '../types/extraction.js';

// ---------------------------------------------------------------------------
// Regex Patterns — including defanged variants
// ---------------------------------------------------------------------------

/**
 * Defanging patterns to normalize before matching:
 * [.] (.) [dot] → .
 * hxxp → http
 * [://] → ://
 * [@] [at] → @
 */

// IPv4: standard + defanged (with [.] or (.) or [dot])
const IPV4_DEFANGED = /(?:^|\s|[,;|("'\[])(\d{1,3}(?:\[\.\]|\(\.\)|\[dot\]|\.)\d{1,3}(?:\[\.\]|\(\.\)|\[dot\]|\.)\d{1,3}(?:\[\.\]|\(\.\)|\[dot\]|\.)\d{1,3})(?=$|\s|[,;|)"'\]:/])/gi;

// IPv6 (simplified — matches common formats)
const IPV6_PATTERN = /(?:^|\s)((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})(?=$|\s|[,;|)\]:])/g;

// Domain: standard + defanged
const DOMAIN_DEFANGED = /(?:^|\s|[,;|("'\[/])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\[\.\]|\(\.\)|\[dot\]|\.))+(?:com|net|org|io|info|biz|xyz|top|ru|cn|de|uk|fr|nl|cc|tk|pw|buzz|club|online|site|tech|store|space|zip|mov|app|dev|cloud|co|me|pro|eu|in|br|au|ca|jp|kr|tw|gov|mil|edu|int))(?=$|\s|[.,;|)"'\]/:])/gi;

// URL: standard + defanged (hxxp, hxxps, fxp)
const URL_DEFANGED = /(?:^|\s|[,;|("'\[])((hxxps?|https?|fxps?|ftps?):\/\/(?:\[\.\]|\(\.\)|\[dot\]|[^\s<>"{}|\\^`\[\]])+)(?=$|\s|[,;|)"'\]>])/gi;

// Email: standard + defanged
const EMAIL_DEFANGED = /(?:^|\s|[,;|("'\[])([a-zA-Z0-9._%+\-]+(?:@|\[@\]|\[at\])[a-zA-Z0-9](?:[a-zA-Z0-9.\-\[\]()]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})(?=$|\s|[,;|)"'\]])/gi;

// Hashes: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
const HASH_PATTERN = /(?:^|\s|[,;|("'\[=:])([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?=$|\s|[,;|)"'\]])/g;

// Windows file paths
const WINDOWS_PATH = /(?:^|\s|[,;|("'\[])([A-Z]:\\(?:[^\s<>"|?*:]+\\)*[^\s<>"|?*:]+\.[a-zA-Z0-9]{1,10})(?=$|\s|[,;|)"'\]])/g;

// Linux file paths
const LINUX_PATH = /(?:^|\s|[,;|("'\[])(\/(?:usr|etc|var|tmp|opt|home|root|bin|sbin|dev|proc|sys|run|mnt|media)\/[^\s<>"'|]+)(?=$|\s|[,;|)"'\]])/g;

// Registry keys
const REGISTRY_KEY = /(?:^|\s|[,;|("'\[])((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\s<>"']+)(?=$|\s|[,;|)"'\]])/gi;

// CVE IDs
const CVE_PATTERN = /(?:^|\s|[,;|("'\[])(CVE-\d{4}-\d{4,})(?=$|\s|[,;|)"'\]])/gi;

// ---------------------------------------------------------------------------
// Extraction context window
// ---------------------------------------------------------------------------

const CONTEXT_CHARS = 100; // Characters of surrounding text to capture

function extractContext(text: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - CONTEXT_CHARS);
  const end = Math.min(text.length, matchIndex + matchLength + CONTEXT_CHARS);
  let context = text.substring(start, end).trim();
  if (start > 0) context = '...' + context;
  if (end < text.length) context = context + '...';
  return context.replace(/\n+/g, ' ');
}

// ---------------------------------------------------------------------------
// Known benign values to filter
// ---------------------------------------------------------------------------

const BENIGN_DOMAINS = new Set([
  'example.com', 'example.org', 'example.net',
  'localhost', 'localhost.localdomain',
  'google.com', 'www.google.com',
  'microsoft.com', 'www.microsoft.com',
  'github.com', 'www.github.com',
  'wikipedia.org', 'en.wikipedia.org',
  'twitter.com', 'x.com',
  'youtube.com', 'www.youtube.com',
  'linkedin.com', 'www.linkedin.com',
  'mitre.org', 'attack.mitre.org',
  'cisa.gov', 'www.cisa.gov',
  'nist.gov', 'nvd.nist.gov',
  'virustotal.com', 'www.virustotal.com',
  'abuse.ch', 'bazaar.abuse.ch',
  'shodan.io',
]);

const BENIGN_IP_PREFIXES = ['0.', '255.', '224.', '240.'];

// ---------------------------------------------------------------------------
// Main extraction function
// ---------------------------------------------------------------------------

export interface IocExtractionOptions {
  /** Include private/RFC1918 IPs. Default: false */
  includePrivateIPs?: boolean;
  /** Include benign domains (google.com, etc.). Default: false */
  includeBenignDomains?: boolean;
  /** Maximum IOCs to extract per type. Default: 500 */
  maxPerType?: number;
}

/**
 * Extract IOCs from text using regex patterns.
 * Returns deduplicated, normalized IOCs with context.
 */
export function extractIocsFromText(
  text: string,
  options: IocExtractionOptions = {},
): ExtractedIOC[] {
  const {
    includePrivateIPs = false,
    includeBenignDomains = false,
    maxPerType = 500,
  } = options;

  const results: ExtractedIOC[] = [];
  const seen = new Set<string>(); // Deduplicate by normalized value

  // Track counts per type to enforce limits
  const typeCounts: Partial<Record<IOCType, number>> = {};

  function addIoc(
    value: string,
    type: IOCType,
    originalValue: string,
    matchIndex: number,
    confidence: 'high' | 'medium' | 'low' = 'high',
  ): void {
    const normalizedKey = `${type}:${value.toLowerCase()}`;
    if (seen.has(normalizedKey)) return;

    const count = typeCounts[type] ?? 0;
    if (count >= maxPerType) return;

    seen.add(normalizedKey);
    typeCounts[type] = count + 1;

    results.push({
      value,
      type,
      context: extractContext(text, matchIndex, originalValue.length),
      confidence,
      defanged: originalValue !== value,
      originalValue,
      relationships: [],
    });
  }

  // --- Extract IPv4 addresses ---
  for (const match of text.matchAll(IPV4_DEFANGED)) {
    const original = match[1];
    const refanged = refang(original);

    if (!isValidIPv4(refanged)) continue;
    if (!includePrivateIPs && isPrivateIP(refanged)) continue;
    if (BENIGN_IP_PREFIXES.some(p => refanged.startsWith(p))) continue;

    addIoc(refanged, 'ipv4', original, match.index! + match[0].indexOf(original));
  }

  // --- Extract IPv6 addresses ---
  for (const match of text.matchAll(IPV6_PATTERN)) {
    const value = match[1];
    if (value === '::' || value === '::1') continue; // loopback
    addIoc(value, 'ipv6', value, match.index! + match[0].indexOf(value), 'medium');
  }

  // --- Extract URLs (before domains, to avoid double-matching) ---
  const urlDomains = new Set<string>();
  for (const match of text.matchAll(URL_DEFANGED)) {
    const original = match[1];
    const refanged = refang(original);

    // Track domain from URL so we skip it in domain extraction
    try {
      const parsed = new URL(refanged);
      urlDomains.add(parsed.hostname.toLowerCase());
    } catch { /* ignore */ }

    addIoc(refanged, 'url', original, match.index! + match[0].indexOf(original));
  }

  // --- Extract domains ---
  for (const match of text.matchAll(DOMAIN_DEFANGED)) {
    const original = match[1];
    const refanged = refang(original);
    const lower = refanged.toLowerCase();

    // Skip if already captured as part of a URL
    if (urlDomains.has(lower)) continue;

    if (!isValidDomain(refanged)) continue;
    if (!includeBenignDomains && BENIGN_DOMAINS.has(lower)) continue;

    addIoc(refanged, 'domain', original, match.index! + match[0].indexOf(original));
  }

  // --- Extract emails ---
  for (const match of text.matchAll(EMAIL_DEFANGED)) {
    const original = match[1];
    const refanged = refang(original);

    if (!isValidEmail(refanged)) continue;

    addIoc(refanged, 'email', original, match.index! + match[0].indexOf(original), 'medium');
  }

  // --- Extract hashes ---
  for (const match of text.matchAll(HASH_PATTERN)) {
    const value = match[1];
    const hashType = detectHashType(value);
    if (!hashType) continue;

    // Skip values that are all zeros or all one character (common in docs)
    if (/^(.)\1+$/.test(value)) continue;

    const iocType: IOCType = hashType; // md5, sha1, sha256
    addIoc(value.toLowerCase(), iocType, value, match.index! + match[0].indexOf(value));
  }

  // --- Extract Windows file paths ---
  for (const match of text.matchAll(WINDOWS_PATH)) {
    const value = match[1];
    // Filter common benign paths
    if (/^C:\\(Windows\\System32|Program Files|Users\\[^\\]+\\AppData)$/i.test(value)) continue;
    addIoc(value, 'filepath_windows', value, match.index! + match[0].indexOf(value), 'medium');
  }

  // --- Extract Linux file paths ---
  for (const match of text.matchAll(LINUX_PATH)) {
    const value = match[1];
    addIoc(value, 'filepath_linux', value, match.index! + match[0].indexOf(value), 'medium');
  }

  // --- Extract registry keys ---
  for (const match of text.matchAll(REGISTRY_KEY)) {
    const value = match[1];
    addIoc(value, 'registry_key', value, match.index! + match[0].indexOf(value), 'medium');
  }

  // --- Extract CVE IDs ---
  for (const match of text.matchAll(CVE_PATTERN)) {
    const value = match[1].toUpperCase();
    addIoc(value, 'cve', match[1], match.index! + match[0].indexOf(match[1]));
  }

  return results;
}

// ---------------------------------------------------------------------------
// Relationship inference
// ---------------------------------------------------------------------------

/**
 * Infer relationships between extracted IOCs based on proximity in text.
 * IOCs mentioned within the same paragraph/sentence likely relate.
 */
export function inferRelationships(iocs: ExtractedIOC[], text: string): ExtractedIOC[] {
  // Group IOCs by their approximate position in the text
  const positioned = iocs.map(ioc => {
    const idx = text.indexOf(ioc.originalValue);
    return { ioc, position: idx >= 0 ? idx : 0 };
  });

  // Find IOCs within ~300 chars of each other
  const PROXIMITY = 300;

  for (let i = 0; i < positioned.length; i++) {
    for (let j = i + 1; j < positioned.length; j++) {
      const a = positioned[i];
      const b = positioned[j];

      if (Math.abs(a.position - b.position) > PROXIMITY) continue;

      // Infer relationship type based on IOC types
      const rel = inferRelType(a.ioc.type, b.ioc.type);
      if (!rel) continue;

      const existing = a.ioc.relationships.find(r => r.relatedIOC === b.ioc.value);
      if (!existing) {
        a.ioc.relationships.push({
          relatedIOC: b.ioc.value,
          relationship: rel.forward,
        });
      }

      const existingReverse = b.ioc.relationships.find(r => r.relatedIOC === a.ioc.value);
      if (!existingReverse) {
        b.ioc.relationships.push({
          relatedIOC: a.ioc.value,
          relationship: rel.reverse,
        });
      }
    }
  }

  return iocs;
}

function inferRelType(
  typeA: IOCType,
  typeB: IOCType,
): { forward: string; reverse: string } | null {
  // Domain ↔ IP
  if (typeA === 'domain' && typeB === 'ipv4') {
    return { forward: 'resolves to', reverse: 'hosts' };
  }
  if (typeA === 'ipv4' && typeB === 'domain') {
    return { forward: 'hosts', reverse: 'resolves to' };
  }

  // URL ↔ Hash (URL serves a file)
  if (typeA === 'url' && (typeB === 'md5' || typeB === 'sha1' || typeB === 'sha256')) {
    return { forward: 'serves', reverse: 'downloaded from' };
  }
  if ((typeA === 'md5' || typeA === 'sha1' || typeA === 'sha256') && typeB === 'url') {
    return { forward: 'downloaded from', reverse: 'serves' };
  }

  // Domain ↔ URL
  if (typeA === 'domain' && typeB === 'url') {
    return { forward: 'associated with', reverse: 'hosted on' };
  }
  if (typeA === 'url' && typeB === 'domain') {
    return { forward: 'hosted on', reverse: 'associated with' };
  }

  // IP ↔ URL
  if (typeA === 'ipv4' && typeB === 'url') {
    return { forward: 'associated with', reverse: 'hosted on' };
  }
  if (typeA === 'url' && typeB === 'ipv4') {
    return { forward: 'hosted on', reverse: 'associated with' };
  }

  // Hash ↔ filepath
  if ((typeA === 'md5' || typeA === 'sha1' || typeA === 'sha256') &&
      (typeB === 'filepath_windows' || typeB === 'filepath_linux')) {
    return { forward: 'file at', reverse: 'hash of' };
  }
  if ((typeA === 'filepath_windows' || typeA === 'filepath_linux') &&
      (typeB === 'md5' || typeB === 'sha1' || typeB === 'sha256')) {
    return { forward: 'hash of', reverse: 'file at' };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Convenience: full extraction pipeline (regex only)
// ---------------------------------------------------------------------------

/**
 * Full IOC extraction pipeline: extract → infer relationships → return.
 * For AI-enhanced extraction, use the AI disambiguation layer on top.
 */
export function extractIocs(
  text: string,
  options: IocExtractionOptions = {},
): ExtractedIOC[] {
  const iocs = extractIocsFromText(text, options);
  return inferRelationships(iocs, text);
}
