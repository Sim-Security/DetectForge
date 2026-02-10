/**
 * IOC Enrichment — deduplication, classification, and normalization.
 *
 * Takes raw extracted IOCs and enriches them with:
 * - Canonical normalization (lowercase hashes, consistent domains)
 * - Type classification (C2, phishing, payload hash, etc.)
 * - Deduplication across extraction sources
 * - Confidence adjustment based on context
 */

import type { ExtractedIOC, IOCType } from '../types/extraction.js';
import { refang } from '../utils/defang.js';
import { isPrivateIP } from '../utils/network.js';

// ---------------------------------------------------------------------------
// IOC Classification
// ---------------------------------------------------------------------------

export type IOCClassification =
  | 'c2_server'
  | 'c2_domain'
  | 'phishing_domain'
  | 'phishing_url'
  | 'payload_hash'
  | 'payload_url'
  | 'download_url'
  | 'exfiltration_target'
  | 'staging_path'
  | 'persistence_key'
  | 'lateral_movement_tool'
  | 'vulnerability'
  | 'unknown';

/** Context keywords for classification */
const CLASSIFICATION_PATTERNS: Array<{ pattern: RegExp; classification: IOCClassification }> = [
  { pattern: /c2|command.and.control|beacon|callback|c&c/i, classification: 'c2_server' },
  { pattern: /phish|spear|lure|social.engineer/i, classification: 'phishing_domain' },
  { pattern: /payload|dropper|loader|implant|backdoor|malware|trojan|rat\b/i, classification: 'payload_hash' },
  { pattern: /download|fetch|retrieve|stage|deliver/i, classification: 'download_url' },
  { pattern: /exfil|steal|upload|transfer|rclone|mega\b/i, classification: 'exfiltration_target' },
  { pattern: /persist|autorun|run.key|scheduled.task|startup|service/i, classification: 'persistence_key' },
  { pattern: /lateral|psexec|wmi|smb|rdp|remote/i, classification: 'lateral_movement_tool' },
  { pattern: /cve-\d{4}/i, classification: 'vulnerability' },
];

/**
 * Classify an IOC based on its type and surrounding context.
 */
export function classifyIOC(ioc: ExtractedIOC): IOCClassification {
  const context = ioc.context.toLowerCase();

  // Type-specific overrides
  if (ioc.type === 'cve') return 'vulnerability';
  if (ioc.type === 'registry_key') return 'persistence_key';

  // Context-based classification
  for (const { pattern, classification } of CLASSIFICATION_PATTERNS) {
    if (pattern.test(context)) {
      // Adjust classification for specific IOC types
      if (classification === 'c2_server' && ioc.type === 'domain') return 'c2_domain';
      if (classification === 'phishing_domain' && ioc.type === 'url') return 'phishing_url';
      if (classification === 'payload_hash' && ioc.type === 'url') return 'payload_url';
      return classification;
    }
  }

  // File paths are often staging paths
  if (ioc.type === 'filepath_windows' || ioc.type === 'filepath_linux') {
    return 'staging_path';
  }

  return 'unknown';
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/**
 * Normalize an IOC value to its canonical form.
 */
export function normalizeIOC(value: string, type: IOCType): string {
  // Refang first (handle [.] etc.)
  let normalized = refang(value);

  switch (type) {
    case 'md5':
    case 'sha1':
    case 'sha256':
      return normalized.toLowerCase().trim();

    case 'domain':
      return normalized.toLowerCase().trim().replace(/\.$/, ''); // Remove trailing dot

    case 'ipv4':
    case 'ipv6':
      return normalized.trim();

    case 'url':
      // Normalize URL: lowercase scheme and host, remove trailing slash
      try {
        const url = new URL(normalized);
        url.hostname = url.hostname.toLowerCase();
        let result = url.toString();
        if (result.endsWith('/') && url.pathname === '/') {
          result = result.slice(0, -1);
        }
        return result;
      } catch {
        return normalized.trim();
      }

    case 'email':
      return normalized.toLowerCase().trim();

    case 'cve':
      return normalized.toUpperCase().trim();

    case 'registry_key':
      // Normalize HKEY_LOCAL_MACHINE → HKLM etc. for consistency
      normalized = normalized
        .replace(/^HKEY_LOCAL_MACHINE/i, 'HKLM')
        .replace(/^HKEY_CURRENT_USER/i, 'HKCU')
        .replace(/^HKEY_CLASSES_ROOT/i, 'HKCR')
        .replace(/^HKEY_USERS/i, 'HKU')
        .replace(/^HKEY_CURRENT_CONFIG/i, 'HKCC');
      return normalized.trim();

    default:
      return normalized.trim();
  }
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

/**
 * Deduplicate IOCs, merging context and relationships from duplicates.
 * Keeps the highest-confidence instance.
 */
export function deduplicateIOCs(iocs: ExtractedIOC[]): ExtractedIOC[] {
  const groups = new Map<string, ExtractedIOC[]>();

  for (const ioc of iocs) {
    const normalizedValue = normalizeIOC(ioc.value, ioc.type);
    const key = `${ioc.type}:${normalizedValue}`;

    const group = groups.get(key);
    if (group) {
      group.push(ioc);
    } else {
      groups.set(key, [ioc]);
    }
  }

  const CONFIDENCE_ORDER = { high: 3, medium: 2, low: 1 };

  const results: ExtractedIOC[] = [];

  for (const group of groups.values()) {
    // Sort by confidence (highest first)
    group.sort((a, b) => CONFIDENCE_ORDER[b.confidence] - CONFIDENCE_ORDER[a.confidence]);

    const primary = group[0];

    // Merge unique relationships from all duplicates
    const allRels = new Map<string, string>();
    for (const ioc of group) {
      for (const rel of ioc.relationships) {
        const key = `${rel.relatedIOC}:${rel.relationship}`;
        if (!allRels.has(key)) {
          allRels.set(key, rel.relatedIOC);
        }
      }
    }

    // Merge contexts (take first 3 unique)
    const contexts = new Set<string>();
    for (const ioc of group) {
      if (ioc.context && contexts.size < 3) {
        contexts.add(ioc.context);
      }
    }

    results.push({
      value: normalizeIOC(primary.value, primary.type),
      type: primary.type,
      context: [...contexts].join(' | '),
      confidence: primary.confidence,
      defanged: group.some(g => g.defanged),
      originalValue: primary.originalValue,
      relationships: primary.relationships,
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// Confidence adjustment
// ---------------------------------------------------------------------------

/**
 * Adjust IOC confidence based on various signals.
 */
export function adjustConfidence(ioc: ExtractedIOC): ExtractedIOC {
  let confidence = ioc.confidence;

  // Boost confidence for IOCs in explicit IOC sections
  if (/indicator|ioc|compromise|observable|hash/i.test(ioc.context)) {
    confidence = 'high';
  }

  // Lower confidence for IOCs in recommendation/mitigation sections
  if (/recommend|mitigat|prevent|patch|update|remediat/i.test(ioc.context)) {
    confidence = 'low';
  }

  // Private IPs are usually low confidence (lab/example)
  if (ioc.type === 'ipv4' && isPrivateIP(ioc.value)) {
    confidence = 'low';
  }

  return { ...ioc, confidence };
}

// ---------------------------------------------------------------------------
// Enrichment pipeline
// ---------------------------------------------------------------------------

export interface EnrichedIOC extends ExtractedIOC {
  classification: IOCClassification;
  normalizedValue: string;
}

/**
 * Full enrichment pipeline: normalize → deduplicate → classify → adjust confidence.
 */
export function enrichIOCs(iocs: ExtractedIOC[]): EnrichedIOC[] {
  // Step 1: Deduplicate
  const deduped = deduplicateIOCs(iocs);

  // Step 2: Enrich each IOC
  return deduped.map(ioc => {
    const adjusted = adjustConfidence(ioc);
    return {
      ...adjusted,
      classification: classifyIOC(adjusted),
      normalizedValue: normalizeIOC(adjusted.value, adjusted.type),
    };
  });
}
