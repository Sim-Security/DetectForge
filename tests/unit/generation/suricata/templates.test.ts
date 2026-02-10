/**
 * Unit tests for Suricata rule template registry and category suggestion heuristics.
 *
 * Covers:
 * - getSuricataTemplate: lookup by category, unknown category
 * - getAllSuricataTemplates: exhaustive template list
 * - Per-template field assertions (protocol, ports, action, direction, requiredKeywords)
 * - suggestSuricataCategory: domain, URL, IP, TTP-based heuristics, edge cases
 */

import { describe, it, expect } from 'vitest';
import {
  getSuricataTemplate,
  getAllSuricataTemplates,
  suggestSuricataCategory,
} from '@/generation/suricata/templates.js';
import type { SuricataTemplate } from '@/generation/suricata/templates.js';
import type { ExtractedIOC, ExtractedTTP } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Helpers: factory functions for IOC / TTP test fixtures
// ---------------------------------------------------------------------------

function makeIOC(overrides: Partial<ExtractedIOC> & { value: string; type: string }): ExtractedIOC {
  return {
    context: 'test context',
    confidence: 'high',
    defanged: false,
    originalValue: overrides.value,
    relationships: [],
    ...overrides,
  } as ExtractedIOC;
}

function makeTTP(overrides: Partial<ExtractedTTP> = {}): ExtractedTTP {
  return {
    description: 'Some TTP description',
    tools: [],
    targetPlatforms: ['windows'],
    artifacts: [],
    detectionOpportunities: [],
    confidence: 'high',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// All known category identifiers
// ---------------------------------------------------------------------------

const ALL_CATEGORIES = [
  'dns_query',
  'http_request',
  'tls_sni',
  'http_download',
  'tcp_connection',
  'udp_connection',
] as const;

// ===================================================================
// getSuricataTemplate
// ===================================================================

describe('getSuricataTemplate', () => {
  it.each(ALL_CATEGORIES)('returns a template for category "%s"', (category) => {
    const tpl = getSuricataTemplate(category);
    expect(tpl).toBeDefined();
    expect(tpl!.category).toBe(category);
  });

  it('returns undefined for an unknown category', () => {
    expect(getSuricataTemplate('nonexistent_category')).toBeUndefined();
  });

  it('returns undefined for an empty string', () => {
    expect(getSuricataTemplate('')).toBeUndefined();
  });
});

// ===================================================================
// getAllSuricataTemplates
// ===================================================================

describe('getAllSuricataTemplates', () => {
  it('returns exactly 6 templates', () => {
    const templates = getAllSuricataTemplates();
    expect(templates).toHaveLength(6);
  });

  it('returns an array containing all known category names', () => {
    const categories = getAllSuricataTemplates().map(t => t.category);
    for (const cat of ALL_CATEGORIES) {
      expect(categories).toContain(cat);
    }
  });

  it('returns distinct template objects (no duplicates by category)', () => {
    const categories = getAllSuricataTemplates().map(t => t.category);
    expect(new Set(categories).size).toBe(categories.length);
  });
});

// ===================================================================
// Template field integrity
// ===================================================================

describe('Template field integrity', () => {
  const templates = getAllSuricataTemplates();

  it('every template has all required fields', () => {
    const requiredKeys: (keyof SuricataTemplate)[] = [
      'category',
      'protocol',
      'description',
      'defaultAction',
      'defaultDirection',
      'defaultSourceIp',
      'defaultSourcePort',
      'defaultDestIp',
      'defaultDestPort',
      'requiredKeywords',
      'exampleOptions',
      'commonClasstype',
    ];

    for (const tpl of templates) {
      for (const key of requiredKeys) {
        expect(tpl[key], `${tpl.category} missing "${key}"`).toBeDefined();
      }
    }
  });

  it('all templates have defaultAction = "alert"', () => {
    for (const tpl of templates) {
      expect(tpl.defaultAction, `${tpl.category} action`).toBe('alert');
    }
  });

  it('all templates have defaultDirection = "->"', () => {
    for (const tpl of templates) {
      expect(tpl.defaultDirection, `${tpl.category} direction`).toBe('->');
    }
  });

  it('all templates have a non-empty requiredKeywords array', () => {
    for (const tpl of templates) {
      expect(tpl.requiredKeywords.length, `${tpl.category} requiredKeywords`).toBeGreaterThan(0);
    }
  });

  it('all templates have a non-empty exampleOptions array', () => {
    for (const tpl of templates) {
      expect(tpl.exampleOptions.length, `${tpl.category} exampleOptions`).toBeGreaterThan(0);
    }
  });

  it('all templates have a non-empty commonClasstype', () => {
    for (const tpl of templates) {
      expect(tpl.commonClasstype.length, `${tpl.category} commonClasstype`).toBeGreaterThan(0);
    }
  });
});

// ===================================================================
// Protocol-specific template details
// ===================================================================

describe('dns_query template', () => {
  const tpl = getSuricataTemplate('dns_query')!;

  it('uses the "dns" protocol', () => {
    expect(tpl.protocol).toBe('dns');
  });

  it('has destination port "53"', () => {
    expect(tpl.defaultDestPort).toBe('53');
  });

  it('requires dns.query, content, and nocase keywords', () => {
    expect(tpl.requiredKeywords).toContain('dns.query');
    expect(tpl.requiredKeywords).toContain('content');
    expect(tpl.requiredKeywords).toContain('nocase');
  });

  it('uses $HOME_NET as default source IP', () => {
    expect(tpl.defaultSourceIp).toBe('$HOME_NET');
  });
});

describe('http_request template', () => {
  const tpl = getSuricataTemplate('http_request')!;

  it('uses the "http" protocol', () => {
    expect(tpl.protocol).toBe('http');
  });

  it('has destination port "$HTTP_PORTS"', () => {
    expect(tpl.defaultDestPort).toBe('$HTTP_PORTS');
  });

  it('uses $EXTERNAL_NET as default destination IP', () => {
    expect(tpl.defaultDestIp).toBe('$EXTERNAL_NET');
  });

  it('requires http-related keywords', () => {
    expect(tpl.requiredKeywords).toContain('http.host');
    expect(tpl.requiredKeywords).toContain('content');
  });
});

describe('tls_sni template', () => {
  const tpl = getSuricataTemplate('tls_sni')!;

  it('uses the "tls" protocol', () => {
    expect(tpl.protocol).toBe('tls');
  });

  it('has destination port "443"', () => {
    expect(tpl.defaultDestPort).toBe('443');
  });

  it('requires tls.sni and content keywords', () => {
    expect(tpl.requiredKeywords).toContain('tls.sni');
    expect(tpl.requiredKeywords).toContain('content');
  });
});

describe('http_download template', () => {
  const tpl = getSuricataTemplate('http_download')!;

  it('uses the "http" protocol', () => {
    expect(tpl.protocol).toBe('http');
  });

  it('has destination port "$HTTP_PORTS"', () => {
    expect(tpl.defaultDestPort).toBe('$HTTP_PORTS');
  });

  it('requires http.uri, file_data, and content keywords', () => {
    expect(tpl.requiredKeywords).toContain('http.uri');
    expect(tpl.requiredKeywords).toContain('file_data');
    expect(tpl.requiredKeywords).toContain('content');
  });
});

describe('tcp_connection template', () => {
  const tpl = getSuricataTemplate('tcp_connection')!;

  it('uses the "tcp" protocol', () => {
    expect(tpl.protocol).toBe('tcp');
  });

  it('has destination port "any"', () => {
    expect(tpl.defaultDestPort).toBe('any');
  });

  it('requires flow keyword', () => {
    expect(tpl.requiredKeywords).toContain('flow');
  });
});

describe('udp_connection template', () => {
  const tpl = getSuricataTemplate('udp_connection')!;

  it('uses the "udp" protocol', () => {
    expect(tpl.protocol).toBe('udp');
  });

  it('has destination port "any"', () => {
    expect(tpl.defaultDestPort).toBe('any');
  });

  it('requires content keyword', () => {
    expect(tpl.requiredKeywords).toContain('content');
  });
});

// ===================================================================
// suggestSuricataCategory
// ===================================================================

describe('suggestSuricataCategory', () => {
  // ---- Domain IOC ----

  it('suggests dns_query and tls_sni for a domain IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'evil.example.com', type: 'domain' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toContain('dns_query');
    expect(result).toContain('tls_sni');
  });

  it('does not suggest http_request for a plain domain IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'evil.example.com', type: 'domain' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).not.toContain('http_request');
  });

  // ---- URL IOC ----

  it('suggests http_request, dns_query, and tls_sni for a URL IOC starting with http://', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'http://malware.example.com/callback', type: 'url' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toContain('http_request');
    expect(result).toContain('dns_query');
    expect(result).toContain('tls_sni');
  });

  it('suggests http_request for a URL IOC starting with https://', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'https://c2.example.com/api/check', type: 'url' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toContain('http_request');
  });

  it('suggests http_download for a URL whose path ends with a file extension (.exe)', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'https://dl.example.com/payload.exe', type: 'url' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toContain('http_download');
    // Should also include http_request and dns/tls
    expect(result).toContain('http_request');
    expect(result).toContain('dns_query');
    expect(result).toContain('tls_sni');
  });

  it('suggests http_download for a URL ending in .dll', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'http://evil.com/loader.dll', type: 'url' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toContain('http_download');
  });

  it('suggests http_download for URL with file extension followed by query string', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'http://evil.com/dropper.bin?v=2', type: 'url' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toContain('http_download');
  });

  it('does not suggest http_download when URL has no file extension', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'http://evil.com/api/callback', type: 'url' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).not.toContain('http_download');
  });

  // ---- IPv4 / IPv6 IOC ----

  it('suggests tcp_connection for an IPv4 IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: '198.51.100.42', type: 'ipv4' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toContain('tcp_connection');
  });

  it('suggests tcp_connection for an IPv6 IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: '2001:db8::1', type: 'ipv6' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toContain('tcp_connection');
  });

  it('does not suggest udp_connection for IPv4 IOC when no TTPs mention UDP', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: '198.51.100.42', type: 'ipv4' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).not.toContain('udp_connection');
  });

  it('suggests tcp_connection AND udp_connection for IPv4 when TTP description mentions UDP', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: '198.51.100.42', type: 'ipv4' }),
    ];
    const ttps: ExtractedTTP[] = [
      makeTTP({ description: 'C2 beaconing over UDP on port 53' }),
    ];
    const result = suggestSuricataCategory(iocs, ttps);
    expect(result).toContain('tcp_connection');
    expect(result).toContain('udp_connection');
  });

  it('detects UDP mention in TTP artifact descriptions (not just description field)', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: '10.0.0.1', type: 'ipv4' }),
    ];
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Exfiltration over encrypted channel',
        artifacts: [
          { type: 'network', description: 'UDP traffic to port 443', value: 'udp:443' },
        ],
      }),
    ];
    const result = suggestSuricataCategory(iocs, ttps);
    expect(result).toContain('udp_connection');
  });

  // ---- TTP with network artifact ----

  it('suggests tcp_connection when a TTP has a network artifact (no relevant IOCs)', () => {
    const iocs: ExtractedIOC[] = [];
    const ttps: ExtractedTTP[] = [
      makeTTP({
        artifacts: [
          { type: 'network', description: 'TCP connection to C2 server' },
        ],
      }),
    ];
    const result = suggestSuricataCategory(iocs, ttps);
    expect(result).toContain('tcp_connection');
  });

  it('includes tcp_connection from TTP network artifacts even alongside domain IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'c2.evil.com', type: 'domain' }),
    ];
    const ttps: ExtractedTTP[] = [
      makeTTP({
        artifacts: [
          { type: 'network', description: 'Raw TCP connection' },
        ],
      }),
    ];
    const result = suggestSuricataCategory(iocs, ttps);
    expect(result).toContain('dns_query');
    expect(result).toContain('tls_sni');
    expect(result).toContain('tcp_connection');
  });

  // ---- Edge cases ----

  it('returns empty array when there are no IOCs and no network-related TTPs', () => {
    const result = suggestSuricataCategory([], []);
    expect(result).toEqual([]);
  });

  it('returns empty array for file-hash-only IOCs', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'd41d8cd98f00b204e9800998ecf8427e', type: 'md5' }),
      makeIOC({ value: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', type: 'sha1' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toEqual([]);
  });

  it('returns empty array for email IOC only', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'attacker@evil.com', type: 'email' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toEqual([]);
  });

  it('returns empty array for registry key IOC only', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'HKLM\\Software\\Evil', type: 'registry_key' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toEqual([]);
  });

  it('does not produce duplicate categories when multiple IOCs trigger the same template', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'evil1.com', type: 'domain' }),
      makeIOC({ value: 'evil2.com', type: 'domain' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    const unique = [...new Set(result)];
    expect(result).toEqual(unique);
  });

  it('combines categories from mixed IOC types', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: 'evil.com', type: 'domain' }),
      makeIOC({ value: '10.0.0.1', type: 'ipv4' }),
    ];
    const result = suggestSuricataCategory(iocs, []);
    expect(result).toContain('dns_query');
    expect(result).toContain('tls_sni');
    expect(result).toContain('tcp_connection');
  });

  it('does not suggest TTP network artifacts for non-network artifact types', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        artifacts: [
          { type: 'file', description: 'Dropped file on disk' },
          { type: 'registry', description: 'Registry persistence key' },
          { type: 'process', description: 'Child process spawned' },
        ],
      }),
    ];
    const result = suggestSuricataCategory([], ttps);
    expect(result).toEqual([]);
  });
});
