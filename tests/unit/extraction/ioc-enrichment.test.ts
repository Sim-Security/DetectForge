/**
 * Unit tests for IOC enrichment module.
 */

import { describe, it, expect } from 'vitest';
import {
  classifyIOC,
  normalizeIOC,
  deduplicateIOCs,
  adjustConfidence,
  enrichIOCs,
} from '@/extraction/ioc-enrichment.js';
import type { ExtractedIOC } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeIOC(overrides: Partial<ExtractedIOC> = {}): ExtractedIOC {
  return {
    value: '23.227.203.210',
    type: 'ipv4',
    context: 'The C2 server at 23.227.203.210 was active.',
    confidence: 'high',
    defanged: false,
    originalValue: '23.227.203.210',
    relationships: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

describe('IOC Enrichment — classifyIOC', () => {
  it('classifies CVE as vulnerability', () => {
    const ioc = makeIOC({ type: 'cve', value: 'CVE-2024-1709', context: 'something' });
    expect(classifyIOC(ioc)).toBe('vulnerability');
  });

  it('classifies registry key as persistence_key', () => {
    const ioc = makeIOC({
      type: 'registry_key',
      value: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Update',
      context: 'registry value',
    });
    expect(classifyIOC(ioc)).toBe('persistence_key');
  });

  it('classifies C2-related IP as c2_server', () => {
    const ioc = makeIOC({ context: 'The C2 server communicated via beacon callback.' });
    expect(classifyIOC(ioc)).toBe('c2_server');
  });

  it('classifies C2-related domain as c2_domain', () => {
    const ioc = makeIOC({
      type: 'domain',
      value: 'evil.com',
      context: 'Command and control domain.',
    });
    expect(classifyIOC(ioc)).toBe('c2_domain');
  });

  it('classifies phishing URL', () => {
    const ioc = makeIOC({
      type: 'url',
      value: 'http://phish.com/login',
      context: 'Spear phishing URL used in lure.',
    });
    expect(classifyIOC(ioc)).toBe('phishing_url');
  });

  it('classifies download URL', () => {
    const ioc = makeIOC({
      type: 'url',
      value: 'http://evil.com/tools.exe',
      context: 'Download the tools from staging server to fetch more.',
    });
    expect(classifyIOC(ioc)).toBe('download_url');
  });

  it('classifies exfiltration target', () => {
    const ioc = makeIOC({
      type: 'domain',
      value: 'mega.nz',
      context: 'Rclone used to exfiltrate data to MEGA storage.',
    });
    expect(classifyIOC(ioc)).toBe('exfiltration_target');
  });

  it('classifies file path as staging_path', () => {
    const ioc = makeIOC({
      type: 'filepath_windows',
      value: 'C:\\Windows\\Temp\\svc.exe',
      context: 'some file',
    });
    expect(classifyIOC(ioc)).toBe('staging_path');
  });

  it('returns unknown for unclassifiable IOCs', () => {
    const ioc = makeIOC({ context: 'This is a normal sentence.' });
    expect(classifyIOC(ioc)).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

describe('IOC Enrichment — normalizeIOC', () => {
  it('lowercases hashes', () => {
    expect(normalizeIOC('AABBCCDD', 'md5')).toBe('aabbccdd');
  });

  it('lowercases domains', () => {
    expect(normalizeIOC('Evil-Domain.COM', 'domain')).toBe('evil-domain.com');
  });

  it('removes trailing dot from domains', () => {
    expect(normalizeIOC('evil.com.', 'domain')).toBe('evil.com');
  });

  it('uppercases CVE IDs', () => {
    expect(normalizeIOC('cve-2024-1709', 'cve')).toBe('CVE-2024-1709');
  });

  it('normalizes HKEY_LOCAL_MACHINE to HKLM', () => {
    expect(normalizeIOC('HKEY_LOCAL_MACHINE\\Software\\Test', 'registry_key'))
      .toBe('HKLM\\Software\\Test');
  });

  it('refangs defanged values', () => {
    expect(normalizeIOC('evil[.]com', 'domain')).toBe('evil.com');
  });

  it('lowercases emails', () => {
    expect(normalizeIOC('Admin@Evil.COM', 'email')).toBe('admin@evil.com');
  });
});

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('IOC Enrichment — deduplicateIOCs', () => {
  it('merges duplicate IOCs', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: '1.2.3.4', confidence: 'low' }),
      makeIOC({ value: '1.2.3.4', confidence: 'high' }),
    ];
    const result = deduplicateIOCs(iocs);
    expect(result).toHaveLength(1);
    expect(result[0].confidence).toBe('high');
  });

  it('keeps different IOCs separate', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ value: '1.2.3.4' }),
      makeIOC({ value: '5.6.7.8' }),
    ];
    const result = deduplicateIOCs(iocs);
    expect(result).toHaveLength(2);
  });

  it('merges case-insensitive hashes', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({ type: 'sha256', value: 'AABB1122' + 'CC'.repeat(24) }),
      makeIOC({ type: 'sha256', value: 'aabb1122' + 'cc'.repeat(24) }),
    ];
    const result = deduplicateIOCs(iocs);
    expect(result).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Confidence adjustment
// ---------------------------------------------------------------------------

describe('IOC Enrichment — adjustConfidence', () => {
  it('boosts confidence for IOCs in IOC sections', () => {
    const ioc = makeIOC({
      confidence: 'medium',
      context: 'Indicators of Compromise: 23.227.203.210',
    });
    const adjusted = adjustConfidence(ioc);
    expect(adjusted.confidence).toBe('high');
  });

  it('lowers confidence for IOCs in recommendation sections', () => {
    const ioc = makeIOC({
      confidence: 'high',
      context: 'We recommend blocking this IP and patching systems.',
    });
    const adjusted = adjustConfidence(ioc);
    expect(adjusted.confidence).toBe('low');
  });
});

// ---------------------------------------------------------------------------
// Full enrichment pipeline
// ---------------------------------------------------------------------------

describe('IOC Enrichment — enrichIOCs', () => {
  it('deduplicates, classifies, and adjusts confidence', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: '23.227.203.210',
        context: 'C2 server at 23.227.203.210 beaconed.',
      }),
      makeIOC({
        value: '23.227.203.210',
        confidence: 'low',
        context: 'The beacon callback was observed.',
      }),
    ];

    const enriched = enrichIOCs(iocs);
    expect(enriched).toHaveLength(1);
    expect(enriched[0].classification).toBe('c2_server');
    expect(enriched[0].normalizedValue).toBe('23.227.203.210');
    expect(enriched[0].confidence).toBe('high');
  });

  it('handles empty input', () => {
    expect(enrichIOCs([])).toHaveLength(0);
  });
});
