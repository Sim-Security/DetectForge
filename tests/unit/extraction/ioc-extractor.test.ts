/**
 * Unit tests for the IOC extractor.
 * Tests regex-based extraction of all IOC types including defanged variants.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  extractIocsFromText,
  extractIocs,
  inferRelationships,
} from '@/extraction/ioc-extractor.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FIXTURES_DIR = join(import.meta.dirname ?? '.', '..', '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'reports', `${name}.md`), 'utf-8');
}

function loadExpected(name: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(join(FIXTURES_DIR, 'expected-outputs', `${name}.json`), 'utf-8'),
  );
}

function iocValues(iocs: ReturnType<typeof extractIocsFromText>, type: string): string[] {
  return iocs.filter(i => i.type === type).map(i => i.value);
}

// ---------------------------------------------------------------------------
// IPv4 extraction
// ---------------------------------------------------------------------------

describe('IOC Extractor — IPv4', () => {
  it('extracts standard IPv4 addresses', () => {
    const text = 'The C2 server was at 185.68.93.115 and 45.63.1.44 in the network.';
    const iocs = extractIocsFromText(text);
    const ips = iocValues(iocs, 'ipv4');
    expect(ips).toContain('185.68.93.115');
    expect(ips).toContain('45.63.1.44');
  });

  it('extracts defanged IPv4 with [.]', () => {
    const text = 'Beacon pointed to 23.227.203[.]210 for C2 traffic.';
    const iocs = extractIocsFromText(text);
    const ips = iocValues(iocs, 'ipv4');
    expect(ips).toContain('23.227.203.210');
    expect(iocs.find(i => i.value === '23.227.203.210')?.defanged).toBe(true);
  });

  it('extracts defanged IPv4 with (.)', () => {
    const text = 'Also seen: 194.165.16(.)98 traffic.';
    const iocs = extractIocsFromText(text);
    const ips = iocValues(iocs, 'ipv4');
    expect(ips).toContain('194.165.16.98');
  });

  it('extracts defanged IPv4 with [dot]', () => {
    const text = 'Callback to 149.28.134[dot]130 observed.';
    const iocs = extractIocsFromText(text);
    const ips = iocValues(iocs, 'ipv4');
    expect(ips).toContain('149.28.134.130');
  });

  it('skips private IPs by default', () => {
    const text = 'Internal host 192.168.1.50 communicated with 23.227.203.210';
    const iocs = extractIocsFromText(text);
    const ips = iocValues(iocs, 'ipv4');
    expect(ips).not.toContain('192.168.1.50');
    expect(ips).toContain('23.227.203.210');
  });

  it('includes private IPs when option enabled', () => {
    const text = 'Internal host 192.168.1.50 was compromised.';
    const iocs = extractIocsFromText(text, { includePrivateIPs: true });
    const ips = iocValues(iocs, 'ipv4');
    expect(ips).toContain('192.168.1.50');
  });

  it('rejects invalid IPv4 (octets > 255)', () => {
    const text = 'Not a valid IP: 999.999.999.999 or 256.1.1.1';
    const iocs = extractIocsFromText(text);
    const ips = iocValues(iocs, 'ipv4');
    expect(ips).toHaveLength(0);
  });

  it('deduplicates repeated IPs', () => {
    const text = 'Seen at 23.227.203.210 and again at 23.227.203.210 in the log.';
    const iocs = extractIocsFromText(text);
    const ips = iocValues(iocs, 'ipv4');
    expect(ips.filter(ip => ip === '23.227.203.210')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Domain extraction
// ---------------------------------------------------------------------------

describe('IOC Extractor — Domains', () => {
  it('extracts standard domains', () => {
    const text = 'The malware contacted systemupdatework.com for C2.';
    const iocs = extractIocsFromText(text);
    const domains = iocValues(iocs, 'domain');
    expect(domains).toContain('systemupdatework.com');
  });

  it('extracts defanged domains with [.]', () => {
    const text = 'C2 domain: cloudaborede[.]com was active.';
    const iocs = extractIocsFromText(text);
    const domains = iocValues(iocs, 'domain');
    expect(domains).toContain('cloudaborede.com');
    expect(iocs.find(i => i.value === 'cloudaborede.com')?.defanged).toBe(true);
  });

  it('extracts defanged domains with [dot]', () => {
    const text = 'Contacted trackingrealtime[dot]com.';
    const iocs = extractIocsFromText(text);
    const domains = iocValues(iocs, 'domain');
    expect(domains).toContain('trackingrealtime.com');
  });

  it('filters benign domains by default', () => {
    const text = 'As noted by google.com, the actor used evil-c2.com for operations.';
    const iocs = extractIocsFromText(text);
    const domains = iocValues(iocs, 'domain');
    expect(domains).not.toContain('google.com');
    expect(domains).toContain('evil-c2.com');
  });

  it('includes benign domains when option enabled', () => {
    const text = 'The actor spoofed google.com login pages.';
    const iocs = extractIocsFromText(text, { includeBenignDomains: true });
    const domains = iocValues(iocs, 'domain');
    expect(domains).toContain('google.com');
  });
});

// ---------------------------------------------------------------------------
// URL extraction
// ---------------------------------------------------------------------------

describe('IOC Extractor — URLs', () => {
  it('extracts standard URLs', () => {
    const text = 'Payload downloaded from http://malicious.site/payload.exe';
    const iocs = extractIocsFromText(text);
    const urls = iocValues(iocs, 'url');
    expect(urls).toContain('http://malicious.site/payload.exe');
  });

  it('extracts defanged URLs with hxxp', () => {
    const text = 'Downloaded from hxxp://evil[.]com/malware.exe';
    const iocs = extractIocsFromText(text);
    const urls = iocValues(iocs, 'url');
    expect(urls.some(u => u.includes('http://evil.com/malware.exe'))).toBe(true);
  });

  it('does not duplicate domain from URL', () => {
    const text = 'Payload at http://malicious-server.com/payload.exe was identified.';
    const iocs = extractIocsFromText(text);
    const domains = iocValues(iocs, 'domain');
    // The domain should NOT appear separately since it's already in the URL
    expect(domains).not.toContain('malicious-server.com');
  });
});

// ---------------------------------------------------------------------------
// Hash extraction
// ---------------------------------------------------------------------------

describe('IOC Extractor — Hashes', () => {
  it('extracts SHA256 hashes', () => {
    const text = 'File hash: 17205c43189c22dfcb278f5cc45c2562f622b0b6280dcd43cc1d3c274095eb90';
    const iocs = extractIocsFromText(text);
    const hashes = iocValues(iocs, 'sha256');
    expect(hashes).toContain('17205c43189c22dfcb278f5cc45c2562f622b0b6280dcd43cc1d3c274095eb90');
  });

  it('extracts SHA1 hashes', () => {
    const text = 'SHA1: a94a8fe5ccb19ba61c4c0873d391e987982fbbd3';
    const iocs = extractIocsFromText(text);
    const hashes = iocValues(iocs, 'sha1');
    expect(hashes).toContain('a94a8fe5ccb19ba61c4c0873d391e987982fbbd3');
  });

  it('extracts MD5 hashes', () => {
    const text = 'MD5: d41d8cd98f00b204e9800998ecf8427e';
    const iocs = extractIocsFromText(text);
    const hashes = iocValues(iocs, 'md5');
    expect(hashes).toContain('d41d8cd98f00b204e9800998ecf8427e');
  });

  it('normalizes hashes to lowercase', () => {
    const text = 'SHA256: AABBCCDD11223344556677889900AABBCCDD11223344556677889900AABBCCDD';
    const iocs = extractIocsFromText(text);
    const hashes = iocValues(iocs, 'sha256');
    expect(hashes[0]).toBe('aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd');
  });

  it('rejects all-zero hashes', () => {
    const text = 'SHA256: 0000000000000000000000000000000000000000000000000000000000000000';
    const iocs = extractIocsFromText(text);
    const hashes = iocValues(iocs, 'sha256');
    expect(hashes).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Email extraction
// ---------------------------------------------------------------------------

describe('IOC Extractor — Emails', () => {
  it('extracts standard email addresses', () => {
    const text = 'Phishing from attacker@evil-domain.com was observed.';
    const iocs = extractIocsFromText(text);
    const emails = iocValues(iocs, 'email');
    expect(emails).toContain('attacker@evil-domain.com');
  });

  it('extracts defanged emails with [@]', () => {
    const text = 'Contact: admin[@]malicious-server.com';
    const iocs = extractIocsFromText(text);
    const emails = iocValues(iocs, 'email');
    expect(emails).toContain('admin@malicious-server.com');
  });
});

// ---------------------------------------------------------------------------
// File path extraction
// ---------------------------------------------------------------------------

describe('IOC Extractor — File Paths', () => {
  it('extracts Windows file paths', () => {
    const text = 'Payload dropped at C:\\Windows\\Temp\\svc.exe';
    const iocs = extractIocsFromText(text);
    const paths = iocValues(iocs, 'filepath_windows');
    expect(paths).toContain('C:\\Windows\\Temp\\svc.exe');
  });

  it('extracts Linux file paths', () => {
    const text = 'Backdoor installed at /tmp/evil_backdoor.sh';
    const iocs = extractIocsFromText(text);
    const paths = iocValues(iocs, 'filepath_linux');
    expect(paths).toContain('/tmp/evil_backdoor.sh');
  });
});

// ---------------------------------------------------------------------------
// Registry key extraction
// ---------------------------------------------------------------------------

describe('IOC Extractor — Registry Keys', () => {
  it('extracts HKLM registry keys', () => {
    const text = 'Persistence via HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate';
    const iocs = extractIocsFromText(text);
    const keys = iocValues(iocs, 'registry_key');
    expect(keys).toContain('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate');
  });

  it('extracts HKCU registry keys', () => {
    const text = 'Modified HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command';
    const iocs = extractIocsFromText(text);
    const keys = iocValues(iocs, 'registry_key');
    expect(keys.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CVE extraction
// ---------------------------------------------------------------------------

describe('IOC Extractor — CVE IDs', () => {
  it('extracts CVE identifiers', () => {
    const text = 'Exploited CVE-2024-1709 (ConnectWise) and CVE-2023-22515 (Confluence).';
    const iocs = extractIocsFromText(text);
    const cves = iocValues(iocs, 'cve');
    expect(cves).toContain('CVE-2024-1709');
    expect(cves).toContain('CVE-2023-22515');
  });

  it('normalizes CVE IDs to uppercase', () => {
    const text = 'Vulnerability cve-2023-23397 was exploited.';
    const iocs = extractIocsFromText(text);
    const cves = iocValues(iocs, 'cve');
    expect(cves).toContain('CVE-2023-23397');
  });
});

// ---------------------------------------------------------------------------
// Context extraction
// ---------------------------------------------------------------------------

describe('IOC Extractor — Context', () => {
  it('captures surrounding context for each IOC', () => {
    const text = 'The attacker used the C2 server at 23.227.203.210 to exfiltrate data.';
    const iocs = extractIocsFromText(text);
    const ip = iocs.find(i => i.value === '23.227.203.210');
    expect(ip?.context).toContain('C2 server');
    expect(ip?.context).toContain('exfiltrate');
  });
});

// ---------------------------------------------------------------------------
// Relationship inference
// ---------------------------------------------------------------------------

describe('IOC Extractor — Relationships', () => {
  it('infers domain-to-IP relationships for nearby IOCs', () => {
    const text = 'The domain evil-c2.com (45.63.1.44) was used as a C2 server.';
    const iocs = extractIocs(text);
    const domain = iocs.find(i => i.value === 'evil-c2.com');
    expect(domain?.relationships.length).toBeGreaterThan(0);
    expect(domain?.relationships.some(r => r.relatedIOC === '45.63.1.44')).toBe(true);
  });

  it('infers URL-to-hash relationships', () => {
    const text = 'Downloaded http://evil.com/payload.exe with hash a94a8fe5ccb19ba61c4c0873d391e987982fbbd3';
    const iocs = extractIocs(text);
    const url = iocs.find(i => i.type === 'url');
    if (url) {
      expect(url.relationships.some(r => r.relationship === 'serves')).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Ground truth: Black Basta report
// ---------------------------------------------------------------------------

describe('IOC Extractor — Black Basta Ground Truth', () => {
  const reportText = loadFixture('black-basta-ransomware');
  const expected = loadExpected('black-basta-ransomware') as {
    ground_truth: {
      iocs: {
        ipv4: string[];
        domains: string[];
        sha256: string[];
        file_paths: string[];
        registry_keys: string[];
      };
    };
  };
  const iocs = extractIocs(reportText);

  it('extracts all expected IPv4 addresses', () => {
    const extractedIPs = iocValues(iocs, 'ipv4');
    for (const ip of expected.ground_truth.iocs.ipv4) {
      expect(extractedIPs).toContain(ip);
    }
  });

  it('extracts all expected domains', () => {
    const extractedDomains = iocValues(iocs, 'domain');
    for (const domain of expected.ground_truth.iocs.domains) {
      expect(extractedDomains).toContain(domain);
    }
  });

  it('extracts all expected SHA256 hashes', () => {
    const extractedHashes = iocValues(iocs, 'sha256');
    for (const hash of expected.ground_truth.iocs.sha256) {
      expect(extractedHashes).toContain(hash);
    }
  });

  it('extracts expected file paths', () => {
    const extractedPaths = iocValues(iocs, 'filepath_windows');
    // At least some file paths should be found
    expect(extractedPaths.length).toBeGreaterThan(0);
  });

  it('extracts expected registry keys', () => {
    const extractedKeys = iocValues(iocs, 'registry_key');
    expect(extractedKeys.length).toBeGreaterThan(0);
  });

  it('extracts expected CVE IDs', () => {
    const extractedCVEs = iocValues(iocs, 'cve');
    expect(extractedCVEs).toContain('CVE-2024-1709');
    expect(extractedCVEs).toContain('CVE-2023-22515');
  });

  it('achieves >90% IOC recall across all types', () => {
    const gt = expected.ground_truth.iocs;
    const allExpected = [
      ...gt.ipv4,
      ...gt.domains,
      ...gt.sha256,
    ];
    const allExtracted = [
      ...iocValues(iocs, 'ipv4'),
      ...iocValues(iocs, 'domain'),
      ...iocValues(iocs, 'sha256'),
    ];

    let found = 0;
    for (const expected of allExpected) {
      if (allExtracted.includes(expected)) found++;
    }

    const recall = found / allExpected.length;
    expect(recall).toBeGreaterThanOrEqual(0.9);
  });
});

// ---------------------------------------------------------------------------
// Ground truth: Lazarus KANDYKORN report
// ---------------------------------------------------------------------------

describe('IOC Extractor — Lazarus KANDYKORN Ground Truth', () => {
  const reportText = loadFixture('lazarus-kandykorn');
  const expected = loadExpected('lazarus-kandykorn') as {
    ground_truth: {
      iocs: {
        ipv4: string[];
        domains: string[];
        sha256: string[];
      };
    };
  };
  const iocs = extractIocs(reportText);

  it('extracts all expected IPv4 addresses', () => {
    const extractedIPs = iocValues(iocs, 'ipv4');
    for (const ip of expected.ground_truth.iocs.ipv4) {
      expect(extractedIPs).toContain(ip);
    }
  });

  it('extracts all expected domains (as domain or in URL)', () => {
    const extractedDomains = iocValues(iocs, 'domain');
    const extractedUrls = iocValues(iocs, 'url');
    for (const domain of expected.ground_truth.iocs.domains) {
      // Domain might be captured standalone or as part of a URL
      const foundAsDomain = extractedDomains.includes(domain);
      const foundInUrl = extractedUrls.some(u => u.includes(domain));
      expect(foundAsDomain || foundInUrl).toBe(true);
    }
  });

  it('extracts all expected SHA256 hashes', () => {
    const extractedHashes = iocValues(iocs, 'sha256');
    for (const hash of expected.ground_truth.iocs.sha256) {
      expect(extractedHashes).toContain(hash);
    }
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('IOC Extractor — Edge Cases', () => {
  it('handles empty input', () => {
    const iocs = extractIocsFromText('');
    expect(iocs).toHaveLength(0);
  });

  it('handles input with no IOCs', () => {
    const text = 'This is a normal report about cybersecurity trends.';
    const iocs = extractIocsFromText(text);
    expect(iocs).toHaveLength(0);
  });

  it('handles very long input without crashing', () => {
    const text = 'IP: 8.8.8.8 '.repeat(10000);
    const iocs = extractIocsFromText(text);
    expect(iocs.length).toBeGreaterThan(0);
  });

  it('respects maxPerType limit', () => {
    const ips = Array.from({ length: 100 }, (_, i) =>
      `${(i % 250) + 1}.${Math.floor(i / 250) + 1}.1.1`
    ).join('\n');
    const iocs = extractIocsFromText(ips, { maxPerType: 10 });
    const ipCount = iocs.filter(i => i.type === 'ipv4').length;
    expect(ipCount).toBeLessThanOrEqual(10);
  });
});
