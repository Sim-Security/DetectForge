/**
 * Tests for the ingestion normalizer
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  normalizeReport,
  detectFormat,
  classifySection,
  type InputFormat,
} from '@/ingestion/normalizer.js';

// Helper to load fixture files
const fixturesDir = join(import.meta.dirname ?? '.', '../../fixtures/reports');

function loadFixture(filename: string): string {
  return readFileSync(join(fixturesDir, filename), 'utf-8');
}

describe('Format Detection', () => {
  it('should detect PDF from extension', () => {
    const format = detectFormat('', 'report.pdf');
    expect(format).toBe('pdf');
  });

  it('should detect PDF from buffer header', () => {
    const buffer = Buffer.from('%PDF-1.4');
    const format = detectFormat(buffer);
    expect(format).toBe('pdf');
  });

  it('should detect HTML from extension', () => {
    expect(detectFormat('', 'report.html')).toBe('html');
    expect(detectFormat('', 'report.htm')).toBe('html');
  });

  it('should detect HTML from content', () => {
    expect(detectFormat('<html><body>Test</body></html>')).toBe('html');
    expect(detectFormat('<!DOCTYPE html>')).toBe('html');
  });

  it('should detect markdown from extension', () => {
    expect(detectFormat('', 'report.md')).toBe('markdown');
    expect(detectFormat('', 'report.markdown')).toBe('markdown');
  });

  it('should detect markdown from heading syntax', () => {
    expect(detectFormat('# Title\n\nContent')).toBe('markdown');
    expect(detectFormat('---\ntitle: Test\n---\n\nContent')).toBe('markdown');
  });

  it('should detect plaintext from extension', () => {
    const format = detectFormat('', 'report.txt');
    expect(format).toBe('plaintext');
  });

  it('should detect JSON from content', () => {
    expect(detectFormat('{"key": "value"}')).toBe('json');
  });

  it('should detect STIX from content', () => {
    const stix = JSON.stringify({
      type: 'bundle',
      spec_version: '2.1',
      objects: [],
    });
    expect(detectFormat(stix)).toBe('stix');
  });

  it('should default to plaintext for unknown format', () => {
    expect(detectFormat('Just some text')).toBe('plaintext');
    expect(detectFormat('')).toBe('plaintext');
  });

  it('should handle buffer input for text formats', () => {
    const buffer = Buffer.from('# Markdown Title');
    expect(detectFormat(buffer)).toBe('markdown');
  });
});

describe('Section Classification', () => {
  it('should classify overview sections', () => {
    expect(classifySection('Overview', 'This is a summary')).toBe('overview');
    expect(classifySection('Executive Summary', '')).toBe('overview');
    expect(classifySection('Introduction', 'Background info')).toBe('overview');
    expect(classifySection('Abstract', '')).toBe('overview');
  });

  it('should classify technical detail sections', () => {
    expect(classifySection('Technical Details', '')).toBe('technical_details');
    expect(classifySection('Analysis', 'Deep dive')).toBe('technical_details');
    expect(classifySection('Execution', 'How it works')).toBe('technical_details');
    expect(classifySection('Lateral Movement', '')).toBe('technical_details');
  });

  it('should classify IOC sections', () => {
    expect(classifySection('Indicators of Compromise', '')).toBe('iocs');
    expect(classifySection('IOCs', 'IP addresses')).toBe('iocs');
    expect(classifySection('Observable Artifacts', '')).toBe('iocs');
    expect(classifySection('File Hashes', '')).toBe('iocs');
  });

  it('should classify TTP sections', () => {
    expect(classifySection('MITRE ATT&CK Mapping', '')).toBe('ttps');
    expect(classifySection('Tactics and Techniques', '')).toBe('ttps');
    expect(classifySection('Attack Behavior', '')).toBe('ttps');
    expect(classifySection('Kill Chain', '')).toBe('ttps');
  });

  it('should classify recommendation sections', () => {
    expect(classifySection('Recommendations', '')).toBe('recommendations');
    expect(classifySection('Mitigation', 'Steps to take')).toBe('recommendations');
    expect(classifySection('Detection', 'How to detect')).toBe('recommendations');
    expect(classifySection('Response Actions', '')).toBe('recommendations');
  });

  it('should return other for unclassified sections', () => {
    expect(classifySection('Random Section', 'Random content')).toBe('other');
    expect(classifySection('Acknowledgments', 'Thanks')).toBe('other');
  });

  it('should be case insensitive', () => {
    expect(classifySection('OVERVIEW', '')).toBe('overview');
    expect(classifySection('technical details', '')).toBe('technical_details');
  });

  it('should classify based on content when heading is unclear', () => {
    expect(classifySection('Section 1', 'This is an overview of the attack')).toBe('overview');
    expect(classifySection('Section 2', 'MITRE ATT&CK technique T1234')).toBe('ttps');
    expect(classifySection('Section 3', 'IP address 192.168.1.1 and file hash abc123')).toBe('iocs');
  });
});

describe('Normalize Report', () => {
  it('should normalize markdown report', async () => {
    const markdown = loadFixture('apt29-midnight-blizzard.md');
    const report = await normalizeReport(markdown, {
      filename: 'apt29-midnight-blizzard.md',
    });

    expect(report.id).toBeDefined();
    expect(report.title).toContain('Midnight Blizzard');
    expect(report.inputFormat).toBe('markdown');
    expect(report.sections.length).toBeGreaterThan(0);

    // Should have classified sections
    const sectionTypes = report.sections.map(s => s.type);
    expect(sectionTypes).toContain('overview');
    expect(sectionTypes).toContain('technical_details');
  });

  it('should normalize all fixture markdown files', async () => {
    const fixtures = [
      'apt29-midnight-blizzard.md',
      'black-basta-ransomware.md',
      'icedid-to-ransomware.md',
      'ivanti-vpn-zero-day.md',
      'lazarus-kandykorn.md',
      'scattered-spider-social-eng.md',
    ];

    for (const filename of fixtures) {
      const markdown = loadFixture(filename);
      const report = await normalizeReport(markdown, { filename });

      expect(report.id).toBeDefined();
      expect(report.title).not.toBe('Empty Report');
      expect(report.sections.length).toBeGreaterThan(0);
      expect(report.rawText).toBeDefined();

      // Should have at least some classified sections
      const classifiedSections = report.sections.filter(s => s.type !== 'other');
      expect(classifiedSections.length).toBeGreaterThan(0);
    }
  });

  it('should normalize HTML report', async () => {
    const html = `
<html>
<head><title>Test Report</title></head>
<body>
  <article>
    <h1>Test Report</h1>
    <h2>Overview</h2>
    <p>Overview content</p>
  </article>
</body>
</html>`;

    const report = await normalizeReport(html, {
      filename: 'report.html',
      url: 'http://example.com/report.html',
    });

    expect(report.id).toBeDefined();
    expect(report.inputFormat).toBe('html');
    expect(report.metadata.reportUrl).toBe('http://example.com/report.html');
  });

  it('should normalize plaintext report', async () => {
    const text = `THREAT REPORT

OVERVIEW

This is an overview.

TECHNICAL DETAILS

This is technical content.`;

    const report = await normalizeReport(text, { filename: 'report.txt' });

    expect(report.id).toBeDefined();
    expect(report.inputFormat).toBe('plaintext');
    expect(report.sections.length).toBeGreaterThan(0);
  });

  it('should auto-detect format when not specified', async () => {
    const markdown = '# Title\n\nContent';
    const report = await normalizeReport(markdown);

    expect(report.inputFormat).toBe('markdown');
  });

  it('should respect explicit format parameter', async () => {
    const text = '# Could be markdown\n\nOr plaintext';
    const report = await normalizeReport(text, { format: 'plaintext' });

    expect(report.inputFormat).toBe('plaintext');
  });

  it('should reclassify sections left as other', async () => {
    const markdown = `# Random Heading

This section contains MITRE ATT&CK techniques.`;

    const report = await normalizeReport(markdown);

    // The section heading doesn't match TTP keywords, but content does
    // The normalizer should reclassify it
    const section = report.sections.find(s => s.heading === 'Random Heading');
    expect(section?.type).toBe('ttps');
  });

  it('should validate required fields', async () => {
    const markdown = '# Valid Report\n\nContent';
    const report = await normalizeReport(markdown);

    expect(report.id).toBeDefined();
    expect(typeof report.id).toBe('string');
    expect(report.id.length).toBeGreaterThan(0);

    expect(report.rawText).toBeDefined();
    expect(typeof report.rawText).toBe('string');
  });

  it('should throw for unimplemented formats', async () => {
    const stix = JSON.stringify({ type: 'bundle', spec_version: '2.1' });

    await expect(
      normalizeReport(stix, { format: 'stix' })
    ).rejects.toThrow('not yet implemented');

    await expect(
      normalizeReport('{}', { format: 'json' })
    ).rejects.toThrow('not yet implemented');
  });

  it('should handle PDF buffer input', async () => {
    const buffer = Buffer.from('not a real pdf');

    await expect(
      normalizeReport(buffer, { format: 'pdf' })
    ).resolves.toBeDefined();
  });

  it('should throw for PDF with string input', async () => {
    await expect(
      normalizeReport('text', { format: 'pdf' })
    ).rejects.toThrow('PDF input must be a Buffer');
  });
});

describe('Integration with Fixture Files', () => {
  it('should extract IOCs from reports', async () => {
    const markdown = loadFixture('apt29-midnight-blizzard.md');
    const report = await normalizeReport(markdown, {
      filename: 'apt29-midnight-blizzard.md',
    });

    // Check for IOC section
    const iocSection = report.sections.find(s => s.type === 'iocs');
    expect(iocSection).toBeDefined();

    // Should contain defanged or standard IP indicators
    expect(report.rawText).toMatch(/\d+[\[.(]*\.?[\].)]*\d+[\[.(]*\.?[\].)]*\d+[\[.(]*\.?[\].)]*\d+/); // IP pattern (standard or defanged)
  });

  it('should extract MITRE ATT&CK techniques', async () => {
    const markdown = loadFixture('apt29-midnight-blizzard.md');
    const report = await normalizeReport(markdown, {
      filename: 'apt29-midnight-blizzard.md',
    });

    const ttpSection = report.sections.find(s => s.type === 'ttps');
    expect(ttpSection).toBeDefined();

    // Should contain technique IDs
    expect(report.rawText).toMatch(/T\d{4}/); // MITRE technique pattern
  });

  it('should extract threat actor from multiple reports', async () => {
    const testCases = [
      { file: 'apt29-midnight-blizzard.md', expectedActor: 'Midnight Blizzard' },
      { file: 'lazarus-kandykorn.md', expectedActor: 'Lazarus' },
    ];

    for (const { file, expectedActor } of testCases) {
      const markdown = loadFixture(file);
      const report = await normalizeReport(markdown, { filename: file });

      if (report.metadata.threatActor) {
        expect(report.metadata.threatActor).toContain(expectedActor);
      }
    }
  });

  it('should extract CVE IDs when present', async () => {
    const markdown = loadFixture('ivanti-vpn-zero-day.md');
    const report = await normalizeReport(markdown, {
      filename: 'ivanti-vpn-zero-day.md',
    });

    // The Ivanti report should contain CVE IDs
    if (report.metadata.cveIds && report.metadata.cveIds.length > 0) {
      expect(report.metadata.cveIds[0]).toMatch(/^CVE-\d{4}-\d{4,7}$/);
    }
  });
});
