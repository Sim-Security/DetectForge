/**
 * Tests for ingestion parsers (PDF, HTML, Markdown, Plaintext)
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parsePdf } from '@/ingestion/parsers/pdf.js';
import { parseHtml } from '@/ingestion/parsers/html.js';
import { parseMarkdown } from '@/ingestion/parsers/markdown.js';
import { parsePlaintext } from '@/ingestion/parsers/plaintext.js';

// Helper to load fixture files
const fixturesDir = join(import.meta.dirname ?? '.', '../../fixtures/reports');

function loadFixture(filename: string): string {
  return readFileSync(join(fixturesDir, filename), 'utf-8');
}

describe('Markdown Parser', () => {
  it('should parse markdown report with proper sections', () => {
    const markdown = loadFixture('apt29-midnight-blizzard.md');
    const report = parseMarkdown(markdown, 'apt29-midnight-blizzard.md');

    expect(report.id).toBeDefined();
    expect(report.title).toContain('Midnight Blizzard');
    expect(report.inputFormat).toBe('markdown');
    expect(report.sections.length).toBeGreaterThan(0);

    // Should have an overview section
    const overviewSection = report.sections.find(s => s.type === 'overview');
    expect(overviewSection).toBeDefined();

    // Should have technical details
    const techSection = report.sections.find(s => s.type === 'technical_details');
    expect(techSection).toBeDefined();

    // Should extract metadata
    expect(report.metadata.threatActor).toContain('Midnight Blizzard');
  });

  it('should parse all fixture markdown files', () => {
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
      const report = parseMarkdown(markdown, filename);

      expect(report.id).toBeDefined();
      expect(report.title).not.toBe('Empty Report');
      expect(report.sections.length).toBeGreaterThan(0);
      expect(report.rawText).toBeDefined();
      expect(report.inputFormat).toBe('markdown');
    }
  });

  it('should handle markdown with YAML frontmatter', () => {
    const markdown = `---
title: Test Report
date: 2024-01-01
threatActor: Test Actor
---

# Overview

This is a test report.`;

    const report = parseMarkdown(markdown);

    expect(report.title).toBe('Test Report');
    expect(report.metadata.threatActor).toBe('Test Actor');
    expect(report.date).toContain('2024-01-01');
  });

  it('should preserve code blocks', () => {
    const markdown = `# Technical Details

\`\`\`python
import os
os.system('ls')
\`\`\`

Regular text.`;

    const report = parseMarkdown(markdown);

    expect(report.sections.length).toBeGreaterThan(0);
    expect(report.rawText).toContain('```python');
  });

  it('should classify sections correctly', () => {
    const markdown = `# Overview
General information.

## Technical Details
Attack methodology.

## Indicators of Compromise
IP addresses and hashes.

## MITRE ATT&CK Mapping
Techniques used.

## Recommendations
Mitigation steps.`;

    const report = parseMarkdown(markdown);

    expect(report.sections).toHaveLength(5);
    expect(report.sections.find(s => s.type === 'overview')).toBeDefined();
    expect(report.sections.find(s => s.type === 'technical_details')).toBeDefined();
    expect(report.sections.find(s => s.type === 'iocs')).toBeDefined();
    expect(report.sections.find(s => s.type === 'ttps')).toBeDefined();
    expect(report.sections.find(s => s.type === 'recommendations')).toBeDefined();
  });

  it('should handle empty input gracefully', () => {
    const report = parseMarkdown('');

    expect(report.id).toBeDefined();
    expect(report.title).toBe('Empty Report');
    expect(report.sections).toEqual([]);
  });

  it('should handle single section without headings', () => {
    const markdown = 'This is just plain text without any headings.';
    const report = parseMarkdown(markdown);

    expect(report.sections).toHaveLength(1);
    expect(report.sections[0].heading).toBe('Content');
  });

  it('should extract CVE IDs from content', () => {
    const markdown = `# Vulnerability Report

This report covers CVE-2024-1234 and CVE-2024-5678.`;

    const report = parseMarkdown(markdown);

    expect(report.metadata.cveIds).toContain('CVE-2024-1234');
    expect(report.metadata.cveIds).toContain('CVE-2024-5678');
  });
});

describe('HTML Parser', () => {
  it('should parse HTML blog post', async () => {
    const html = `
<!DOCTYPE html>
<html>
<head>
  <title>APT Attack Report</title>
  <meta property="article:published_time" content="2024-01-15">
</head>
<body>
  <nav>Navigation links</nav>
  <article>
    <h1>APT Attack Report</h1>
    <h2>Overview</h2>
    <p>This is an overview of the attack.</p>
    <h2>Technical Details</h2>
    <p>Detailed analysis of the attack.</p>
    <h2>Indicators of Compromise</h2>
    <ul>
      <li>192.168.1.1</li>
      <li>malware.exe</li>
    </ul>
    <h2>Recommendations</h2>
    <p>Update your systems.</p>
  </article>
  <footer>Footer content</footer>
</body>
</html>`;

    const report = await parseHtml(html, 'http://example.com/report.html');

    expect(report.id).toBeDefined();
    expect(report.title).toContain('APT Attack');
    expect(report.inputFormat).toBe('html');
    expect(report.sections.length).toBeGreaterThan(0);

    // Should have removed nav and footer
    expect(report.rawText).not.toContain('Navigation links');
    expect(report.rawText).not.toContain('Footer content');

    // Should extract sections
    expect(report.sections.find(s => s.type === 'overview')).toBeDefined();
    expect(report.sections.find(s => s.type === 'technical_details')).toBeDefined();
    expect(report.sections.find(s => s.type === 'iocs')).toBeDefined();
    expect(report.sections.find(s => s.type === 'recommendations')).toBeDefined();
  });

  it('should handle HTML without article tag', async () => {
    const html = `
<html>
<body>
  <div class="content">
    <h1>Report Title</h1>
    <p>Content here.</p>
  </div>
</body>
</html>`;

    const report = await parseHtml(html);

    expect(report.id).toBeDefined();
    expect(report.sections.length).toBeGreaterThan(0);
  });

  it('should preserve lists in HTML', async () => {
    const html = `
<article>
  <h2>IOCs</h2>
  <ul>
    <li>192.168.1.1</li>
    <li>evil.com</li>
  </ul>
</article>`;

    const report = await parseHtml(html);

    expect(report.sections[0].content).toContain('192.168.1.1');
    expect(report.sections[0].content).toContain('evil.com');
  });

  it('should handle empty HTML gracefully', async () => {
    const report = await parseHtml('');

    expect(report.id).toBeDefined();
    expect(report.title).toBe('Empty Report');
    expect(report.sections).toEqual([]);
  });

  it('should extract metadata from meta tags', async () => {
    const html = `
<html>
<head>
  <meta property="og:title" content="Threat Report">
  <meta property="article:published_time" content="2024-01-15T10:00:00Z">
</head>
<body>
  <article>
    <p>Threat Actor: APT28</p>
    <p>CVE-2024-1234 was exploited.</p>
  </article>
</body>
</html>`;

    const report = await parseHtml(html);

    expect(report.metadata.threatActor).toContain('APT28');
    expect(report.metadata.cveIds).toContain('CVE-2024-1234');
    expect(report.date).toContain('2024-01-15');
  });
});

describe('Plaintext Parser', () => {
  it('should parse CISA-style advisory', () => {
    const text = `CYBERSECURITY ADVISORY

SUMMARY

A critical vulnerability has been discovered.

TECHNICAL DETAILS

The vulnerability allows remote code execution.

INDICATORS OF COMPROMISE

IP Addresses:
- 192.168.1.1
- 10.0.0.1

RECOMMENDED ACTIONS

1. Update systems immediately
2. Monitor for indicators`;

    const report = parsePlaintext(text);

    expect(report.id).toBeDefined();
    expect(report.inputFormat).toBe('plaintext');
    expect(report.sections.length).toBeGreaterThan(0);

    // Should classify sections correctly
    expect(report.sections.find(s => s.type === 'overview')).toBeDefined();
    expect(report.sections.find(s => s.type === 'technical_details')).toBeDefined();
    expect(report.sections.find(s => s.type === 'iocs')).toBeDefined();
    expect(report.sections.find(s => s.type === 'recommendations')).toBeDefined();
  });

  it('should parse numbered sections', () => {
    const text = `Threat Report

1. Overview
This is the overview section.

2. Technical Analysis
This is the technical section.

3. Mitigation
These are the recommendations.`;

    const report = parsePlaintext(text);

    expect(report.sections.length).toBeGreaterThan(2);
    expect(report.sections.find(s => s.type === 'overview')).toBeDefined();
    expect(report.sections.find(s => s.type === 'technical_details')).toBeDefined();
  });

  it('should parse underlined headings', () => {
    const text = `Threat Report

Overview
========

This is the overview.

Technical Details
-----------------

This is technical.`;

    const report = parsePlaintext(text);

    expect(report.sections.length).toBeGreaterThan(1);
    expect(report.sections.find(s => s.heading === 'Overview')).toBeDefined();
    expect(report.sections.find(s => s.heading === 'Technical Details')).toBeDefined();
  });

  it('should handle ALL CAPS headings', () => {
    const text = `THREAT INTELLIGENCE REPORT

EXECUTIVE SUMMARY

This is a summary.

TECHNICAL ANALYSIS

This is technical content.`;

    const report = parsePlaintext(text);

    expect(report.sections.length).toBeGreaterThan(1);
    expect(report.sections.find(s => s.type === 'overview')).toBeDefined();
  });

  it('should extract metadata from plaintext', () => {
    const text = `Threat Report
Date: January 15, 2024
Threat Actor: APT29

Overview:
CVE-2024-1234 was exploited.
Malware: CobaltStrike`;

    const report = parsePlaintext(text);

    expect(report.date).toContain('2024-01-15');
    expect(report.metadata.threatActor).toBe('APT29');
    expect(report.metadata.cveIds).toContain('CVE-2024-1234');
  });

  it('should handle empty input gracefully', () => {
    const report = parsePlaintext('');

    expect(report.id).toBeDefined();
    expect(report.title).toBe('Empty Report');
    expect(report.sections).toEqual([]);
  });

  it('should handle single paragraph without sections', () => {
    const text = 'This is just a paragraph of text without any structure.';
    const report = parsePlaintext(text);

    expect(report.sections).toHaveLength(1);
    expect(report.sections[0].heading).toBe('Content');
  });
});

describe('PDF Parser', () => {
  it('should handle empty buffer gracefully', async () => {
    const report = await parsePdf(Buffer.from(''));

    expect(report.id).toBeDefined();
    expect(report.title).toBe('Empty Report');
    expect(report.inputFormat).toBe('pdf');
  });

  it('should handle invalid PDF gracefully', async () => {
    const report = await parsePdf(Buffer.from('not a pdf'));

    expect(report.id).toBeDefined();
    expect(report.title).toBe('Empty Report');
  });

  // Note: Testing actual PDF parsing requires a valid PDF buffer
  // which would need pdf-parse to be fully functional. For now,
  // we test error handling and edge cases.
});

describe('Edge Cases', () => {
  it('should handle very long content', () => {
    const longContent = '# Title\n\n' + 'a'.repeat(100000);
    const report = parseMarkdown(longContent);

    expect(report.id).toBeDefined();
    expect(report.rawText.length).toBeGreaterThan(90000);
  });

  it('should handle special characters in headings', () => {
    const markdown = `# Title with "quotes" and 'apostrophes'

## Section with <brackets> and &ampersands

Content here.`;

    const report = parseMarkdown(markdown);

    expect(report.sections.length).toBe(2);
  });

  it('should handle defanged IOCs', () => {
    const text = `# IOCs

- 192.168.1[.]1
- evil[.]com
- hxxp://malware[.]com`;

    const report = parseMarkdown(text);

    expect(report.rawText).toContain('192.168.1[.]1');
    expect(report.rawText).toContain('evil[.]com');
  });

  it('should handle multiple consecutive blank lines', () => {
    const markdown = `# Title


Content with



multiple blanks.`;

    const report = parseMarkdown(markdown);

    expect(report.sections.length).toBeGreaterThan(0);
  });
});
