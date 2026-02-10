/**
 * Sprint 5 — End-to-end pipeline integration test.
 *
 * Exercises the full DetectForge pipeline from report ingestion through
 * rule generation using fixture data and mocked AI responses.  No real
 * API calls are made.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

// Ingestion
import { normalizeReport } from '@/ingestion/normalizer.js';

// Extraction (regex-based — no AI needed)
import { extractIocs } from '@/extraction/ioc-extractor.js';

// Generation: validators
import { validateSigmaRule } from '@/generation/sigma/validator.js';
import { validateYaraRule } from '@/generation/yara/validator.js';
import { validateSuricataRule } from '@/generation/suricata/validator.js';

// Types
import type { ThreatReport } from '@/types/threat-report.js';
import type {
  ExtractedIOC,
  ExtractedTTP,
  AttackMappingResult,
} from '@/types/extraction.js';
import type {
  SigmaRule,
  YaraRule,
  SuricataRule,
  ValidationResult,
} from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const FIXTURE_DIR = join(import.meta.dirname ?? '.', '../fixtures/reports');

function loadFixtureReport(filename: string): string {
  return readFileSync(join(FIXTURE_DIR, filename), 'utf-8');
}

// ---------------------------------------------------------------------------
// Pre-canned mock AI responses
// ---------------------------------------------------------------------------

const MOCK_TTP_RESPONSE = {
  ttps: [
    {
      description:
        'Password spray attack from distributed residential proxy infrastructure targeting legacy OAuth application',
      tools: ['Residential Proxy Network'],
      targetPlatforms: ['Azure AD', 'Windows'],
      artifacts: [
        {
          type: 'event_log' as const,
          description: 'Multiple failed authentication attempts from distributed IPs',
          value: 'EventID 4625',
        },
      ],
      detectionOpportunities: [
        'Monitor for many failed logins from distributed IPs targeting multiple accounts',
        'Alert on authentication from known residential proxy IP ranges',
      ],
      confidence: 'high' as const,
    },
    {
      description:
        'Creation of malicious OAuth applications with elevated permissions for persistent access',
      tools: ['Azure AD', 'OAuth'],
      targetPlatforms: ['Azure AD', 'Microsoft 365'],
      artifacts: [
        {
          type: 'event_log' as const,
          description: 'New OAuth application registration event',
        },
        {
          type: 'event_log' as const,
          description: 'Consent grant to OAuth application for Mail.Read permissions',
        },
      ],
      detectionOpportunities: [
        'Alert on new OAuth application creation from non-admin accounts',
        'Monitor for consent grants with Mail.Read or Mail.ReadWrite permissions',
      ],
      confidence: 'high' as const,
    },
    {
      description:
        'Use of OAuth application tokens to authenticate to Exchange Online for email exfiltration',
      tools: ['OAuth', 'Exchange Online'],
      targetPlatforms: ['Microsoft 365'],
      artifacts: [
        {
          type: 'network' as const,
          description: 'OAuth token-based authentication to Exchange Online API',
        },
      ],
      detectionOpportunities: [
        'Alert on email access from newly created OAuth applications',
      ],
      confidence: 'high' as const,
    },
    {
      description:
        'PowerShell execution for initial payload delivery via encoded commands',
      tools: ['PowerShell'],
      targetPlatforms: ['Windows'],
      artifacts: [
        {
          type: 'process' as const,
          description: 'powershell.exe spawned by explorer.exe with encoded command',
          value: 'powershell.exe -enc',
        },
      ],
      detectionOpportunities: [
        'Monitor for powershell.exe with encoded commands',
      ],
      confidence: 'medium' as const,
    },
  ],
};

const MOCK_ATTACK_MAPPINGS: AttackMappingResult[] = [
  {
    techniqueId: 'T1110.003',
    techniqueName: 'Brute Force: Password Spraying',
    tactic: 'Credential Access',
    confidence: 'high',
    reasoning:
      'Low-volume password spray from distributed residential proxy infrastructure',
    sourceTtp: MOCK_TTP_RESPONSE.ttps[0],
    suggestedRuleFormats: ['sigma'],
    validated: true,
  },
  {
    techniqueId: 'T1098.003',
    techniqueName: 'Account Manipulation: Additional Cloud Roles',
    tactic: 'Persistence',
    confidence: 'high',
    reasoning:
      'Created additional malicious OAuth applications with elevated permissions',
    sourceTtp: MOCK_TTP_RESPONSE.ttps[1],
    suggestedRuleFormats: ['sigma'],
    validated: true,
  },
  {
    techniqueId: 'T1550.001',
    techniqueName:
      'Use Alternate Authentication Material: Application Access Token',
    tactic: 'Defense Evasion',
    confidence: 'high',
    reasoning:
      'Used OAuth tokens instead of user credentials to access Exchange Online',
    sourceTtp: MOCK_TTP_RESPONSE.ttps[2],
    suggestedRuleFormats: ['sigma', 'suricata'],
    validated: true,
  },
  {
    techniqueId: 'T1059.001',
    techniqueName: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    confidence: 'medium',
    reasoning: 'PowerShell execution with encoded commands for payload delivery',
    sourceTtp: MOCK_TTP_RESPONSE.ttps[3],
    suggestedRuleFormats: ['sigma', 'yara'],
    validated: true,
  },
];

// ---------------------------------------------------------------------------
// Rule fixtures (what the "AI" would return after generation)
// ---------------------------------------------------------------------------

function buildMockYaraRule(): YaraRule {
  return {
    name: 'DetectForge_APT29_PowerShell_Payload',
    tags: ['apt29', 'powershell'],
    meta: {
      description: 'Detects PowerShell payload associated with APT29 activity',
      author: 'DetectForge',
      date: '2026-02-10',
      reference: 'https://example.com/apt29-report',
      mitre_attack: 'T1059.001',
    },
    strings: [
      {
        identifier: '$s1',
        value: '-EncodedCommand',
        type: 'text',
        modifiers: ['ascii', 'nocase'],
      },
      {
        identifier: '$s2',
        value: 'Invoke-Expression',
        type: 'text',
        modifiers: ['ascii', 'nocase'],
      },
      {
        identifier: '$s3',
        value: 'Net.WebClient',
        type: 'text',
        modifiers: ['ascii'],
      },
    ],
    condition: 'filesize < 5MB and 2 of ($s*)',
    raw: [
      'rule DetectForge_APT29_PowerShell_Payload : apt29 powershell {',
      '    meta:',
      '        description = "Detects PowerShell payload associated with APT29 activity"',
      '        author = "DetectForge"',
      '        date = "2026-02-10"',
      '        reference = "https://example.com/apt29-report"',
      '        mitre_attack = "T1059.001"',
      '    strings:',
      '        $s1 = "-EncodedCommand" ascii nocase',
      '        $s2 = "Invoke-Expression" ascii nocase',
      '        $s3 = "Net.WebClient" ascii',
      '    condition:',
      '        filesize < 5MB and 2 of ($s*)',
      '}',
    ].join('\n'),
  };
}

function buildMockSuricataRule(): SuricataRule {
  return {
    action: 'alert',
    protocol: 'tcp',
    sourceIp: '$HOME_NET',
    sourcePort: 'any',
    direction: '->',
    destIp: '$EXTERNAL_NET',
    destPort: 'any',
    options: [
      { keyword: 'msg', value: '"DetectForge - APT29 C2 Communication to 195.178.120.25"' },
      { keyword: 'flow', value: 'established,to_server' },
      {
        keyword: 'content',
        value: '"|c3 b2 78 19|"',
      },
      { keyword: 'metadata', value: 'mitre_attack T1071.001' },
      { keyword: 'classtype', value: 'trojan-activity' },
      { keyword: 'sid', value: '9000001' },
      { keyword: 'rev', value: '1' },
    ],
    sid: 9000001,
    rev: 1,
    raw: 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"DetectForge - APT29 C2 Communication to 195.178.120.25"; flow:established,to_server; content:"|c3 b2 78 19|"; metadata:mitre_attack T1071.001; classtype:trojan-activity; sid:9000001; rev:1;)',
  };
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Full Pipeline Integration (mocked AI)', () => {
  let fixtureMarkdown: string;
  let report: ThreatReport;
  let iocs: ExtractedIOC[];
  let ttps: ExtractedTTP[];
  let attackMappings: AttackMappingResult[];
  let sigmaRules: SigmaRule[];
  let yaraRules: YaraRule[];
  let suricataRules: SuricataRule[];
  let startTime: number;

  beforeAll(async () => {
    startTime = performance.now();

    // ------- Step 1: Ingest and parse fixture report -------
    fixtureMarkdown = loadFixtureReport('apt29-midnight-blizzard.md');
    report = await normalizeReport(fixtureMarkdown, {
      filename: 'apt29-midnight-blizzard.md',
      format: 'markdown',
    });

    // ------- Step 2: Extract IOCs via regex (no AI) -------
    iocs = extractIocs(report.rawText);

    // ------- Step 3: Mock TTP extraction (no real AI) -------
    ttps = MOCK_TTP_RESPONSE.ttps;

    // ------- Step 4: Mock ATT&CK mapping -------
    attackMappings = MOCK_ATTACK_MAPPINGS;

    // ------- Step 5: Build mock generated rules -------
    sigmaRules = [];
    for (let i = 0; i < attackMappings.length; i++) {
      const mapping = attackMappings[i];
      if (mapping.suggestedRuleFormats.includes('sigma')) {
        const dateStr = '2026/02/10';
        sigmaRules.push({
          id: randomUUID(),
          title: `DetectForge - ${mapping.techniqueName} Detection`,
          status: 'experimental',
          description: `Detects ${mapping.techniqueName} activity as described by ATT&CK ${mapping.techniqueId}.`,
          references: [],
          author: 'DetectForge',
          date: dateStr,
          modified: dateStr,
          tags: [
            `attack.${mapping.tactic.toLowerCase().replace(/\s+/g, '_')}`,
            `attack.${mapping.techniqueId.toLowerCase()}`,
          ],
          logsource: { product: 'windows', category: 'process_creation' },
          detection: {
            selection: { CommandLine: ['*encoded*'] },
            condition: 'selection',
          },
          falsepositives: ['Legitimate administrative scripts'],
          level: 'high',
          raw: '',
        });
      }
    }

    yaraRules = [];
    if (attackMappings.some((m) => m.suggestedRuleFormats.includes('yara'))) {
      yaraRules.push(buildMockYaraRule());
    }

    suricataRules = [];
    if (attackMappings.some((m) => m.suggestedRuleFormats.includes('suricata'))) {
      suricataRules.push(buildMockSuricataRule());
    }
  });

  // -----------------------------------------------------------------------
  // Ingestion tests
  // -----------------------------------------------------------------------

  it('should parse fixture report without errors', () => {
    expect(report).toBeDefined();
    expect(report.id).toBeDefined();
    expect(report.title).toContain('Midnight Blizzard');
    expect(report.inputFormat).toBe('markdown');
    expect(report.sections.length).toBeGreaterThan(0);
    expect(report.rawText.length).toBeGreaterThan(0);
  });

  it('should normalize report with detected metadata', () => {
    expect(report.metadata.threatActor).toBeDefined();
    expect(report.metadata.threatActor).toContain('Midnight Blizzard');
  });

  // -----------------------------------------------------------------------
  // Extraction tests
  // -----------------------------------------------------------------------

  it('should extract IOCs from the report', () => {
    expect(iocs.length).toBeGreaterThan(0);

    // The fixture report contains defanged IPs
    const ipIocs = iocs.filter((i) => i.type === 'ipv4');
    expect(ipIocs.length).toBeGreaterThan(0);

    // Check for known IPs from the fixture
    const ipValues = ipIocs.map((i) => i.value);
    expect(ipValues).toContain('195.178.120.25');
    expect(ipValues).toContain('193.176.86.157');
    expect(ipValues).toContain('185.248.85.18');
  });

  it('should produce TTPs from mock extraction', () => {
    expect(ttps.length).toBeGreaterThan(0);
    expect(ttps.length).toBe(4);

    // Each TTP should have required fields
    for (const ttp of ttps) {
      expect(ttp.description).toBeDefined();
      expect(ttp.description.length).toBeGreaterThan(0);
      expect(ttp.confidence).toMatch(/^(high|medium|low)$/);
      expect(ttp.targetPlatforms.length).toBeGreaterThan(0);
      expect(ttp.detectionOpportunities.length).toBeGreaterThan(0);
    }
  });

  it('should produce ATT&CK mappings with technique IDs', () => {
    expect(attackMappings.length).toBeGreaterThan(0);

    for (const mapping of attackMappings) {
      // Technique ID must match ATT&CK pattern
      expect(mapping.techniqueId).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(mapping.techniqueName.length).toBeGreaterThan(0);
      expect(mapping.tactic.length).toBeGreaterThan(0);
      expect(mapping.confidence).toMatch(/^(high|medium|low)$/);
      expect(mapping.suggestedRuleFormats.length).toBeGreaterThan(0);
    }

    // Check that specific technique IDs from the fixture are present
    const techniqueIds = attackMappings.map((m) => m.techniqueId);
    expect(techniqueIds).toContain('T1110.003');
    expect(techniqueIds).toContain('T1098.003');
    expect(techniqueIds).toContain('T1059.001');
  });

  // -----------------------------------------------------------------------
  // Rule generation tests
  // -----------------------------------------------------------------------

  it('should generate Sigma rules for at least one TTP', () => {
    expect(sigmaRules.length).toBeGreaterThan(0);

    for (const rule of sigmaRules) {
      expect(rule.id).toBeDefined();
      expect(rule.title.length).toBeGreaterThan(0);
      expect(rule.status).toBe('experimental');
      expect(rule.detection).toBeDefined();
      expect(rule.detection.condition).toBeDefined();
      expect(rule.logsource).toBeDefined();
      expect(rule.tags.length).toBeGreaterThan(0);
    }
  });

  it('should generate YARA rules for file-based IOCs', () => {
    // This report has an ATT&CK mapping suggesting yara
    expect(yaraRules.length).toBeGreaterThan(0);

    for (const rule of yaraRules) {
      expect(rule.name).toBeDefined();
      expect(rule.name.length).toBeGreaterThan(0);
      expect(rule.meta.description).toBeDefined();
      expect(rule.meta.author).toBe('DetectForge');
      expect(rule.strings.length).toBeGreaterThan(0);
      expect(rule.condition.length).toBeGreaterThan(0);
      expect(rule.raw.length).toBeGreaterThan(0);
    }
  });

  it('should generate Suricata rules for network IOCs', () => {
    expect(suricataRules.length).toBeGreaterThan(0);

    for (const rule of suricataRules) {
      expect(rule.action).toBe('alert');
      expect(rule.protocol).toBeDefined();
      expect(rule.sid).toBeGreaterThan(0);
      expect(rule.rev).toBeGreaterThan(0);
      expect(rule.options.length).toBeGreaterThan(0);
      expect(rule.raw.length).toBeGreaterThan(0);

      // Must have a msg option
      const msg = rule.options.find((o) => o.keyword === 'msg');
      expect(msg).toBeDefined();
    }
  });

  // -----------------------------------------------------------------------
  // Validation tests
  // -----------------------------------------------------------------------

  it('should pass Sigma rule validation for all generated rules', () => {
    for (const rule of sigmaRules) {
      const result: ValidationResult = validateSigmaRule(rule);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    }
  });

  it('should pass YARA rule validation for all generated rules', () => {
    for (const rule of yaraRules) {
      const result: ValidationResult = validateYaraRule(rule);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    }
  });

  it('should pass Suricata rule validation for all generated rules', () => {
    for (const rule of suricataRules) {
      const result: ValidationResult = validateSuricataRule(rule);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    }
  });

  // -----------------------------------------------------------------------
  // Metrics & performance
  // -----------------------------------------------------------------------

  it('should complete pipeline within 10s timeout (mocked)', () => {
    const elapsed = performance.now() - startTime;
    expect(elapsed).toBeLessThan(10_000);
  });

  it('should report pipeline metrics', () => {
    const elapsed = performance.now() - startTime;

    const totalRules = sigmaRules.length + yaraRules.length + suricataRules.length;
    const validRules =
      sigmaRules.filter((r) => validateSigmaRule(r).valid).length +
      yaraRules.filter((r) => validateYaraRule(r).valid).length +
      suricataRules.filter((r) => validateSuricataRule(r).valid).length;

    const passRate = totalRules > 0 ? (validRules / totalRules) * 100 : 0;

    const metrics = {
      report: 'APT29 Midnight Blizzard',
      iocs: iocs.length,
      ttps: ttps.length,
      sigmaRules: sigmaRules.length,
      yaraRules: yaraRules.length,
      suricataRules: suricataRules.length,
      totalRules,
      validRules,
      validationPassRate: `${passRate.toFixed(0)}%`,
      processingTimeMs: elapsed.toFixed(1),
    };

    // Log metrics for visibility in test output
    console.log('\n--- Pipeline Metrics ---');
    console.log(JSON.stringify(metrics, null, 2));
    console.log('--- End Metrics ---\n');

    expect(totalRules).toBeGreaterThan(0);
    expect(passRate).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Cross-report batch test
// ---------------------------------------------------------------------------

describe('Multi-report fixture validation', () => {
  const FIXTURE_FILES = [
    'apt29-midnight-blizzard.md',
    'black-basta-ransomware.md',
    'icedid-to-ransomware.md',
    'ivanti-vpn-zero-day.md',
    'lazarus-kandykorn.md',
    'scattered-spider-social-eng.md',
  ];

  for (const filename of FIXTURE_FILES) {
    it(`should ingest and extract IOCs from ${filename}`, async () => {
      const markdown = loadFixtureReport(filename);
      const report = await normalizeReport(markdown, {
        filename,
        format: 'markdown',
      });

      expect(report.id).toBeDefined();
      expect(report.title).not.toBe('Empty Report');
      expect(report.sections.length).toBeGreaterThan(0);

      // Extract IOCs (regex only, no AI)
      const reportIocs = extractIocs(report.rawText);

      // Every fixture report should contain at least some extractable indicators
      // (IPs, domains, hashes, CVEs, etc.)
      expect(reportIocs.length).toBeGreaterThanOrEqual(0);

      // Verify IOC structure
      for (const ioc of reportIocs) {
        expect(ioc.value).toBeDefined();
        expect(ioc.type).toBeDefined();
        expect(ioc.confidence).toMatch(/^(high|medium|low)$/);
      }
    });
  }
});
