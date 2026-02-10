/**
 * Unit tests for integration test helper functions and synthetic
 * log generation utilities.
 *
 * Validates that:
 * - Mock data factories produce structurally valid output
 * - Synthetic logs conform to the expected Sigma field schemas
 * - Log datasets cover all Sigma template categories
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';

// Templates
import { getAllTemplates } from '@/generation/sigma/templates.js';

// Validators
import { validateSigmaRule } from '@/generation/sigma/validator.js';
import { validateYaraRule } from '@/generation/yara/validator.js';
import { validateSuricataRule } from '@/generation/suricata/validator.js';

// Sigma tester
import { evaluateSigmaRule } from '@/testing/sigma-tester.js';
import type { LogEntry } from '@/testing/sigma-tester.js';

// Types
import type {
  SigmaRule,
  YaraRule,
  SuricataRule,
} from '@/types/detection-rule.js';
import type {
  ExtractedTTP,
  AttackMappingResult,
} from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Mock data factory helpers (mirrored from scripts)
// ---------------------------------------------------------------------------

function buildMockTtp(overrides?: Partial<ExtractedTTP>): ExtractedTTP {
  return {
    description: 'PowerShell execution with encoded command for payload delivery',
    tools: ['PowerShell'],
    targetPlatforms: ['Windows'],
    artifacts: [
      {
        type: 'process',
        description: 'powershell.exe spawned with encoded command',
        value: 'powershell.exe -enc',
      },
    ],
    detectionOpportunities: [
      'Monitor for powershell.exe with -enc or -encodedcommand flags',
    ],
    confidence: 'high',
    ...overrides,
  };
}

function buildMockAttackMapping(
  ttp: ExtractedTTP,
  overrides?: Partial<AttackMappingResult>,
): AttackMappingResult {
  return {
    techniqueId: 'T1059.001',
    techniqueName: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    confidence: 'high',
    reasoning: 'PowerShell used with encoded commands',
    sourceTtp: ttp,
    suggestedRuleFormats: ['sigma', 'yara'],
    validated: true,
    ...overrides,
  };
}

function buildMockSigmaRule(
  mapping: AttackMappingResult,
): SigmaRule {
  return {
    id: randomUUID(),
    title: `DetectForge - ${mapping.techniqueName} Detection`,
    status: 'experimental',
    description: `Detects ${mapping.techniqueName} (${mapping.techniqueId}).`,
    references: [],
    author: 'DetectForge',
    date: '2026/02/10',
    modified: '2026/02/10',
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
  };
}

function buildMockYaraRule(): YaraRule {
  return {
    name: 'Test_YARA_Rule',
    tags: ['test'],
    meta: {
      description: 'Test YARA rule for validation',
      author: 'DetectForge',
      date: '2026-02-10',
      reference: 'https://detectforge.local/test',
      mitre_attack: 'T1059.001',
    },
    strings: [
      { identifier: '$s1', value: 'test_string', type: 'text', modifiers: ['ascii'] },
    ],
    condition: 'any of ($s*)',
    raw: [
      'rule Test_YARA_Rule : test {',
      '    meta:',
      '        description = "Test YARA rule for validation"',
      '        author = "DetectForge"',
      '        date = "2026-02-10"',
      '        reference = "https://detectforge.local/test"',
      '        mitre_attack = "T1059.001"',
      '    strings:',
      '        $s1 = "test_string" ascii',
      '    condition:',
      '        any of ($s*)',
      '}',
    ].join('\n'),
  };
}

function buildMockSuricataRule(sid: number = 9000001): SuricataRule {
  const msg = '"DetectForge - Test C2 Communication"';
  return {
    action: 'alert',
    protocol: 'tcp',
    sourceIp: '$HOME_NET',
    sourcePort: 'any',
    direction: '->',
    destIp: '$EXTERNAL_NET',
    destPort: 'any',
    options: [
      { keyword: 'msg', value: msg },
      { keyword: 'flow', value: 'established,to_server' },
      { keyword: 'content', value: '"test_content"' },
      { keyword: 'metadata', value: 'mitre_attack T1071.001' },
      { keyword: 'classtype', value: 'trojan-activity' },
      { keyword: 'sid', value: String(sid) },
      { keyword: 'rev', value: '1' },
    ],
    sid,
    rev: 1,
    raw: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:${msg}; flow:established,to_server; content:"test_content"; metadata:mitre_attack T1071.001; classtype:trojan-activity; sid:${sid}; rev:1;)`,
  };
}

// ---------------------------------------------------------------------------
// Tests: Mock data factory structural validity
// ---------------------------------------------------------------------------

describe('Mock TTP factory', () => {
  it('should produce a structurally valid TTP', () => {
    const ttp = buildMockTtp();

    expect(ttp.description).toBeDefined();
    expect(ttp.description.length).toBeGreaterThan(10);
    expect(ttp.tools).toBeInstanceOf(Array);
    expect(ttp.tools.length).toBeGreaterThan(0);
    expect(ttp.targetPlatforms.length).toBeGreaterThan(0);
    expect(ttp.artifacts.length).toBeGreaterThan(0);
    expect(ttp.detectionOpportunities.length).toBeGreaterThan(0);
    expect(ttp.confidence).toMatch(/^(high|medium|low)$/);
  });

  it('should accept overrides', () => {
    const ttp = buildMockTtp({
      description: 'Custom description',
      confidence: 'low',
    });

    expect(ttp.description).toBe('Custom description');
    expect(ttp.confidence).toBe('low');
  });
});

describe('Mock ATT&CK mapping factory', () => {
  it('should produce a valid mapping', () => {
    const ttp = buildMockTtp();
    const mapping = buildMockAttackMapping(ttp);

    expect(mapping.techniqueId).toMatch(/^T\d{4}(\.\d{3})?$/);
    expect(mapping.techniqueName.length).toBeGreaterThan(0);
    expect(mapping.tactic.length).toBeGreaterThan(0);
    expect(mapping.confidence).toMatch(/^(high|medium|low)$/);
    expect(mapping.suggestedRuleFormats.length).toBeGreaterThan(0);
    expect(mapping.sourceTtp).toBe(ttp);
  });

  it('should accept overrides', () => {
    const ttp = buildMockTtp();
    const mapping = buildMockAttackMapping(ttp, {
      techniqueId: 'T1110.003',
      tactic: 'Credential Access',
    });

    expect(mapping.techniqueId).toBe('T1110.003');
    expect(mapping.tactic).toBe('Credential Access');
  });
});

// ---------------------------------------------------------------------------
// Tests: Mock rule validation
// ---------------------------------------------------------------------------

describe('Mock Sigma rule factory', () => {
  it('should produce a rule that passes validation', () => {
    const ttp = buildMockTtp();
    const mapping = buildMockAttackMapping(ttp);
    const rule = buildMockSigmaRule(mapping);

    const result = validateSigmaRule(rule);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should contain ATT&CK tags', () => {
    const ttp = buildMockTtp();
    const mapping = buildMockAttackMapping(ttp);
    const rule = buildMockSigmaRule(mapping);

    expect(rule.tags.length).toBeGreaterThan(0);
    expect(rule.tags.some((t) => t.startsWith('attack.'))).toBe(true);
  });
});

describe('Mock YARA rule factory', () => {
  it('should produce a rule that passes validation', () => {
    const rule = buildMockYaraRule();
    const result = validateYaraRule(rule);

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});

describe('Mock Suricata rule factory', () => {
  it('should produce a rule that passes validation', () => {
    const rule = buildMockSuricataRule();
    const result = validateSuricataRule(rule);

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should support custom SID', () => {
    const rule = buildMockSuricataRule(9000099);

    expect(rule.sid).toBe(9000099);
    const sidOpt = rule.options.find((o) => o.keyword === 'sid');
    expect(sidOpt?.value).toBe('9000099');
  });
});

// ---------------------------------------------------------------------------
// Tests: Sigma template coverage for log generation
// ---------------------------------------------------------------------------

describe('Sigma template catalog', () => {
  it('should have templates for all common categories', () => {
    const expectedCategories = [
      'process_creation',
      'image_load',
      'file_event',
      'registry_event',
      'network_connection',
      'dns_query',
      'pipe_created',
      'wmi_event',
      'ps_script',
      'security',
    ];

    const allTemplates = getAllTemplates();
    const availableCategories = allTemplates.map((t) => t.category);

    for (const category of expectedCategories) {
      expect(availableCategories).toContain(category);
    }
  });

  it('should have availableFields defined for every template', () => {
    const templates = getAllTemplates();

    for (const template of templates) {
      expect(template.availableFields.length).toBeGreaterThan(0);
      expect(template.logsource.product).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// Tests: Sigma rule evaluation against synthetic logs
// ---------------------------------------------------------------------------

describe('Sigma rule evaluation with synthetic logs', () => {
  it('should match a process creation rule against attack log', () => {
    const rule: SigmaRule = {
      id: randomUUID(),
      title: 'Test - Encoded PowerShell',
      status: 'experimental',
      description: 'Detects encoded PowerShell execution',
      references: [],
      author: 'Test',
      date: '2026/02/10',
      modified: '2026/02/10',
      tags: ['attack.execution', 'attack.t1059.001'],
      logsource: { product: 'windows', category: 'process_creation' },
      detection: {
        selection: {
          Image: ['*\\powershell.exe', '*\\pwsh.exe'],
          'CommandLine|contains': ['-encodedcommand', '-enc'],
        },
        condition: 'selection',
      },
      falsepositives: ['Admin scripts'],
      level: 'high',
      raw: '',
    };

    const attackLog: LogEntry = {
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      CommandLine: 'powershell.exe -nop -w hidden -encodedcommand JABzAD0A',
      ParentImage: 'C:\\Windows\\explorer.exe',
      User: 'CORP\\jdoe',
    };

    const benignLog: LogEntry = {
      Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      CommandLine: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
      ParentImage: 'C:\\Windows\\explorer.exe',
      User: 'CORP\\user1',
    };

    const attackResult = evaluateSigmaRule(rule, attackLog);
    expect(attackResult.matched).toBe(true);

    const benignResult = evaluateSigmaRule(rule, benignLog);
    expect(benignResult.matched).toBe(false);
  });

  it('should match a DNS query rule against attack log', () => {
    const rule: SigmaRule = {
      id: randomUUID(),
      title: 'Test - Malicious DNS Query',
      status: 'experimental',
      description: 'Detects DNS query to known malicious domain',
      references: [],
      author: 'Test',
      date: '2026/02/10',
      modified: '2026/02/10',
      tags: ['attack.command_and_control'],
      logsource: { product: 'windows', category: 'dns_query' },
      detection: {
        selection: {
          QueryName: ['*evil.example.com'],
        },
        condition: 'selection',
      },
      falsepositives: [],
      level: 'high',
      raw: '',
    };

    const attackLog: LogEntry = {
      Image: 'C:\\Users\\Public\\beacon.exe',
      QueryName: 'c2.evil.example.com',
      QueryStatus: '0',
    };

    const benignLog: LogEntry = {
      Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      QueryName: 'www.google.com',
      QueryStatus: '0',
    };

    expect(evaluateSigmaRule(rule, attackLog).matched).toBe(true);
    expect(evaluateSigmaRule(rule, benignLog).matched).toBe(false);
  });

  it('should handle selection with filter in condition', () => {
    const rule: SigmaRule = {
      id: randomUUID(),
      title: 'Test - Network Connection with Filter',
      status: 'experimental',
      description: 'Detects suspicious outbound connections excluding browsers',
      references: [],
      author: 'Test',
      date: '2026/02/10',
      modified: '2026/02/10',
      tags: ['attack.command_and_control'],
      logsource: { product: 'windows', category: 'network_connection' },
      detection: {
        selection: {
          Initiated: [true],
          DestinationPort: [4444, 5555, 8888],
        },
        filter_browsers: {
          Image: ['*\\chrome.exe', '*\\firefox.exe', '*\\msedge.exe'],
        },
        condition: 'selection and not filter_browsers',
      },
      falsepositives: [],
      level: 'high',
      raw: '',
    };

    const attackLog: LogEntry = {
      Image: 'C:\\Users\\Public\\svchost.exe',
      Initiated: true,
      DestinationPort: 4444,
      DestinationIp: '198.51.100.42',
    };

    const benignLog: LogEntry = {
      Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      Initiated: true,
      DestinationPort: 4444,
      DestinationIp: '142.250.80.100',
    };

    expect(evaluateSigmaRule(rule, attackLog).matched).toBe(true);
    expect(evaluateSigmaRule(rule, benignLog).matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tests: Edge cases in mock data
// ---------------------------------------------------------------------------

describe('Mock data edge cases', () => {
  it('should produce unique Sigma rule IDs', () => {
    const ttp = buildMockTtp();
    const mapping = buildMockAttackMapping(ttp);

    const rule1 = buildMockSigmaRule(mapping);
    const rule2 = buildMockSigmaRule(mapping);

    expect(rule1.id).not.toBe(rule2.id);
  });

  it('should produce unique Suricata SIDs', () => {
    const rule1 = buildMockSuricataRule(9000001);
    const rule2 = buildMockSuricataRule(9000002);

    expect(rule1.sid).not.toBe(rule2.sid);
  });

  it('should handle TTP with empty tools array', () => {
    const ttp = buildMockTtp({ tools: [] });

    expect(ttp.tools).toHaveLength(0);
    expect(ttp.description.length).toBeGreaterThan(0);
  });

  it('should handle TTP with multiple platforms', () => {
    const ttp = buildMockTtp({
      targetPlatforms: ['Windows', 'Linux', 'macOS'],
    });

    expect(ttp.targetPlatforms).toHaveLength(3);
    expect(ttp.targetPlatforms).toContain('Linux');
  });
});
