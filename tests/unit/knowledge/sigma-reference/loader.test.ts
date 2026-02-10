/**
 * Tests for SigmaHQ Reference Corpus loader.
 *
 * Uses inline mock YAML strings — no actual SigmaHQ files required.
 */

import { describe, it, expect } from 'vitest';
import {
  parseRuleYaml,
  SigmaReferenceCorpus,
  type SigmaReferenceRule,
} from '../../../../src/knowledge/sigma-reference/loader.js';

// ---------------------------------------------------------------------------
// Fixtures – inline YAML strings
// ---------------------------------------------------------------------------

const VALID_RULE_YAML = `
title: Suspicious PowerShell Download
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: test
description: Detects suspicious PowerShell download cradles
author: Test Author
date: 2024/01/01
tags:
  - attack.execution
  - attack.t1059.001
  - attack.command_and_control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'Invoke-WebRequest'
      - 'IWR'
      - 'wget'
      - 'curl'
    Image|endswith: '\\\\powershell.exe'
  condition: selection
falsepositives:
  - Legitimate admin scripts that download updates
  - Software deployment tools
level: high
`;

const VALID_RULE_LINUX_YAML = `
title: Suspicious Crontab Modification
id: 9a3d9c42-1b2e-4c3d-8e5f-6a7b8c9d0e1f
status: experimental
description: Detects modification of crontab files for persistence
author: Linux Analyst
date: 2024/02/01
tags:
  - attack.persistence
  - attack.t1053.003
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/crontab'
    CommandLine|contains: '-e'
  condition: selection
falsepositives:
  - Legitimate scheduled task creation by administrators
level: medium
`;

const MINIMAL_RULE_YAML = `
title: Minimal Detection Rule
detection:
  selection:
    FieldA: valueA
  condition: selection
`;

const CLOUD_RULE_YAML = `
title: AWS CloudTrail Logging Disabled
id: aabbccdd-1122-3344-5566-778899001122
status: stable
description: Detects when AWS CloudTrail logging is stopped
author: Cloud Security
date: 2024/03/01
tags:
  - attack.defense_evasion
  - attack.t1562.008
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: StopLogging
    eventSource: cloudtrail.amazonaws.com
  condition: selection
falsepositives:
  - Planned maintenance operations
level: critical
`;

const MALFORMED_YAML = `
this is not: valid yaml: [[[
  broken: {
`;

const EMPTY_YAML = '';

const NO_DETECTION_YAML = `
title: Rule without detection
description: This rule is missing the detection field
`;

// ---------------------------------------------------------------------------
// parseRuleYaml tests
// ---------------------------------------------------------------------------

describe('parseRuleYaml', () => {
  it('should parse a valid Sigma rule YAML', () => {
    const rule = parseRuleYaml(VALID_RULE_YAML, 'windows/process_creation/test.yml');
    expect(rule).toBeDefined();
    expect(rule!.title).toBe('Suspicious PowerShell Download');
    expect(rule!.id).toBe('3b6ab547-8ec2-4991-b9d2-2b06702a48d7');
    expect(rule!.status).toBe('test');
    expect(rule!.author).toBe('Test Author');
    expect(rule!.level).toBe('high');
    expect(rule!.filePath).toBe('windows/process_creation/test.yml');
  });

  it('should extract ATT&CK techniques from tags', () => {
    const rule = parseRuleYaml(VALID_RULE_YAML, 'test.yml');
    expect(rule).toBeDefined();
    expect(rule!.attackTechniques).toContain('T1059.001');
    expect(rule!.attackTechniques).toContain('T1105');
    expect(rule!.attackTechniques).toHaveLength(2);
  });

  it('should extract ATT&CK tactics from tags', () => {
    const rule = parseRuleYaml(VALID_RULE_YAML, 'test.yml');
    expect(rule).toBeDefined();
    expect(rule!.attackTactics).toContain('execution');
    expect(rule!.attackTactics).toContain('command_and_control');
    expect(rule!.attackTactics).toHaveLength(2);
  });

  it('should parse logsource correctly', () => {
    const rule = parseRuleYaml(VALID_RULE_YAML, 'test.yml');
    expect(rule).toBeDefined();
    expect(rule!.logsource.category).toBe('process_creation');
    expect(rule!.logsource.product).toBe('windows');
    expect(rule!.logsource.service).toBeUndefined();
  });

  it('should parse logsource with service field', () => {
    const rule = parseRuleYaml(CLOUD_RULE_YAML, 'test.yml');
    expect(rule).toBeDefined();
    expect(rule!.logsource.product).toBe('aws');
    expect(rule!.logsource.service).toBe('cloudtrail');
    expect(rule!.logsource.category).toBeUndefined();
  });

  it('should parse false positives', () => {
    const rule = parseRuleYaml(VALID_RULE_YAML, 'test.yml');
    expect(rule).toBeDefined();
    expect(rule!.falsepositives).toHaveLength(2);
    expect(rule!.falsepositives[0]).toContain('Legitimate admin scripts');
  });

  it('should parse detection block', () => {
    const rule = parseRuleYaml(VALID_RULE_YAML, 'test.yml');
    expect(rule).toBeDefined();
    expect(rule!.detection).toHaveProperty('selection');
    expect(rule!.detection).toHaveProperty('condition');
  });

  it('should preserve raw YAML in the rule', () => {
    const rule = parseRuleYaml(VALID_RULE_YAML, 'test.yml');
    expect(rule).toBeDefined();
    expect(rule!.rawYaml).toBe(VALID_RULE_YAML);
  });

  it('should parse a minimal rule with only title and detection', () => {
    const rule = parseRuleYaml(MINIMAL_RULE_YAML, 'minimal.yml');
    expect(rule).toBeDefined();
    expect(rule!.title).toBe('Minimal Detection Rule');
    expect(rule!.id).toBe('');
    expect(rule!.status).toBe('unknown');
    expect(rule!.attackTechniques).toHaveLength(0);
    expect(rule!.attackTactics).toHaveLength(0);
    expect(rule!.falsepositives).toHaveLength(0);
  });

  it('should return undefined for malformed YAML', () => {
    const rule = parseRuleYaml(MALFORMED_YAML, 'bad.yml');
    expect(rule).toBeUndefined();
  });

  it('should return undefined for empty YAML', () => {
    const rule = parseRuleYaml(EMPTY_YAML, 'empty.yml');
    expect(rule).toBeUndefined();
  });

  it('should return undefined for YAML missing detection field', () => {
    const rule = parseRuleYaml(NO_DETECTION_YAML, 'no-detection.yml');
    expect(rule).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// SigmaReferenceCorpus tests
// ---------------------------------------------------------------------------

function buildMockRules(): SigmaReferenceRule[] {
  const rules: SigmaReferenceRule[] = [];

  const r1 = parseRuleYaml(VALID_RULE_YAML, 'windows/process_creation/ps_download.yml');
  if (r1) rules.push(r1);

  const r2 = parseRuleYaml(VALID_RULE_LINUX_YAML, 'linux/process_creation/crontab.yml');
  if (r2) rules.push(r2);

  const r3 = parseRuleYaml(CLOUD_RULE_YAML, 'cloud/aws/cloudtrail_disabled.yml');
  if (r3) rules.push(r3);

  return rules;
}

describe('SigmaReferenceCorpus', () => {
  describe('fromRules', () => {
    it('should create a corpus from in-memory rules', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      expect(corpus.getAllRules()).toHaveLength(3);
    });
  });

  describe('getRuleById', () => {
    it('should return a rule by its ID', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const rule = corpus.getRuleById('3b6ab547-8ec2-4991-b9d2-2b06702a48d7');
      expect(rule).toBeDefined();
      expect(rule!.title).toBe('Suspicious PowerShell Download');
    });

    it('should return undefined for unknown ID', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      expect(corpus.getRuleById('nonexistent-id')).toBeUndefined();
    });
  });

  describe('getRulesByTechnique', () => {
    it('should return rules matching a technique ID', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const rules = corpus.getRulesByTechnique('T1059.001');
      expect(rules).toHaveLength(1);
      expect(rules[0].title).toBe('Suspicious PowerShell Download');
    });

    it('should handle case-insensitive technique IDs', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const rules = corpus.getRulesByTechnique('t1059.001');
      expect(rules).toHaveLength(1);
    });

    it('should return empty array for unknown technique', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      expect(corpus.getRulesByTechnique('T9999')).toHaveLength(0);
    });
  });

  describe('getRulesByTactic', () => {
    it('should return rules matching a tactic', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const rules = corpus.getRulesByTactic('execution');
      expect(rules).toHaveLength(1);
      expect(rules[0].title).toBe('Suspicious PowerShell Download');
    });

    it('should return rules for persistence tactic', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const rules = corpus.getRulesByTactic('persistence');
      expect(rules).toHaveLength(1);
      expect(rules[0].title).toBe('Suspicious Crontab Modification');
    });

    it('should handle case-insensitive tactic names', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const rules = corpus.getRulesByTactic('DEFENSE_EVASION');
      expect(rules).toHaveLength(1);
    });

    it('should return empty array for unknown tactic', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      expect(corpus.getRulesByTactic('nonexistent')).toHaveLength(0);
    });
  });

  describe('getRulesByCategory', () => {
    it('should return rules matching a logsource category', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const rules = corpus.getRulesByCategory('process_creation');
      expect(rules).toHaveLength(2); // Windows + Linux
    });

    it('should return empty array for unknown category', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      expect(corpus.getRulesByCategory('file_access')).toHaveLength(0);
    });
  });

  describe('getRulesByLevel', () => {
    it('should return rules matching a severity level', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const rules = corpus.getRulesByLevel('high');
      expect(rules).toHaveLength(1);
      expect(rules[0].title).toBe('Suspicious PowerShell Download');
    });

    it('should return critical rules', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const rules = corpus.getRulesByLevel('critical');
      expect(rules).toHaveLength(1);
      expect(rules[0].title).toBe('AWS CloudTrail Logging Disabled');
    });

    it('should return empty array for unknown level', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      expect(corpus.getRulesByLevel('info')).toHaveLength(0);
    });
  });

  describe('searchRules', () => {
    it('should search rules by title keyword', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const results = corpus.searchRules('PowerShell');
      expect(results).toHaveLength(1);
      expect(results[0].title).toContain('PowerShell');
    });

    it('should search rules by description keyword', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const results = corpus.searchRules('crontab');
      expect(results).toHaveLength(1);
      expect(results[0].title).toContain('Crontab');
    });

    it('should be case-insensitive', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const results = corpus.searchRules('powershell');
      expect(results).toHaveLength(1);
    });

    it('should return empty array for no matches', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      expect(corpus.searchRules('zzz_nonexistent_zzz')).toHaveLength(0);
    });
  });

  describe('getAllRules', () => {
    it('should return all loaded rules', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      expect(corpus.getAllRules()).toHaveLength(3);
    });

    it('should return a copy of the rules array', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const all = corpus.getAllRules();
      all.pop();
      // Original should not be mutated
      expect(corpus.getAllRules()).toHaveLength(3);
    });
  });

  describe('getStats', () => {
    it('should return correct total count', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const stats = corpus.getStats();
      expect(stats.totalRules).toBe(3);
    });

    it('should count rules by category', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const stats = corpus.getStats();
      expect(stats.byCategory['process_creation']).toBe(2);
    });

    it('should count rules by level', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const stats = corpus.getStats();
      expect(stats.byLevel['high']).toBe(1);
      expect(stats.byLevel['medium']).toBe(1);
      expect(stats.byLevel['critical']).toBe(1);
    });

    it('should count rules by tactic', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const stats = corpus.getStats();
      expect(stats.byTactic['execution']).toBe(1);
      expect(stats.byTactic['persistence']).toBe(1);
      expect(stats.byTactic['defense_evasion']).toBe(1);
    });

    it('should list covered techniques', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const stats = corpus.getStats();
      expect(stats.techniquesCovered).toContain('T1059.001');
      expect(stats.techniquesCovered).toContain('T1105');
      expect(stats.techniquesCovered).toContain('T1053.003');
      expect(stats.techniquesCovered).toContain('T1562.008');
    });

    it('should sort techniques alphabetically', () => {
      const corpus = SigmaReferenceCorpus.fromRules(buildMockRules());
      const stats = corpus.getStats();
      const sorted = [...stats.techniquesCovered].sort();
      expect(stats.techniquesCovered).toEqual(sorted);
    });
  });

  describe('empty corpus', () => {
    it('should handle empty corpus gracefully', () => {
      const corpus = SigmaReferenceCorpus.fromRules([]);
      expect(corpus.getAllRules()).toHaveLength(0);
      expect(corpus.getRuleById('any')).toBeUndefined();
      expect(corpus.getRulesByTechnique('T1059')).toHaveLength(0);
      expect(corpus.getRulesByTactic('execution')).toHaveLength(0);
      expect(corpus.getRulesByCategory('process_creation')).toHaveLength(0);
      expect(corpus.getRulesByLevel('high')).toHaveLength(0);
      expect(corpus.searchRules('test')).toHaveLength(0);
    });

    it('should return valid stats for empty corpus', () => {
      const corpus = SigmaReferenceCorpus.fromRules([]);
      const stats = corpus.getStats();
      expect(stats.totalRules).toBe(0);
      expect(stats.techniquesCovered).toHaveLength(0);
      expect(Object.keys(stats.byCategory)).toHaveLength(0);
    });
  });

  describe('load from nonexistent path', () => {
    it('should return empty corpus for nonexistent directory', async () => {
      const corpus = await SigmaReferenceCorpus.load('/tmp/nonexistent-sigma-dir');
      expect(corpus.getAllRules()).toHaveLength(0);
    });
  });
});
