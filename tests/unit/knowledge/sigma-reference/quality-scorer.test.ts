/**
 * Tests for SigmaHQ quality scorer.
 *
 * Uses mock rules and generated rule objects to verify scoring logic.
 */

import { describe, it, expect } from 'vitest';
import {
  scoreRuleQuality,
  compareToReference,
} from '../../../../src/knowledge/sigma-reference/quality-scorer.js';
import {
  parseRuleYaml,
  type SigmaReferenceRule,
} from '../../../../src/knowledge/sigma-reference/loader.js';

// ---------------------------------------------------------------------------
// Fixtures – reference rules (parsed from inline YAML)
// ---------------------------------------------------------------------------

const REFERENCE_YAML_1 = `
title: Suspicious PowerShell Download Cradle
id: ref-001
status: test
description: Detects PowerShell download cradles
author: Reference Author
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
    Image|endswith: '\\\\powershell.exe'
  filter:
    ParentImage|endswith: '\\\\svchost.exe'
  condition: selection and not filter
falsepositives:
  - Legitimate PowerShell scripts used by administrators
  - Software deployment tools like SCCM
level: high
`;

const REFERENCE_YAML_2 = `
title: PowerShell Encoded Command Execution
id: ref-002
status: test
description: Detects encoded PowerShell command execution
author: Reference Author
date: 2024/01/01
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
    Image|endswith: '\\\\powershell.exe'
  selection_parent:
    ParentImage|endswith:
      - '\\\\cmd.exe'
      - '\\\\explorer.exe'
  condition: selection and selection_parent
falsepositives:
  - Enterprise software installation scripts
level: high
`;

function buildReferenceRules(): SigmaReferenceRule[] {
  const rules: SigmaReferenceRule[] = [];
  const r1 = parseRuleYaml(REFERENCE_YAML_1, 'ref1.yml');
  if (r1) rules.push(r1);
  const r2 = parseRuleYaml(REFERENCE_YAML_2, 'ref2.yml');
  if (r2) rules.push(r2);
  return rules;
}

// ---------------------------------------------------------------------------
// Generated rule fixtures
// ---------------------------------------------------------------------------

/** A well-formed generated rule that closely matches references */
const GOOD_GENERATED_RULE: Record<string, unknown> = {
  title: 'PowerShell Download via Invoke-Expression',
  id: 'gen-001',
  status: 'experimental',
  description: 'Detects PowerShell IEX download patterns',
  author: 'DetectForge',
  date: '2024/06/01',
  tags: [
    'attack.execution',
    'attack.t1059.001',
  ],
  logsource: {
    category: 'process_creation',
    product: 'windows',
  },
  detection: {
    selection: {
      'CommandLine|contains': [
        'Invoke-Expression',
        'IEX',
        'Invoke-WebRequest',
      ],
      'Image|endswith': '\\powershell.exe',
    },
    filter: {
      'ParentImage|endswith': '\\svchost.exe',
    },
    condition: 'selection and not filter',
  },
  falsepositives: [
    'Legitimate PowerShell automation scripts',
    'Enterprise management tools',
  ],
  level: 'high',
  references: ['https://example.com'],
};

/** A minimal generated rule missing many fields */
const MINIMAL_GENERATED_RULE: Record<string, unknown> = {
  title: 'Basic Detection',
  detection: {
    selection: {
      CommandLine: 'malware.exe',
    },
    condition: 'selection',
  },
  level: 'medium',
};

/** A rule with no detection at all */
const EMPTY_DETECTION_RULE: Record<string, unknown> = {
  title: 'Empty Detection',
  detection: {},
};

/** A rule with good metadata but poor detection */
const METADATA_RICH_RULE: Record<string, unknown> = {
  title: 'Well-Documented Rule',
  id: 'meta-001',
  status: 'experimental',
  description: 'A rule with good metadata but weak detection',
  author: 'Test Author',
  date: '2024/06/01',
  tags: [
    'attack.execution',
    'attack.t1059.001',
  ],
  logsource: {
    category: 'process_creation',
    product: 'windows',
  },
  detection: {
    selection: {
      CommandLine: 'suspicious',
    },
    condition: 'selection',
  },
  falsepositives: [
    'Unknown',
  ],
  level: 'low',
  references: ['https://example.com'],
  modified: '2024/06/15',
};

/** A rule with specific and detailed false positives */
const DETAILED_FP_RULE: Record<string, unknown> = {
  title: 'Rule With Detailed FPs',
  id: 'fp-001',
  status: 'experimental',
  description: 'A rule with detailed false positive documentation',
  author: 'Test Author',
  date: '2024/06/01',
  tags: [
    'attack.execution',
    'attack.t1059.001',
  ],
  logsource: {
    category: 'process_creation',
    product: 'windows',
  },
  detection: {
    selection: {
      'CommandLine|contains': ['Invoke-WebRequest'],
      'Image|endswith': '\\powershell.exe',
    },
    condition: 'selection',
  },
  falsepositives: [
    'System Center Configuration Manager (SCCM) often uses PowerShell download cmdlets for software deployment',
    'Administrators running patch management scripts that pull updates via PowerShell',
    'CI/CD pipelines that invoke PowerShell download commands to fetch build artifacts',
  ],
  level: 'high',
};

// ---------------------------------------------------------------------------
// scoreRuleQuality tests
// ---------------------------------------------------------------------------

describe('scoreRuleQuality', () => {
  describe('overall scoring', () => {
    it('should return a score between 1 and 10 for all components', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(GOOD_GENERATED_RULE, refs, 'T1059.001');

      expect(score.overall).toBeGreaterThanOrEqual(1);
      expect(score.overall).toBeLessThanOrEqual(10);
      expect(score.fieldCoverage).toBeGreaterThanOrEqual(1);
      expect(score.fieldCoverage).toBeLessThanOrEqual(10);
      expect(score.conditionComplexity).toBeGreaterThanOrEqual(1);
      expect(score.conditionComplexity).toBeLessThanOrEqual(10);
      expect(score.fpDocumentation).toBeGreaterThanOrEqual(1);
      expect(score.fpDocumentation).toBeLessThanOrEqual(10);
      expect(score.metadataCompleteness).toBeGreaterThanOrEqual(1);
      expect(score.metadataCompleteness).toBeLessThanOrEqual(10);
      expect(score.techniqueAlignment).toBeGreaterThanOrEqual(1);
      expect(score.techniqueAlignment).toBeLessThanOrEqual(10);
    });

    it('should return details array', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(GOOD_GENERATED_RULE, refs);
      expect(Array.isArray(score.details)).toBe(true);
      expect(score.details.length).toBeGreaterThan(0);
    });

    it('should score a good rule higher than a minimal rule', () => {
      const refs = buildReferenceRules();
      const goodScore = scoreRuleQuality(GOOD_GENERATED_RULE, refs, 'T1059.001');
      const minScore = scoreRuleQuality(MINIMAL_GENERATED_RULE, refs, 'T1059.001');

      expect(goodScore.overall).toBeGreaterThan(minScore.overall);
    });
  });

  describe('field coverage', () => {
    it('should score higher when generated rule uses same fields as references', () => {
      const refs = buildReferenceRules();
      const goodScore = scoreRuleQuality(GOOD_GENERATED_RULE, refs);
      const minScore = scoreRuleQuality(MINIMAL_GENERATED_RULE, refs);

      expect(goodScore.fieldCoverage).toBeGreaterThan(minScore.fieldCoverage);
    });

    it('should handle scoring with no reference rules', () => {
      const score = scoreRuleQuality(GOOD_GENERATED_RULE, []);
      expect(score.fieldCoverage).toBeGreaterThanOrEqual(1);
      expect(score.fieldCoverage).toBeLessThanOrEqual(10);
    });

    it('should give a low score for empty detection', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(EMPTY_DETECTION_RULE, refs);
      expect(score.fieldCoverage).toBeLessThanOrEqual(4);
    });
  });

  describe('condition complexity', () => {
    it('should score higher for rules with multiple condition clauses', () => {
      const refs = buildReferenceRules();
      const complexScore = scoreRuleQuality(GOOD_GENERATED_RULE, refs);

      // Minimal rule has a simple single-selection condition
      const simpleScore = scoreRuleQuality(MINIMAL_GENERATED_RULE, refs);

      expect(complexScore.conditionComplexity).toBeGreaterThanOrEqual(
        simpleScore.conditionComplexity,
      );
    });

    it('should give low score for empty detection', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(EMPTY_DETECTION_RULE, refs);
      expect(score.conditionComplexity).toBeLessThanOrEqual(3);
    });
  });

  describe('false positive documentation', () => {
    it('should score higher for rules with specific false positives', () => {
      const refs = buildReferenceRules();
      const detailedScore = scoreRuleQuality(DETAILED_FP_RULE, refs);
      const noFpScore = scoreRuleQuality(MINIMAL_GENERATED_RULE, refs);

      expect(detailedScore.fpDocumentation).toBeGreaterThan(
        noFpScore.fpDocumentation,
      );
    });

    it('should score low for vague false positives', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(METADATA_RICH_RULE, refs);
      // "Unknown" is vague
      expect(score.fpDocumentation).toBeLessThan(7);
    });

    it('should give low score for no false positives', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(MINIMAL_GENERATED_RULE, refs);
      expect(score.fpDocumentation).toBeLessThanOrEqual(3);
    });
  });

  describe('metadata completeness', () => {
    it('should score high for a fully documented rule', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(GOOD_GENERATED_RULE, refs);
      expect(score.metadataCompleteness).toBeGreaterThanOrEqual(7);
    });

    it('should score low for a minimal rule', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(MINIMAL_GENERATED_RULE, refs);
      expect(score.metadataCompleteness).toBeLessThanOrEqual(4);
    });

    it('should note missing required fields in details', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(MINIMAL_GENERATED_RULE, refs);
      const missingMsg = score.details.find((d) =>
        d.startsWith('Missing required fields'),
      );
      expect(missingMsg).toBeDefined();
    });
  });

  describe('technique alignment', () => {
    it('should score higher when technique ID matches', () => {
      const refs = buildReferenceRules();
      const matchScore = scoreRuleQuality(
        GOOD_GENERATED_RULE,
        refs,
        'T1059.001',
      );

      // Create a rule that maps to a different technique
      const wrongTechRule = {
        ...GOOD_GENERATED_RULE,
        tags: ['attack.execution', 'attack.t1059.003'],
      };
      const mismatchScore = scoreRuleQuality(wrongTechRule, refs, 'T1059.001');

      expect(matchScore.techniqueAlignment).toBeGreaterThan(
        mismatchScore.techniqueAlignment,
      );
    });

    it('should give low score for rules with no tags', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(MINIMAL_GENERATED_RULE, refs);
      expect(score.techniqueAlignment).toBeLessThanOrEqual(4);
    });

    it('should work without a target technique ID', () => {
      const refs = buildReferenceRules();
      const score = scoreRuleQuality(GOOD_GENERATED_RULE, refs);
      expect(score.techniqueAlignment).toBeGreaterThanOrEqual(1);
      expect(score.techniqueAlignment).toBeLessThanOrEqual(10);
    });
  });

  describe('scoring without reference rules', () => {
    it('should still produce valid scores without reference rules', () => {
      const score = scoreRuleQuality(GOOD_GENERATED_RULE, [], 'T1059.001');

      expect(score.overall).toBeGreaterThanOrEqual(1);
      expect(score.overall).toBeLessThanOrEqual(10);
      expect(score.fieldCoverage).toBeGreaterThanOrEqual(1);
      expect(score.conditionComplexity).toBeGreaterThanOrEqual(1);
      expect(score.fpDocumentation).toBeGreaterThanOrEqual(1);
      expect(score.metadataCompleteness).toBeGreaterThanOrEqual(1);
      expect(score.techniqueAlignment).toBeGreaterThanOrEqual(1);
    });
  });
});

// ---------------------------------------------------------------------------
// compareToReference tests
// ---------------------------------------------------------------------------

describe('compareToReference', () => {
  it('should return comparison result with all four categories', () => {
    const ref = buildReferenceRules()[0];
    const result = compareToReference(GOOD_GENERATED_RULE, ref);

    expect(Array.isArray(result.similarities)).toBe(true);
    expect(Array.isArray(result.differences)).toBe(true);
    expect(Array.isArray(result.improvements)).toBe(true);
    expect(Array.isArray(result.gaps)).toBe(true);
  });

  it('should identify shared detection fields', () => {
    const ref = buildReferenceRules()[0];
    const result = compareToReference(GOOD_GENERATED_RULE, ref);

    const fieldSimilarity = result.similarities.find((s) =>
      s.includes('Both rules detect on fields'),
    );
    expect(fieldSimilarity).toBeDefined();
  });

  it('should identify shared ATT&CK techniques', () => {
    const ref = buildReferenceRules()[0];
    const result = compareToReference(GOOD_GENERATED_RULE, ref);

    const techSimilarity = result.similarities.find((s) =>
      s.includes('Both rules target technique'),
    );
    expect(techSimilarity).toBeDefined();
  });

  it('should identify same logsource', () => {
    const ref = buildReferenceRules()[0];
    const result = compareToReference(GOOD_GENERATED_RULE, ref);

    const logsourceSimilarity = result.similarities.find((s) =>
      s.includes('Same logsource'),
    );
    expect(logsourceSimilarity).toBeDefined();
  });

  it('should identify same severity level', () => {
    const ref = buildReferenceRules()[0];
    const result = compareToReference(GOOD_GENERATED_RULE, ref);

    const levelSimilarity = result.similarities.find((s) =>
      s.includes('Same severity level'),
    );
    expect(levelSimilarity).toBeDefined();
  });

  it('should identify gaps when reference has more techniques', () => {
    const ref = buildReferenceRules()[0];
    // Our good rule only has T1059.001 but reference also has T1105
    const result = compareToReference(GOOD_GENERATED_RULE, ref);

    const techGap = result.gaps.find((g) =>
      g.includes('techniques not in generated rule'),
    );
    expect(techGap).toBeDefined();
  });

  it('should identify missing false positives as a gap', () => {
    const ref = buildReferenceRules()[0];
    const result = compareToReference(MINIMAL_GENERATED_RULE, ref);

    const fpGap = result.gaps.find((g) =>
      g.includes('false positives'),
    );
    expect(fpGap).toBeDefined();
  });

  it('should identify different logsource as a difference', () => {
    const ref = buildReferenceRules()[0];
    const differentLogsource = {
      ...GOOD_GENERATED_RULE,
      logsource: {
        category: 'file_access',
        product: 'linux',
      },
    };
    const result = compareToReference(differentLogsource, ref);

    const logsourceDiff = result.differences.find((d) =>
      d.includes('Different logsource'),
    );
    expect(logsourceDiff).toBeDefined();
  });

  it('should identify different severity level', () => {
    const ref = buildReferenceRules()[0];
    const differentLevel = {
      ...GOOD_GENERATED_RULE,
      level: 'low',
    };
    const result = compareToReference(differentLevel, ref);

    const levelDiff = result.differences.find((d) =>
      d.includes('Different severity levels'),
    );
    expect(levelDiff).toBeDefined();
  });

  it('should identify when generated rule has more criteria as improvement', () => {
    const ref = buildReferenceRules()[0];
    // Our good rule has more criteria patterns
    const detailedRule = {
      ...GOOD_GENERATED_RULE,
      detection: {
        selection: {
          'CommandLine|contains': [
            'Invoke-Expression',
            'IEX',
            'Invoke-WebRequest',
            'DownloadString',
            'DownloadFile',
            'Net.WebClient',
            'Start-BitsTransfer',
          ],
          'Image|endswith': '\\powershell.exe',
          'ParentImage|endswith': '\\cmd.exe',
        },
        filter: {
          'User|contains': 'SYSTEM',
        },
        condition: 'selection and not filter',
      },
    };
    const result = compareToReference(detailedRule, ref);

    const criteriaNote = result.improvements.find(
      (i) =>
        i.includes('more detection criteria'),
    );
    expect(criteriaNote).toBeDefined();
  });

  it('should identify when generated rule documents FPs where reference does not', () => {
    // Reference rule 2 has only one FP entry; let's build a scenario
    const ref = parseRuleYaml(
      `
title: No FP Rule
id: no-fp-001
status: test
description: A rule without false positives
author: Test
date: 2024/01/01
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine: suspicious
  condition: selection
level: high
`,
      'no-fp.yml',
    );
    expect(ref).toBeDefined();

    const result = compareToReference(DETAILED_FP_RULE, ref!);
    const fpImprovement = result.improvements.find((i) =>
      i.includes('false positives'),
    );
    expect(fpImprovement).toBeDefined();
  });
});
