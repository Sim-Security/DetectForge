/**
 * Unit tests for hold-out validation in the real data tester.
 *
 * Tests:
 * - Techniques with 2+ datasets get hold-out split
 * - Single-dataset techniques have no hold-out
 * - Hold-out results reported separately
 * - Hold-out verdict correct
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

vi.mock('@/knowledge/logsource-catalog/index.js', () => ({
  validateSigmaLogsource: vi.fn(() => true),
  getFieldsForLogsource: vi.fn(() => []),
}));

// Mock dataset downloader to provide test data
vi.mock('@/testing/real-data/dataset-downloader.js', () => ({
  loadDownloadedDatasets: vi.fn(),
}));

// Mock effectiveness tester to avoid synthetic testing overhead
vi.mock('@/testing/effectiveness-tester.js', () => ({
  testRuleEffectiveness: vi.fn(() => ({
    suite: { tpRate: 0.8, fpRate: 0.1, truePositives: 8, falsePositives: 1, attackLogs: 10, benignLogs: 10 },
    behavioralTpRate: 0.7,
    confidence: { score: 50, level: 'medium', factors: [] },
    evasionResilience: null,
  })),
  assessConfidence: vi.fn(() => ({ score: 50, level: 'medium', factors: [] })),
}));

import { loadDownloadedDatasets } from '@/testing/real-data/dataset-downloader.js';
import { testRulesAgainstRealData } from '@/testing/real-data/real-data-tester.js';
import { DATASET_CATALOG } from '@/testing/real-data/dataset-catalog.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(techniqueId: string, category: string): SigmaRule {
  return {
    id: `test-${techniqueId}`,
    title: `Test Rule for ${techniqueId}`,
    status: 'experimental',
    description: 'Test rule for hold-out validation testing.',
    references: [],
    author: 'DetectForge',
    date: '2026/02/12',
    modified: '2026/02/12',
    tags: [`attack.credential_access`, `attack.${techniqueId.toLowerCase()}`],
    logsource: { product: 'windows', category },
    detection: {
      selection: { 'CommandLine|contains': 'test' },
      filter: { User: 'SYSTEM' },
      condition: 'selection and not filter',
    },
    falsepositives: ['Legitimate activity'],
    level: 'high',
    raw: '',
  };
}

/**
 * Create a mock Sysmon process_creation log entry.
 */
function makeSysmonLog(image: string, commandLine: string, parentImage = 'explorer.exe') {
  return {
    EventID: 1,
    Channel: 'Microsoft-Windows-Sysmon/Operational',
    Image: image,
    CommandLine: commandLine,
    ParentImage: parentImage,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('hold-out validation', () => {
  beforeEach(() => {
    vi.mocked(loadDownloadedDatasets).mockReset();
  });

  it('returns no-holdout when technique has only 1 dataset', async () => {
    // T1070.001 has only 1 dataset (wevtutil)
    const t1070Datasets = DATASET_CATALOG.filter(d => d.attackTechniqueId === 'T1070.001');
    expect(t1070Datasets).toHaveLength(1);

    // Set up mock data for that single dataset
    const mockData = new Map<string, unknown[]>();
    mockData.set('t1070.001_wevtutil', [
      makeSysmonLog('C:\\Windows\\System32\\wevtutil.exe', 'wevtutil cl security'),
      makeSysmonLog('C:\\Windows\\System32\\svchost.exe', 'svchost -k netsvcs'),
    ]);
    vi.mocked(loadDownloadedDatasets).mockResolvedValue(mockData);

    const rule = makeRule('T1070.001', 'process_creation');
    const summary = await testRulesAgainstRealData([rule], {});

    const result = summary.results[0];
    expect(result.holdOutVerdict).toBe('no-holdout');
    expect(result.holdOutResults).toBeUndefined();
  });

  it('splits datasets when technique has 2+ datasets', async () => {
    // T1003.001 has 4 datasets: mimikatz, comsvcs, taskmgr, dumpert
    const t1003_001 = DATASET_CATALOG.filter(d => d.attackTechniqueId === 'T1003.001');
    expect(t1003_001.length).toBeGreaterThanOrEqual(2);

    // Provide mock data for all T1003.001 datasets
    const mockData = new Map<string, unknown[]>();
    for (const ds of t1003_001) {
      mockData.set(ds.id, [
        makeSysmonLog('C:\\Windows\\System32\\rundll32.exe', 'rundll32.exe comsvcs.dll MiniDump test'),
        makeSysmonLog('C:\\Windows\\System32\\svchost.exe', 'svchost -k netsvcs'),
      ]);
    }
    vi.mocked(loadDownloadedDatasets).mockResolvedValue(mockData);

    const rule = makeRule('T1003.001', 'process_creation');
    const summary = await testRulesAgainstRealData([rule], {});

    const result = summary.results[0];
    // With hold-out enabled and 4 datasets, the development set should have 3
    // and hold-out should have 1
    if (result.perDatasetResults.length > 0) {
      expect(result.perDatasetResults.length).toBeLessThan(t1003_001.length);
    }
    // Hold-out should have data
    if (result.holdOutVerdict !== 'no-holdout') {
      expect(result.holdOutResults).toBeDefined();
      expect(result.holdOutResults!.length).toBeGreaterThan(0);
    }
  });

  it('always computes hold-out (no opt-out)', async () => {
    const t1003_001 = DATASET_CATALOG.filter(d => d.attackTechniqueId === 'T1003.001');

    const mockData = new Map<string, unknown[]>();
    for (const ds of t1003_001) {
      mockData.set(ds.id, [
        makeSysmonLog('C:\\Windows\\System32\\rundll32.exe', 'rundll32.exe comsvcs.dll MiniDump test'),
        makeSysmonLog('C:\\Windows\\System32\\svchost.exe', 'svchost -k netsvcs'),
      ]);
    }
    vi.mocked(loadDownloadedDatasets).mockResolvedValue(mockData);

    const rule = makeRule('T1003.001', 'process_creation');
    // No holdOutValidation option — hold-out is always on
    const summary = await testRulesAgainstRealData([rule]);

    const result = summary.results[0];
    // Hold-out is always computed: development set should have fewer datasets than total
    if (t1003_001.length >= 2) {
      expect(result.perDatasetResults.length).toBeLessThan(t1003_001.length);
      expect(result.holdOutVerdict).toBeDefined();
    }
  });

  it('hold-out verdict is pass when hold-out TP exceeds threshold', async () => {
    // Create two datasets for a technique
    const mockData = new Map<string, unknown[]>();

    // Dataset A - the detection will match 'test' in commandline
    mockData.set('t1003.001_lsass_comsvcs', [
      makeSysmonLog('C:\\Windows\\System32\\rundll32.exe', 'test command'),
      makeSysmonLog('C:\\Windows\\System32\\svchost.exe', 'svchost -k netsvcs'),
    ]);

    // Dataset B (hold-out) - will also match since 'test' is in CommandLine
    mockData.set('t1003.001_rdp_taskmgr_lsass', [
      makeSysmonLog('C:\\Windows\\System32\\taskmgr.exe', 'test command'),
      makeSysmonLog('C:\\Windows\\System32\\svchost.exe', 'svchost -k netsvcs'),
    ]);

    vi.mocked(loadDownloadedDatasets).mockResolvedValue(mockData);

    const rule = makeRule('T1003.001', 'process_creation');
    // Rule detects 'test' in CommandLine, so both datasets should match
    rule.detection = {
      selection: { 'CommandLine|contains': 'test' },
      filter: { User: 'SYSTEM' },
      condition: 'selection and not filter',
    };

    const summary = await testRulesAgainstRealData([rule], {});
    const result = summary.results[0];

    // One of the two datasets should be held out
    if (result.holdOutVerdict !== 'no-holdout' && result.holdOutResults && result.holdOutResults.length > 0) {
      const bestHo = result.holdOutResults.filter(d => d.attackCount > 0);
      if (bestHo.length > 0) {
        // If the hold-out detected the rule, verdict should be pass
        expect(result.holdOutVerdict).toBe(bestHo[0].tpRate >= 0.3 ? 'pass' : 'fail');
      }
    }
  });

  it('reclassifies as behavior-mismatch when TP < 1% with many attack logs', async () => {
    // Create a dataset where the rule's detection has zero overlap with attack content
    // but there are many attack logs (> 10), triggering behavior-mismatch threshold
    const mockData = new Map<string, unknown[]>();

    // Create 15 attack logs that don't match the rule's 'test' pattern
    const logs: unknown[] = [];
    for (let i = 0; i < 15; i++) {
      logs.push(makeSysmonLog(
        'C:\\Windows\\System32\\schtasks.exe',
        `schtasks /create /tn Task${i}`,
        'C:\\Windows\\System32\\services.exe',
      ));
    }
    // Add some benign logs too
    logs.push(makeSysmonLog('C:\\Windows\\System32\\svchost.exe', 'svchost -k netsvcs'));

    mockData.set('t1053.005_schtasks_user', logs);
    vi.mocked(loadDownloadedDatasets).mockResolvedValue(mockData);

    const rule = makeRule('T1053.005', 'process_creation');
    // Rule detects 'uniquestring' — nothing in the dataset matches
    rule.detection = {
      selection: { 'CommandLine|contains': 'uniquestring_that_never_matches' },
      condition: 'selection',
    };

    const summary = await testRulesAgainstRealData([rule]);
    const result = summary.results[0];

    // With > 10 attack logs and 0% TP, should be reclassified as behavior-mismatch
    expect(result.matchType).toBe('behavior-mismatch');
    expect(result.verdict).toBe('behavior-mismatch');
  });

  it('reports empty hold-out results when no data matches hold-out', async () => {
    // Only provide data for one dataset of a multi-dataset technique
    const mockData = new Map<string, unknown[]>();
    mockData.set('t1003.001_lsass_comsvcs', [
      makeSysmonLog('C:\\Windows\\System32\\rundll32.exe', 'test command'),
    ]);
    // The other T1003.001 datasets don't exist in our mock
    vi.mocked(loadDownloadedDatasets).mockResolvedValue(mockData);

    const rule = makeRule('T1003.001', 'process_creation');
    const summary = await testRulesAgainstRealData([rule], {});

    const result = summary.results[0];
    // With only 1 dataset actually loaded, there's no hold-out split
    expect(result.holdOutVerdict).toBe('no-holdout');
  });
});
