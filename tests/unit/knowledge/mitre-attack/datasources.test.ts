import { describe, it, expect, beforeAll } from 'vitest';
import {
  AttackKnowledgeBase,
  type ParsedAttackData,
} from '@/knowledge/mitre-attack/loader.js';
import {
  getDataSourcesForTechnique,
  getTechniquesForDataSource,
  getDetectionRecommendations,
} from '@/knowledge/mitre-attack/datasources.js';

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

function createMockData(): ParsedAttackData {
  return {
    techniques: {
      T1059: {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        description:
          'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
        tactics: ['execution'],
        platforms: ['Windows', 'macOS', 'Linux'],
        dataSources: ['Command: Command Execution', 'Process: Process Creation'],
        isSubtechnique: false,
        url: 'https://attack.mitre.org/techniques/T1059',
      },
      'T1059.001': {
        id: 'T1059.001',
        name: 'PowerShell',
        description:
          'Adversaries may abuse PowerShell commands and scripts for execution.',
        tactics: ['execution'],
        platforms: ['Windows'],
        dataSources: [
          'Command: Command Execution',
          'Module: Module Load',
          'Script: Script Execution',
        ],
        isSubtechnique: true,
        parentId: 'T1059',
        url: 'https://attack.mitre.org/techniques/T1059/001',
      },
      T1547: {
        id: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        description:
          'Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence.',
        tactics: ['persistence', 'privilege-escalation'],
        platforms: ['Windows', 'macOS', 'Linux'],
        dataSources: [
          'Windows Registry: Windows Registry Key Modification',
          'File: File Creation',
        ],
        isSubtechnique: false,
        url: 'https://attack.mitre.org/techniques/T1547',
      },
      T1078: {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may obtain and abuse credentials of existing accounts.',
        tactics: ['defense-evasion', 'persistence'],
        platforms: ['Windows', 'Linux'],
        dataSources: [],
        isSubtechnique: false,
        url: 'https://attack.mitre.org/techniques/T1078',
      },
    },
    tactics: {
      TA0002: {
        id: 'TA0002',
        name: 'Execution',
        shortName: 'execution',
        techniques: ['T1059', 'T1059.001'],
      },
    },
    dataSources: {
      Command: {
        name: 'Command',
        techniques: ['T1059', 'T1059.001'],
      },
      Process: {
        name: 'Process',
        techniques: ['T1059'],
      },
      Module: {
        name: 'Module',
        techniques: ['T1059.001'],
      },
    },
    metadata: {
      version: '14.1',
      lastModified: '2024-04-23T00:00:00.000Z',
      techniqueCount: 3,
      subtechniqueCount: 1,
      tacticCount: 1,
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

let kb: AttackKnowledgeBase;

beforeAll(() => {
  AttackKnowledgeBase.reset();
  kb = AttackKnowledgeBase.fromData(createMockData());
});

describe('getDataSourcesForTechnique', () => {
  it('should return data sources for a known technique', () => {
    const ds = getDataSourcesForTechnique(kb, 'T1059');
    expect(ds).toContain('Command: Command Execution');
    expect(ds).toContain('Process: Process Creation');
  });

  it('should return multiple data sources for a subtechnique', () => {
    const ds = getDataSourcesForTechnique(kb, 'T1059.001');
    expect(ds.length).toBe(3);
    expect(ds).toContain('Module: Module Load');
  });

  it('should return empty array for a technique with no data sources', () => {
    const ds = getDataSourcesForTechnique(kb, 'T1078');
    expect(ds).toEqual([]);
  });

  it('should return empty array for unknown technique', () => {
    const ds = getDataSourcesForTechnique(kb, 'T9999');
    expect(ds).toEqual([]);
  });
});

describe('getTechniquesForDataSource', () => {
  it('should return technique IDs from the pre-computed map', () => {
    const techniques = getTechniquesForDataSource(kb, 'Command');
    expect(techniques).toContain('T1059');
    expect(techniques).toContain('T1059.001');
  });

  it('should be case-insensitive', () => {
    const techniques = getTechniquesForDataSource(kb, 'command');
    expect(techniques).toContain('T1059');
  });

  it('should return technique IDs for Process data source', () => {
    const techniques = getTechniquesForDataSource(kb, 'Process');
    expect(techniques).toContain('T1059');
  });

  it('should fall back to scanning techniques for unlisted sources', () => {
    // "Windows Registry" is not in our dataSources map but appears in
    // technique T1547's dataSources list.
    const techniques = getTechniquesForDataSource(kb, 'Windows Registry');
    expect(techniques).toContain('T1547');
  });

  it('should return empty array for unknown data source', () => {
    expect(getTechniquesForDataSource(kb, 'Nonexistent')).toEqual([]);
  });
});

describe('getDetectionRecommendations', () => {
  it('should return a recommendation string for a known technique', () => {
    const rec = getDetectionRecommendations(kb, 'T1059');
    expect(rec).toContain('T1059');
    expect(rec).toContain('Command and Scripting Interpreter');
    expect(rec).toContain('Recommended data sources');
    expect(rec).toContain('Command: Command Execution');
  });

  it('should mention missing data sources for a technique without them', () => {
    const rec = getDetectionRecommendations(kb, 'T1078');
    expect(rec).toContain('No specific data sources listed');
  });

  it('should return a "not found" message for unknown technique', () => {
    const rec = getDetectionRecommendations(kb, 'T9999');
    expect(rec).toContain('No technique found');
    expect(rec).toContain('T9999');
  });
});
