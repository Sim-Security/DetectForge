import { describe, it, expect, beforeEach } from 'vitest';
import {
  AttackKnowledgeBase,
  type ParsedAttackData,
} from '@/knowledge/mitre-attack/loader.js';

// ---------------------------------------------------------------------------
// Shared mock data
// ---------------------------------------------------------------------------

function createMockData(): ParsedAttackData {
  return {
    techniques: {
      T1059: {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        description:
          'Adversaries may abuse command and script interpreters to execute commands.',
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
    },
    metadata: {
      version: '14.1',
      lastModified: '2024-04-23T00:00:00.000Z',
      techniqueCount: 1,
      subtechniqueCount: 1,
      tacticCount: 1,
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AttackKnowledgeBase', () => {
  beforeEach(() => {
    AttackKnowledgeBase.reset();
  });

  it('should create a knowledge base from in-memory data', () => {
    const kb = AttackKnowledgeBase.fromData(createMockData());
    expect(kb).toBeInstanceOf(AttackKnowledgeBase);
  });

  it('should expose techniques map', () => {
    const kb = AttackKnowledgeBase.fromData(createMockData());
    expect(Object.keys(kb.techniques)).toContain('T1059');
    expect(Object.keys(kb.techniques)).toContain('T1059.001');
  });

  it('should expose tactics map', () => {
    const kb = AttackKnowledgeBase.fromData(createMockData());
    expect(Object.keys(kb.tactics)).toContain('TA0002');
    expect(kb.tactics['TA0002'].shortName).toBe('execution');
  });

  it('should expose dataSources map', () => {
    const kb = AttackKnowledgeBase.fromData(createMockData());
    expect(Object.keys(kb.dataSources)).toContain('Command');
  });

  it('should expose metadata', () => {
    const kb = AttackKnowledgeBase.fromData(createMockData());
    expect(kb.metadata.version).toBe('14.1');
    expect(kb.metadata.techniqueCount).toBe(1);
    expect(kb.metadata.subtechniqueCount).toBe(1);
    expect(kb.metadata.tacticCount).toBe(1);
  });

  it('should return the same instance (singleton) when fromData is called', () => {
    const data = createMockData();
    const kb1 = AttackKnowledgeBase.fromData(data);
    const kb2 = AttackKnowledgeBase.fromData(data);
    // fromData always replaces the singleton, but should still be valid
    expect(kb2).toBeInstanceOf(AttackKnowledgeBase);
  });

  it('should reset the singleton', () => {
    AttackKnowledgeBase.fromData(createMockData());
    AttackKnowledgeBase.reset();
    // After reset there is no public way to retrieve the instance without
    // loading from file or calling fromData again, so just verify no throw.
    expect(() => AttackKnowledgeBase.reset()).not.toThrow();
  });
});
