import { describe, it, expect, beforeAll } from 'vitest';
import {
  AttackKnowledgeBase,
  type ParsedAttackData,
} from '@/knowledge/mitre-attack/loader.js';
import {
  getTechnique,
  searchTechniques,
  getTechniquesByTactic,
  getTechniquesByPlatform,
  getSubtechniques,
  getParentTechnique,
  validateTechniqueId,
} from '@/knowledge/mitre-attack/techniques.js';

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
      'T1059.003': {
        id: 'T1059.003',
        name: 'Windows Command Shell',
        description:
          'Adversaries may abuse the Windows command shell (cmd) for execution.',
        tactics: ['execution'],
        platforms: ['Windows'],
        dataSources: ['Command: Command Execution', 'Process: Process Creation'],
        isSubtechnique: true,
        parentId: 'T1059',
        url: 'https://attack.mitre.org/techniques/T1059/003',
      },
      T1547: {
        id: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        description:
          'Adversaries may configure system settings to automatically execute a program during system boot or logon.',
        tactics: ['persistence', 'privilege-escalation'],
        platforms: ['Windows', 'macOS', 'Linux'],
        dataSources: [
          'Windows Registry: Windows Registry Key Modification',
          'File: File Creation',
        ],
        isSubtechnique: false,
        url: 'https://attack.mitre.org/techniques/T1547',
      },
      'T1547.001': {
        id: 'T1547.001',
        name: 'Registry Run Keys / Startup Folder',
        description:
          'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.',
        tactics: ['persistence', 'privilege-escalation'],
        platforms: ['Windows'],
        dataSources: [
          'Windows Registry: Windows Registry Key Modification',
          'File: File Modification',
        ],
        isSubtechnique: true,
        parentId: 'T1547',
        url: 'https://attack.mitre.org/techniques/T1547/001',
      },
      T1078: {
        id: 'T1078',
        name: 'Valid Accounts',
        description:
          'Adversaries may obtain and abuse credentials of existing accounts.',
        tactics: ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access'],
        platforms: ['Windows', 'Azure AD', 'Office 365', 'SaaS', 'IaaS', 'Linux', 'macOS', 'Google Workspace'],
        dataSources: ['Logon Session: Logon Session Creation', 'User Account: User Account Authentication'],
        isSubtechnique: false,
        url: 'https://attack.mitre.org/techniques/T1078',
      },
    },
    tactics: {
      TA0002: {
        id: 'TA0002',
        name: 'Execution',
        shortName: 'execution',
        techniques: ['T1059', 'T1059.001', 'T1059.003'],
      },
      TA0003: {
        id: 'TA0003',
        name: 'Persistence',
        shortName: 'persistence',
        techniques: ['T1547', 'T1547.001', 'T1078'],
      },
    },
    dataSources: {
      Command: { name: 'Command', techniques: ['T1059', 'T1059.001', 'T1059.003'] },
      Process: { name: 'Process', techniques: ['T1059', 'T1059.003'] },
    },
    metadata: {
      version: '14.1',
      lastModified: '2024-04-23T00:00:00.000Z',
      techniqueCount: 3,
      subtechniqueCount: 3,
      tacticCount: 2,
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

describe('getTechnique', () => {
  it('should return a technique by ID', () => {
    const t = getTechnique(kb, 'T1059');
    expect(t).toBeDefined();
    expect(t!.id).toBe('T1059');
    expect(t!.name).toBe('Command and Scripting Interpreter');
  });

  it('should return a subtechnique by ID', () => {
    const t = getTechnique(kb, 'T1059.001');
    expect(t).toBeDefined();
    expect(t!.name).toBe('PowerShell');
    expect(t!.isSubtechnique).toBe(true);
  });

  it('should return undefined for unknown ID', () => {
    expect(getTechnique(kb, 'T9999')).toBeUndefined();
  });
});

describe('searchTechniques', () => {
  it('should find techniques by name keyword', () => {
    const results = searchTechniques(kb, 'PowerShell');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.some((t) => t.id === 'T1059.001')).toBe(true);
  });

  it('should find techniques by description keyword', () => {
    const results = searchTechniques(kb, 'credentials');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.some((t) => t.id === 'T1078')).toBe(true);
  });

  it('should be case-insensitive', () => {
    const results = searchTechniques(kb, 'powershell');
    expect(results.some((t) => t.id === 'T1059.001')).toBe(true);
  });

  it('should return empty array for no matches', () => {
    const results = searchTechniques(kb, 'xyznonexistent');
    expect(results).toEqual([]);
  });
});

describe('getTechniquesByTactic', () => {
  it('should return techniques for execution tactic', () => {
    const results = getTechniquesByTactic(kb, 'execution');
    expect(results.length).toBe(3);
    const ids = results.map((t) => t.id);
    expect(ids).toContain('T1059');
    expect(ids).toContain('T1059.001');
    expect(ids).toContain('T1059.003');
  });

  it('should return techniques for persistence tactic', () => {
    const results = getTechniquesByTactic(kb, 'persistence');
    const ids = results.map((t) => t.id);
    expect(ids).toContain('T1547');
    expect(ids).toContain('T1547.001');
    expect(ids).toContain('T1078');
  });

  it('should be case-insensitive', () => {
    const results = getTechniquesByTactic(kb, 'Execution');
    expect(results.length).toBe(3);
  });

  it('should return empty array for unknown tactic', () => {
    expect(getTechniquesByTactic(kb, 'nonexistent')).toEqual([]);
  });
});

describe('getTechniquesByPlatform', () => {
  it('should return all Windows techniques', () => {
    const results = getTechniquesByPlatform(kb, 'Windows');
    expect(results.length).toBe(6); // all six mock techniques target Windows
  });

  it('should return Linux techniques', () => {
    const results = getTechniquesByPlatform(kb, 'Linux');
    const ids = results.map((t) => t.id);
    expect(ids).toContain('T1059');
    expect(ids).toContain('T1547');
    expect(ids).toContain('T1078');
  });

  it('should be case-insensitive', () => {
    const results = getTechniquesByPlatform(kb, 'windows');
    expect(results.length).toBe(6);
  });

  it('should return empty array for unsupported platform', () => {
    expect(getTechniquesByPlatform(kb, 'Nintendo')).toEqual([]);
  });
});

describe('getSubtechniques', () => {
  it('should return subtechniques of T1059', () => {
    const results = getSubtechniques(kb, 'T1059');
    expect(results.length).toBe(2);
    const ids = results.map((t) => t.id);
    expect(ids).toContain('T1059.001');
    expect(ids).toContain('T1059.003');
  });

  it('should return subtechniques of T1547', () => {
    const results = getSubtechniques(kb, 'T1547');
    expect(results.length).toBe(1);
    expect(results[0].id).toBe('T1547.001');
  });

  it('should return empty array when no subtechniques exist', () => {
    expect(getSubtechniques(kb, 'T1078')).toEqual([]);
  });

  it('should return empty for unknown parent', () => {
    expect(getSubtechniques(kb, 'T9999')).toEqual([]);
  });
});

describe('getParentTechnique', () => {
  it('should return parent for a subtechnique', () => {
    const parent = getParentTechnique(kb, 'T1059.001');
    expect(parent).toBeDefined();
    expect(parent!.id).toBe('T1059');
  });

  it('should return undefined for a top-level technique', () => {
    expect(getParentTechnique(kb, 'T1059')).toBeUndefined();
  });

  it('should return undefined for unknown ID', () => {
    expect(getParentTechnique(kb, 'T9999')).toBeUndefined();
  });
});

describe('validateTechniqueId', () => {
  it('should return true for existing technique', () => {
    expect(validateTechniqueId(kb, 'T1059')).toBe(true);
  });

  it('should return true for existing subtechnique', () => {
    expect(validateTechniqueId(kb, 'T1059.001')).toBe(true);
  });

  it('should return false for unknown technique', () => {
    expect(validateTechniqueId(kb, 'T9999')).toBe(false);
  });

  it('should return false for empty string', () => {
    expect(validateTechniqueId(kb, '')).toBe(false);
  });
});
