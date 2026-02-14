/**
 * Unit tests for DEFAULT_ATTACK_PATTERNS coverage in the log normalizer.
 *
 * Ensures that behavioral attack patterns cover key detection categories
 * and that critical patterns exist for common attack scenarios.
 */

import { describe, it, expect } from 'vitest';
import { normalizeOTRFLogs } from '@/testing/real-data/log-normalizer.js';

// ===========================================================================
// Helper: create a minimal log entry matching a Sysmon event
// ===========================================================================

function makeSysmonLog(eventId: number, fields: Record<string, string>) {
  return {
    EventID: eventId,
    Channel: 'Microsoft-Windows-Sysmon/Operational',
    ...fields,
  };
}

// ===========================================================================
// Process Creation (EID 1) — attack pattern coverage
// ===========================================================================

describe('DEFAULT_ATTACK_PATTERNS — process_creation', () => {
  it('classifies encoded PowerShell commands as attack', () => {
    const logs = [makeSysmonLog(1, {
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      CommandLine: 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
    })];
    const result = normalizeOTRFLogs(logs, ['process_creation']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies LOLBin execution (rundll32) as attack', () => {
    const logs = [makeSysmonLog(1, {
      Image: 'C:\\Windows\\System32\\rundll32.exe',
      CommandLine: 'rundll32.exe comsvcs.dll MiniDump 123',
    })];
    const result = normalizeOTRFLogs(logs, ['process_creation']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies service-spawned shell as attack', () => {
    const logs = [makeSysmonLog(1, {
      Image: 'C:\\Windows\\System32\\cmd.exe',
      ParentImage: 'C:\\Windows\\System32\\services.exe',
      CommandLine: 'cmd.exe /c whoami',
    })];
    const result = normalizeOTRFLogs(logs, ['process_creation']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies credential store targeting as attack', () => {
    const logs = [makeSysmonLog(1, {
      Image: 'C:\\Windows\\System32\\reg.exe',
      CommandLine: 'reg save HKLM\\SAM C:\\temp\\sam.hiv',
    })];
    const result = normalizeOTRFLogs(logs, ['process_creation']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies seatbelt/discovery tool as attack', () => {
    const logs = [makeSysmonLog(1, {
      Image: 'C:\\Users\\attacker\\Desktop\\seatbelt.exe',
      CommandLine: 'seatbelt.exe -group=all',
    })];
    const result = normalizeOTRFLogs(logs, ['process_creation']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies net view/share enumeration as attack', () => {
    const logs = [makeSysmonLog(1, {
      Image: 'C:\\Windows\\System32\\net.exe',
      CommandLine: 'net view \\\\fileserver',
    })];
    const result = normalizeOTRFLogs(logs, ['process_creation']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies minidump command as attack', () => {
    const logs = [makeSysmonLog(1, {
      Image: 'C:\\Windows\\System32\\rundll32.exe',
      CommandLine: 'rundll32.exe comsvcs.dll, MiniDump 456 C:\\temp\\out.dmp full',
    })];
    const result = normalizeOTRFLogs(logs, ['process_creation']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// Process Access (EID 10) — attack pattern coverage
// ===========================================================================

describe('DEFAULT_ATTACK_PATTERNS — process_access', () => {
  it('classifies LSASS access as attack', () => {
    const logs = [makeSysmonLog(10, {
      SourceImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      TargetImage: 'C:\\Windows\\System32\\lsass.exe',
      GrantedAccess: '0x1010',
    })];
    const result = normalizeOTRFLogs(logs, ['process_access']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies suspicious GrantedAccess mask as attack', () => {
    const logs = [makeSysmonLog(10, {
      SourceImage: 'C:\\Users\\attacker\\novel.exe',
      TargetImage: 'C:\\Windows\\System32\\lsass.exe',
      GrantedAccess: '0x1fffff',
    })];
    const result = normalizeOTRFLogs(logs, ['process_access']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// Create Remote Thread (EID 8) — attack pattern coverage
// ===========================================================================

describe('DEFAULT_ATTACK_PATTERNS — create_remote_thread', () => {
  it('classifies LoadLibrary injection as attack', () => {
    const logs = [makeSysmonLog(8, {
      SourceImage: 'C:\\Users\\attacker\\injector.exe',
      TargetImage: 'C:\\Windows\\explorer.exe',
      StartFunction: 'LoadLibraryA',
    })];
    const result = normalizeOTRFLogs(logs, ['create_remote_thread']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies UNKNOWN CallTrace injection as attack', () => {
    const logs = [makeSysmonLog(8, {
      SourceImage: 'C:\\Users\\attacker\\injector.exe',
      TargetImage: 'C:\\Windows\\explorer.exe',
      CallTrace: 'C:\\Windows\\SYSTEM32\\ntdll.dll+UNKNOWN',
    })];
    const result = normalizeOTRFLogs(logs, ['create_remote_thread']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// Registry Set (EID 13) — attack pattern coverage
// ===========================================================================

describe('DEFAULT_ATTACK_PATTERNS — registry_set', () => {
  it('classifies Run key persistence as attack', () => {
    const logs = [makeSysmonLog(13, {
      Image: 'C:\\Windows\\System32\\reg.exe',
      TargetObject: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor',
      Details: 'C:\\Users\\attacker\\payload.exe',
    })];
    const result = normalizeOTRFLogs(logs, ['registry_set']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies WDigest downgrade as attack', () => {
    const logs = [makeSysmonLog(13, {
      Image: 'C:\\Windows\\System32\\reg.exe',
      TargetObject: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest',
      Details: 'DWORD (0x00000001)',
    })];
    const result = normalizeOTRFLogs(logs, ['registry_set']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// SourceImage patterns for injection detection
// ===========================================================================

describe('DEFAULT_ATTACK_PATTERNS — SourceImage injection patterns', () => {
  it('classifies powershell as injection source', () => {
    const logs = [makeSysmonLog(8, {
      SourceImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      TargetImage: 'C:\\Windows\\explorer.exe',
      StartFunction: 'SomeFunction',
    })];
    const result = normalizeOTRFLogs(logs, ['create_remote_thread']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies cmd.exe as injection source', () => {
    const logs = [makeSysmonLog(8, {
      SourceImage: 'C:\\Windows\\System32\\cmd.exe',
      TargetImage: 'C:\\Windows\\explorer.exe',
      StartFunction: 'SomeFunction',
    })];
    const result = normalizeOTRFLogs(logs, ['create_remote_thread']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });

  it('classifies mshta as injection source', () => {
    const logs = [makeSysmonLog(8, {
      SourceImage: 'C:\\Windows\\System32\\mshta.exe',
      TargetImage: 'C:\\Windows\\explorer.exe',
      StartFunction: 'SomeFunction',
    })];
    const result = normalizeOTRFLogs(logs, ['create_remote_thread']);
    expect(result).toHaveLength(1);
    expect(result[0].attackLogs.length).toBeGreaterThan(0);
  });
});
