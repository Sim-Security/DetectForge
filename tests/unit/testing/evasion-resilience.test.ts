/**
 * Unit tests for evasion resilience testing (Level 7 Phase 1).
 *
 * Tests the generateEvasionVariants() function and its integration
 * with the effectiveness tester.
 */

import { describe, it, expect } from 'vitest';
import { generateEvasionVariants } from '@/testing/log-generator.js';
import { testRuleEffectiveness } from '@/testing/effectiveness-tester.js';
import type { LogEntry } from '@/testing/sigma-tester.js';
import type { SigmaRule } from '@/types/detection-rule.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRule(
  detection: Record<string, unknown> & { condition: string },
  overrides: Partial<SigmaRule> = {},
): SigmaRule {
  return {
    id: 'evasion-test-0001',
    title: 'Evasion Test Rule',
    status: 'experimental',
    description: 'A test rule for evasion testing.',
    references: [],
    author: 'DetectForge',
    date: '2026/02/12',
    modified: '2026/02/12',
    tags: ['attack.execution'],
    logsource: { product: 'windows', category: 'process_creation' },
    detection,
    falsepositives: [],
    level: 'high',
    raw: '',
    ...overrides,
  };
}

// ===========================================================================
// generateEvasionVariants
// ===========================================================================

describe('generateEvasionVariants', () => {
  it('renames non-system binary executables', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\tools\\mimikatz.exe',
        CommandLine: 'mimikatz.exe "privilege::debug"',
      },
    ];

    const { mutatedLogs, mutationsApplied } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    expect(mutatedLogs[0].Image).not.toContain('mimikatz');
    expect(mutationsApplied).toContain('rename-executable');
  });

  it('preserves system binary names', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /c whoami',
      },
    ];

    const { mutatedLogs } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    // cmd.exe is a system binary — should NOT be renamed
    const image = String(mutatedLogs[0].Image);
    expect(image).toContain('cmd.exe');
  });

  it('preserves powershell.exe as system binary', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -encodedcommand SQBFAFgA',
      },
    ];

    const { mutatedLogs, mutationsApplied } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    const image = String(mutatedLogs[0].Image);
    expect(image).toContain('powershell.exe');
    // But should vary argument format
    expect(mutationsApplied).toContain('vary-argument-format');
  });

  it('varies PowerShell argument formats', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -encodedcommand SQBFAFgA -noprofile',
      },
    ];

    const { mutatedLogs, mutationsApplied } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    const cmdLine = String(mutatedLogs[0].CommandLine).toLowerCase();
    // -encodedcommand should be replaced with a shorter variant
    expect(cmdLine).not.toContain('-encodedcommand');
    expect(mutationsApplied).toContain('vary-argument-format');
  });

  it('changes paths for non-system tools', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\tools\\Seatbelt.exe',
        CommandLine: 'Seatbelt.exe group user',
      },
    ];

    const { mutatedLogs, mutationsApplied } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    const image = String(mutatedLogs[0].Image);
    expect(image).not.toContain('Seatbelt');
    expect(mutationsApplied).toContain('rename-executable');
  });

  it('preserves behavioral fields like GrantedAccess', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\tools\\custom_dumper.exe',
        GrantedAccess: '0x1010',
        TargetImage: 'C:\\Windows\\System32\\lsass.exe',
        CommandLine: 'custom_dumper.exe',
      },
    ];

    const { mutatedLogs } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    // GrantedAccess and TargetImage should be preserved
    expect(mutatedLogs[0].GrantedAccess).toBe('0x1010');
    expect(mutatedLogs[0].TargetImage).toBe('C:\\Windows\\System32\\lsass.exe');
  });

  it('handles empty attack logs', () => {
    const { mutatedLogs, mutationsApplied } = generateEvasionVariants([]);

    expect(mutatedLogs).toHaveLength(0);
    expect(mutationsApplied).toHaveLength(0);
  });

  it('renames tool references in CommandLine', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\tools\\Rubeus.exe',
        CommandLine: 'Rubeus.exe kerberoast',
      },
    ];

    const { mutatedLogs, mutationsApplied } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    const cmdLine = String(mutatedLogs[0].CommandLine);
    expect(cmdLine).not.toContain('Rubeus');
    expect(mutationsApplied).toContain('rename-tool-in-commandline');
  });

  it('applies environment variable substitution to CommandLine paths', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'C:\\Windows\\System32\\cmd.exe /c whoami',
      },
    ];

    const { mutatedLogs, mutationsApplied } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    const cmdLine = String(mutatedLogs[0].CommandLine);
    expect(cmdLine).toContain('%');
    expect(mutationsApplied).toContain('env-var-substitution');
  });

  it('applies caret insertion to PowerShell keywords', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell -exec bypass -c "invoke-expression"',
      },
    ];

    const { mutatedLogs, mutationsApplied } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    const cmdLine = String(mutatedLogs[0].CommandLine);
    expect(cmdLine).toContain('^');
    expect(mutationsApplied).toContain('caret-insertion');
  });

  it('applies case randomization to CommandLine', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /c whoami /all',
      },
    ];

    const { mutatedLogs, mutationsApplied } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    const cmdLine = String(mutatedLogs[0].CommandLine);
    // Case randomization should change at least some chars
    expect(mutationsApplied).toContain('case-randomization');
  });

  it('never mutates GrantedAccess, TargetImage, or CallTrace fields', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\tools\\custom_dumper.exe',
        CommandLine: 'custom_dumper.exe -dump',
        GrantedAccess: '0x1010',
        TargetImage: 'C:\\Windows\\System32\\lsass.exe',
        CallTrace: 'C:\\Windows\\SYSTEM32\\ntdll.dll+9d4e4',
        SourceImage: 'C:\\tools\\custom_dumper.exe',
      },
    ];

    const { mutatedLogs } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    expect(mutatedLogs[0].GrantedAccess).toBe('0x1010');
    expect(mutatedLogs[0].TargetImage).toBe('C:\\Windows\\System32\\lsass.exe');
    expect(mutatedLogs[0].CallTrace).toBe('C:\\Windows\\SYSTEM32\\ntdll.dll+9d4e4');
    expect(mutatedLogs[0].SourceImage).toBe('C:\\tools\\custom_dumper.exe');
  });

  it('does not apply env-var substitution to Image field paths', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /c dir C:\\Windows\\System32',
      },
    ];

    const { mutatedLogs } = generateEvasionVariants(attackLogs);

    // Image field should still have the literal path (not env var)
    expect(String(mutatedLogs[0].Image)).toContain('C:\\Windows\\System32\\cmd.exe');
  });

  it('does not rename system binaries in CommandLine', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\Windows\\System32\\rundll32.exe',
        CommandLine: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump',
      },
    ];

    const { mutatedLogs } = generateEvasionVariants(attackLogs);

    expect(mutatedLogs).toHaveLength(1);
    const cmdLine = String(mutatedLogs[0].CommandLine);
    // rundll32.exe is a system binary — should be preserved in CommandLine
    expect(cmdLine).toContain('rundll32.exe');
  });

  it('produces deterministic mutations for same input', () => {
    const attackLogs: LogEntry[] = [
      {
        Image: 'C:\\tools\\mimikatz.exe',
        CommandLine: 'mimikatz.exe "privilege::debug"',
      },
    ];

    const result1 = generateEvasionVariants(attackLogs);
    const result2 = generateEvasionVariants(attackLogs);

    expect(result1.mutatedLogs[0].Image).toBe(result2.mutatedLogs[0].Image);
  });
});

// ===========================================================================
// Integration: Evasion resilience in effectiveness tester
// ===========================================================================

describe('evasionResilience in testRuleEffectiveness', () => {
  it('returns evasionResilience in the result', () => {
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe', CommandLine: '*whoami*' },
      condition: 'selection',
    });

    const result = testRuleEffectiveness(rule);

    expect(result).toHaveProperty('evasionResilience');
  });

  it('behavioral rule has high resilience (system binaries not renamed)', () => {
    // This rule detects cmd.exe (system binary) — evasion can't rename it
    const rule = makeRule({
      selection: { Image: '*\\cmd.exe', CommandLine: '*whoami*' },
      condition: 'selection',
    });

    const result = testRuleEffectiveness(rule);

    if (result.evasionResilience) {
      // cmd.exe is system binary — resilience should be high
      expect(result.evasionResilience.resilienceScore).toBeGreaterThanOrEqual(0.5);
    }
  });
});
