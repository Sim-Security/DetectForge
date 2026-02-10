import { describe, it, expect } from 'vitest';
import {
  getLinuxLogMapping,
  getLinuxFieldsForSource,
  getLinuxSigmaLogsource,
  getAllLinuxSources,
} from '@/knowledge/logsource-catalog/linux.js';

// ---------------------------------------------------------------------------
// getLinuxLogMapping
// ---------------------------------------------------------------------------

describe('getLinuxLogMapping', () => {
  it('returns mapping for auditd', () => {
    const m = getLinuxLogMapping('auditd');
    expect(m).toBeDefined();
    expect(m!.source).toBe('auditd');
    expect(m!.sigmaProduct).toBe('linux');
    expect(m!.sigmaService).toBe('auditd');
    expect(m!.sigmaCategory).toBe('process_creation');
    expect(m!.fields).toContain('type');
    expect(m!.fields).toContain('syscall');
    expect(m!.fields).toContain('exe');
    expect(m!.fields).toContain('comm');
    expect(m!.fields).toContain('key');
  });

  it('returns mapping for auditd_auth', () => {
    const m = getLinuxLogMapping('auditd_auth');
    expect(m).toBeDefined();
    expect(m!.sigmaProduct).toBe('linux');
    expect(m!.sigmaService).toBe('auditd');
    expect(m!.fields).toContain('acct');
    expect(m!.fields).toContain('hostname');
    expect(m!.fields).toContain('addr');
    expect(m!.fields).toContain('terminal');
    expect(m!.fields).toContain('res');
  });

  it('returns mapping for syslog', () => {
    const m = getLinuxLogMapping('syslog');
    expect(m).toBeDefined();
    expect(m!.sigmaProduct).toBe('linux');
    expect(m!.sigmaService).toBe('syslog');
    expect(m!.fields).toContain('timestamp');
    expect(m!.fields).toContain('hostname');
    expect(m!.fields).toContain('program');
    expect(m!.fields).toContain('message');
  });

  it('returns mapping for auth', () => {
    const m = getLinuxLogMapping('auth');
    expect(m).toBeDefined();
    expect(m!.sigmaProduct).toBe('linux');
    expect(m!.sigmaService).toBe('auth');
    expect(m!.fields).toContain('timestamp');
    expect(m!.fields).toContain('hostname');
    expect(m!.fields).toContain('program');
    expect(m!.fields).toContain('message');
  });

  it('returns mapping for journal (systemd)', () => {
    const m = getLinuxLogMapping('journal');
    expect(m).toBeDefined();
    expect(m!.sigmaProduct).toBe('linux');
    expect(m!.sigmaService).toBe('journal');
    expect(m!.fields).toContain('__REALTIME_TIMESTAMP');
    expect(m!.fields).toContain('_HOSTNAME');
    expect(m!.fields).toContain('_COMM');
    expect(m!.fields).toContain('_PID');
    expect(m!.fields).toContain('_UID');
    expect(m!.fields).toContain('MESSAGE');
    expect(m!.fields).toContain('SYSLOG_IDENTIFIER');
  });

  it('returns mapping for cron', () => {
    const m = getLinuxLogMapping('cron');
    expect(m).toBeDefined();
    expect(m!.sigmaService).toBe('cron');
    expect(m!.fields).toContain('command');
  });

  it('returns mapping for sudo', () => {
    const m = getLinuxLogMapping('sudo');
    expect(m).toBeDefined();
    expect(m!.sigmaService).toBe('sudo');
    expect(m!.fields).toContain('command');
    expect(m!.fields).toContain('user');
  });

  it('returns mapping for dpkg', () => {
    const m = getLinuxLogMapping('dpkg');
    expect(m).toBeDefined();
    expect(m!.sigmaService).toBe('dpkg');
    expect(m!.fields).toContain('package');
    expect(m!.fields).toContain('action');
  });

  it('returns mapping for apache', () => {
    const m = getLinuxLogMapping('apache');
    expect(m).toBeDefined();
    expect(m!.sigmaService).toBe('apache');
    expect(m!.fields).toContain('method');
    expect(m!.fields).toContain('uri');
    expect(m!.fields).toContain('status');
  });

  it('returns mapping for sshd', () => {
    const m = getLinuxLogMapping('sshd');
    expect(m).toBeDefined();
    expect(m!.sigmaService).toBe('sshd');
    expect(m!.fields).toContain('user');
    expect(m!.fields).toContain('rhost');
    expect(m!.fields).toContain('method');
  });

  it('returns undefined for an unknown source', () => {
    expect(getLinuxLogMapping('nonexistent')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// getLinuxFieldsForSource
// ---------------------------------------------------------------------------

describe('getLinuxFieldsForSource', () => {
  it('returns fields for auditd including type, syscall, exe, and pid', () => {
    const fields = getLinuxFieldsForSource('auditd');
    expect(fields).toContain('type');
    expect(fields).toContain('syscall');
    expect(fields).toContain('exe');
    expect(fields).toContain('pid');
    expect(fields).toContain('uid');
  });

  it('returns fields for syslog including timestamp and message', () => {
    const fields = getLinuxFieldsForSource('syslog');
    expect(fields).toContain('timestamp');
    expect(fields).toContain('message');
  });

  it('returns fields for journal including systemd-specific names', () => {
    const fields = getLinuxFieldsForSource('journal');
    expect(fields).toContain('__REALTIME_TIMESTAMP');
    expect(fields).toContain('_SYSTEMD_UNIT');
    expect(fields).toContain('MESSAGE');
  });

  it('returns an empty array for an unknown source', () => {
    expect(getLinuxFieldsForSource('nonexistent')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// getLinuxSigmaLogsource
// ---------------------------------------------------------------------------

describe('getLinuxSigmaLogsource', () => {
  it('returns product=linux, service=auditd, category=process_creation for auditd', () => {
    const result = getLinuxSigmaLogsource('auditd');
    expect(result.product).toBe('linux');
    expect(result.service).toBe('auditd');
    expect(result.category).toBe('process_creation');
  });

  it('returns product=linux, service=syslog for syslog (no category)', () => {
    const result = getLinuxSigmaLogsource('syslog');
    expect(result.product).toBe('linux');
    expect(result.service).toBe('syslog');
    expect(result.category).toBeUndefined();
  });

  it('returns product=linux, service=auth for auth', () => {
    const result = getLinuxSigmaLogsource('auth');
    expect(result.product).toBe('linux');
    expect(result.service).toBe('auth');
  });

  it('returns product=linux, service=journal for journal', () => {
    const result = getLinuxSigmaLogsource('journal');
    expect(result.product).toBe('linux');
    expect(result.service).toBe('journal');
  });

  it('returns product=linux with no service for an unknown source', () => {
    const result = getLinuxSigmaLogsource('nonexistent');
    expect(result.product).toBe('linux');
    expect(result.service).toBeUndefined();
    expect(result.category).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// getAllLinuxSources
// ---------------------------------------------------------------------------

describe('getAllLinuxSources', () => {
  it('returns all registered Linux log source mappings', () => {
    const sources = getAllLinuxSources();
    expect(sources.length).toBeGreaterThanOrEqual(10);
  });

  it('all sources have sigmaProduct = "linux"', () => {
    for (const src of getAllLinuxSources()) {
      expect(src.sigmaProduct).toBe('linux');
    }
  });

  it('all sources have a non-empty fields array', () => {
    for (const src of getAllLinuxSources()) {
      expect(src.fields.length).toBeGreaterThan(0);
    }
  });

  it('all sources have a non-empty description', () => {
    for (const src of getAllLinuxSources()) {
      expect(src.description.length).toBeGreaterThan(0);
    }
  });

  it('source names are unique', () => {
    const names = getAllLinuxSources().map((s) => s.source);
    expect(new Set(names).size).toBe(names.length);
  });
});
