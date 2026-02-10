import { describe, it, expect } from 'vitest';
import {
  getSigmaLogsource,
  getFieldsForLogsource,
  validateSigmaLogsource,
} from '@/knowledge/logsource-catalog/index.js';

// ---------------------------------------------------------------------------
// getSigmaLogsource — unified resolver
// ---------------------------------------------------------------------------

describe('getSigmaLogsource', () => {
  // Windows
  it('resolves Windows Event 4688 to product=windows, service=security, category=process_creation', () => {
    const result = getSigmaLogsource('windows', 4688);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('security');
    expect(result.category).toBe('process_creation');
  });

  it('resolves Windows Event 7045 to product=windows, service=system', () => {
    const result = getSigmaLogsource('windows', 7045);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('system');
  });

  it('returns a default for windows without an event ID', () => {
    const result = getSigmaLogsource('windows');
    expect(result.product).toBe('windows');
    expect(result.service).toBe('security');
  });

  // Sysmon
  it('resolves Sysmon Event 1 to product=windows, service=sysmon, category=process_creation', () => {
    const result = getSigmaLogsource('sysmon', 1);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('sysmon');
    expect(result.category).toBe('process_creation');
  });

  it('resolves Sysmon Event 22 to category=dns_query', () => {
    const result = getSigmaLogsource('sysmon', 22);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('sysmon');
    expect(result.category).toBe('dns_query');
  });

  it('returns a default for sysmon without an event ID', () => {
    const result = getSigmaLogsource('sysmon');
    expect(result.product).toBe('windows');
    expect(result.service).toBe('sysmon');
  });

  it('returns default sysmon when event ID is out of range', () => {
    const result = getSigmaLogsource('sysmon', 999);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('sysmon');
  });

  // Linux
  it('resolves "auditd" to product=linux, service=auditd, category=process_creation', () => {
    const result = getSigmaLogsource('auditd');
    expect(result.product).toBe('linux');
    expect(result.service).toBe('auditd');
    expect(result.category).toBe('process_creation');
  });

  it('resolves "syslog" to product=linux, service=syslog', () => {
    const result = getSigmaLogsource('syslog');
    expect(result.product).toBe('linux');
    expect(result.service).toBe('syslog');
  });

  it('resolves "auth" to product=linux, service=auth', () => {
    const result = getSigmaLogsource('auth');
    expect(result.product).toBe('linux');
    expect(result.service).toBe('auth');
  });

  it('resolves "journal" to product=linux, service=journal', () => {
    const result = getSigmaLogsource('journal');
    expect(result.product).toBe('linux');
    expect(result.service).toBe('journal');
  });

  // Case insensitivity
  it('handles uppercase event source names', () => {
    const result = getSigmaLogsource('WINDOWS', 4624);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('security');
  });

  it('handles mixed-case "Sysmon"', () => {
    const result = getSigmaLogsource('Sysmon', 1);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('sysmon');
    expect(result.category).toBe('process_creation');
  });

  // Unknown
  it('returns product=linux for an unknown Linux-like source', () => {
    const result = getSigmaLogsource('unknownsource');
    expect(result.product).toBe('linux');
    expect(result.service).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// getFieldsForLogsource
// ---------------------------------------------------------------------------

describe('getFieldsForLogsource', () => {
  it('returns Sysmon process_creation fields for windows + process_creation', () => {
    const fields = getFieldsForLogsource('windows', 'process_creation');
    expect(fields).toContain('CommandLine');
    expect(fields).toContain('ParentCommandLine');
    expect(fields).toContain('Image');
  });

  it('returns Windows logon fields for windows + logon', () => {
    const fields = getFieldsForLogsource('windows', 'logon');
    expect(fields).toContain('LogonType');
    expect(fields).toContain('IpAddress');
    expect(fields).toContain('TargetUserName');
  });

  it('returns aggregated fields for windows + sysmon service with no category', () => {
    const fields = getFieldsForLogsource('windows', undefined, 'sysmon');
    expect(fields.length).toBeGreaterThan(10);
    // Should include fields from multiple sysmon events
    expect(fields).toContain('CommandLine');
    expect(fields).toContain('DestinationIp');
    expect(fields).toContain('QueryName');
  });

  it('returns aggregated fields for windows security service with no category', () => {
    const fields = getFieldsForLogsource('windows', undefined, 'security');
    expect(fields.length).toBeGreaterThan(10);
    expect(fields).toContain('CommandLine');
    expect(fields).toContain('LogonType');
  });

  it('returns fields for registry_set via Sysmon', () => {
    const fields = getFieldsForLogsource('windows', 'registry_set');
    expect(fields).toContain('TargetObject');
    expect(fields).toContain('Details');
  });

  it('returns fields for dns_query via Sysmon', () => {
    const fields = getFieldsForLogsource('windows', 'dns_query');
    expect(fields).toContain('QueryName');
    expect(fields).toContain('QueryResults');
  });

  it('returns auditd fields for linux + auditd service', () => {
    const fields = getFieldsForLogsource('linux', undefined, 'auditd');
    expect(fields).toContain('type');
    expect(fields).toContain('syscall');
    expect(fields).toContain('exe');
  });

  it('returns auth fields for linux + auth service', () => {
    const fields = getFieldsForLogsource('linux', undefined, 'auth');
    expect(fields).toContain('timestamp');
    expect(fields).toContain('hostname');
    expect(fields).toContain('message');
  });

  it('returns aggregated fields for linux with no service or category', () => {
    const fields = getFieldsForLogsource('linux');
    expect(fields.length).toBeGreaterThan(10);
  });

  it('returns an empty array for an unknown product', () => {
    expect(getFieldsForLogsource('macos')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// validateSigmaLogsource
// ---------------------------------------------------------------------------

describe('validateSigmaLogsource', () => {
  // Valid combinations
  it('validates windows product', () => {
    expect(validateSigmaLogsource('windows')).toBe(true);
  });

  it('validates linux product', () => {
    expect(validateSigmaLogsource('linux')).toBe(true);
  });

  it('validates windows + process_creation', () => {
    expect(validateSigmaLogsource('windows', 'process_creation')).toBe(true);
  });

  it('validates windows + security service', () => {
    expect(validateSigmaLogsource('windows', undefined, 'security')).toBe(true);
  });

  it('validates windows + sysmon service', () => {
    expect(validateSigmaLogsource('windows', undefined, 'sysmon')).toBe(true);
  });

  it('validates windows + system service', () => {
    expect(validateSigmaLogsource('windows', undefined, 'system')).toBe(true);
  });

  it('validates linux + auditd service', () => {
    expect(validateSigmaLogsource('linux', undefined, 'auditd')).toBe(true);
  });

  it('validates linux + syslog service', () => {
    expect(validateSigmaLogsource('linux', undefined, 'syslog')).toBe(true);
  });

  it('validates windows + dns_query category', () => {
    expect(validateSigmaLogsource('windows', 'dns_query')).toBe(true);
  });

  it('validates windows + registry_set category', () => {
    expect(validateSigmaLogsource('windows', 'registry_set')).toBe(true);
  });

  it('validates windows + image_load category', () => {
    expect(validateSigmaLogsource('windows', 'image_load')).toBe(true);
  });

  it('validates full triple: windows + process_creation + sysmon', () => {
    expect(validateSigmaLogsource('windows', 'process_creation', 'sysmon')).toBe(true);
  });

  // Invalid combinations
  it('rejects an unknown product', () => {
    expect(validateSigmaLogsource('macos')).toBe(false);
  });

  it('rejects an unknown category with a valid product', () => {
    expect(validateSigmaLogsource('windows', 'nonexistent_category')).toBe(false);
  });

  it('rejects an unknown service with a valid product', () => {
    expect(validateSigmaLogsource('windows', undefined, 'nonexistent_service')).toBe(false);
  });

  it('rejects when both category and service are unknown', () => {
    expect(validateSigmaLogsource('windows', 'bad_cat', 'bad_svc')).toBe(false);
  });

  // Case sensitivity
  it('is case-insensitive for product names', () => {
    expect(validateSigmaLogsource('Windows')).toBe(true);
    expect(validateSigmaLogsource('LINUX')).toBe(true);
  });

  it('is case-insensitive for service names', () => {
    expect(validateSigmaLogsource('windows', undefined, 'Security')).toBe(true);
    expect(validateSigmaLogsource('windows', undefined, 'SYSMON')).toBe(true);
  });
});
