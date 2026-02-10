import { describe, it, expect } from 'vitest';
import {
  getWindowsEventMapping,
  getWindowsEventsByCategory,
  getWindowsFieldsForEvent,
  getSigmaLogsourceForEvent,
  getAllWindowsEventMappings,
} from '@/knowledge/logsource-catalog/windows.js';

// ---------------------------------------------------------------------------
// getWindowsEventMapping
// ---------------------------------------------------------------------------

describe('getWindowsEventMapping', () => {
  it('returns the mapping for Event ID 4688 (Process Creation)', () => {
    const mapping = getWindowsEventMapping(4688);
    expect(mapping).toBeDefined();
    expect(mapping!.eventId).toBe(4688);
    expect(mapping!.channel).toBe('Security');
    expect(mapping!.description).toContain('process');
    expect(mapping!.category).toBe('process_creation');
    expect(mapping!.sigmaProduct).toBe('windows');
    expect(mapping!.sigmaService).toBe('security');
  });

  it('returns the mapping for Event ID 4624 (Successful Logon)', () => {
    const mapping = getWindowsEventMapping(4624);
    expect(mapping).toBeDefined();
    expect(mapping!.eventId).toBe(4624);
    expect(mapping!.channel).toBe('Security');
    expect(mapping!.category).toBe('logon');
    expect(mapping!.fields).toContain('LogonType');
    expect(mapping!.fields).toContain('IpAddress');
  });

  it('returns the mapping for Event ID 4625 (Failed Logon)', () => {
    const mapping = getWindowsEventMapping(4625);
    expect(mapping).toBeDefined();
    expect(mapping!.eventId).toBe(4625);
    expect(mapping!.category).toBe('logon');
    expect(mapping!.fields).toContain('Status');
    expect(mapping!.fields).toContain('FailureReason');
    expect(mapping!.fields).toContain('SubStatus');
  });

  it('returns the mapping for Event ID 4672 (Special Privileges)', () => {
    const mapping = getWindowsEventMapping(4672);
    expect(mapping).toBeDefined();
    expect(mapping!.category).toBe('logon');
    expect(mapping!.fields).toContain('PrivilegeList');
  });

  it('returns the mapping for Event ID 4720 (User Account Created)', () => {
    const mapping = getWindowsEventMapping(4720);
    expect(mapping).toBeDefined();
    expect(mapping!.category).toBe('account_management');
    expect(mapping!.fields).toContain('TargetUserName');
    expect(mapping!.fields).toContain('SamAccountName');
  });

  it('returns the mapping for Event ID 4732 (Member Added to Group)', () => {
    const mapping = getWindowsEventMapping(4732);
    expect(mapping).toBeDefined();
    expect(mapping!.category).toBe('account_management');
    expect(mapping!.fields).toContain('MemberName');
    expect(mapping!.fields).toContain('MemberSid');
  });

  it('returns the mapping for Event ID 4648 (Explicit Credential Logon)', () => {
    const mapping = getWindowsEventMapping(4648);
    expect(mapping).toBeDefined();
    expect(mapping!.category).toBe('logon');
    expect(mapping!.fields).toContain('TargetServerName');
  });

  it('returns the mapping for Event ID 4663 (Object Access)', () => {
    const mapping = getWindowsEventMapping(4663);
    expect(mapping).toBeDefined();
    expect(mapping!.category).toBe('object_access');
    expect(mapping!.fields).toContain('ObjectName');
    expect(mapping!.fields).toContain('AccessMask');
  });

  it('returns the mapping for Event ID 4670 (Permissions Changed)', () => {
    const mapping = getWindowsEventMapping(4670);
    expect(mapping).toBeDefined();
    expect(mapping!.category).toBe('object_access');
    expect(mapping!.fields).toContain('OldSd');
    expect(mapping!.fields).toContain('NewSd');
  });

  it('returns the mapping for Event ID 4697 (Service Installed)', () => {
    const mapping = getWindowsEventMapping(4697);
    expect(mapping).toBeDefined();
    expect(mapping!.fields).toContain('ServiceName');
    expect(mapping!.fields).toContain('ServiceFileName');
  });

  it('returns the mapping for Event ID 4698 (Scheduled Task Created)', () => {
    const mapping = getWindowsEventMapping(4698);
    expect(mapping).toBeDefined();
    expect(mapping!.fields).toContain('TaskName');
    expect(mapping!.fields).toContain('TaskContent');
  });

  it('returns the mapping for Event ID 4699 (Scheduled Task Deleted)', () => {
    const mapping = getWindowsEventMapping(4699);
    expect(mapping).toBeDefined();
    expect(mapping!.fields).toContain('TaskName');
  });

  it('returns the mapping for Event ID 4700 (Scheduled Task Enabled)', () => {
    const mapping = getWindowsEventMapping(4700);
    expect(mapping).toBeDefined();
    expect(mapping!.fields).toContain('TaskName');
  });

  it('returns the mapping for Event ID 4703 (Token Right Adjusted)', () => {
    const mapping = getWindowsEventMapping(4703);
    expect(mapping).toBeDefined();
    expect(mapping!.fields).toContain('EnabledPrivilegeList');
    expect(mapping!.fields).toContain('DisabledPrivilegeList');
  });

  it('returns the mapping for Event ID 4719 (Audit Policy Changed)', () => {
    const mapping = getWindowsEventMapping(4719);
    expect(mapping).toBeDefined();
    expect(mapping!.category).toBe('policy_change');
    expect(mapping!.fields).toContain('AuditPolicyChanges');
  });

  it('returns the mapping for Event ID 4768 (Kerberos TGT Request)', () => {
    const mapping = getWindowsEventMapping(4768);
    expect(mapping).toBeDefined();
    expect(mapping!.category).toBe('logon');
    expect(mapping!.fields).toContain('TicketOptions');
    expect(mapping!.fields).toContain('TicketEncryptionType');
  });

  it('returns the mapping for Event ID 4769 (Kerberos Service Ticket)', () => {
    const mapping = getWindowsEventMapping(4769);
    expect(mapping).toBeDefined();
    expect(mapping!.fields).toContain('ServiceName');
    expect(mapping!.fields).toContain('TicketEncryptionType');
  });

  it('returns the mapping for Event ID 4771 (Kerberos Pre-Auth Failed)', () => {
    const mapping = getWindowsEventMapping(4771);
    expect(mapping).toBeDefined();
    expect(mapping!.fields).toContain('Status');
    expect(mapping!.fields).toContain('PreAuthType');
  });

  it('returns the mapping for Event ID 7045 (Service Created - System log)', () => {
    const mapping = getWindowsEventMapping(7045);
    expect(mapping).toBeDefined();
    expect(mapping!.channel).toBe('System');
    expect(mapping!.sigmaService).toBe('system');
    expect(mapping!.fields).toContain('ServiceName');
    expect(mapping!.fields).toContain('ImagePath');
  });

  it('returns the mapping for Event ID 1102 (Audit Log Cleared)', () => {
    const mapping = getWindowsEventMapping(1102);
    expect(mapping).toBeDefined();
    expect(mapping!.category).toBe('audit_log_cleared');
    expect(mapping!.channel).toBe('Security');
  });

  it('returns undefined for an unknown event ID', () => {
    expect(getWindowsEventMapping(9999)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// getWindowsEventsByCategory
// ---------------------------------------------------------------------------

describe('getWindowsEventsByCategory', () => {
  it('returns multiple events for the "logon" category', () => {
    const events = getWindowsEventsByCategory('logon');
    expect(events.length).toBeGreaterThanOrEqual(5);

    const eventIds = events.map((e) => e.eventId);
    expect(eventIds).toContain(4624);
    expect(eventIds).toContain(4625);
    expect(eventIds).toContain(4672);
    expect(eventIds).toContain(4648);
    expect(eventIds).toContain(4768);
  });

  it('returns events for "account_management"', () => {
    const events = getWindowsEventsByCategory('account_management');
    expect(events.length).toBeGreaterThanOrEqual(2);
    const eventIds = events.map((e) => e.eventId);
    expect(eventIds).toContain(4720);
    expect(eventIds).toContain(4732);
  });

  it('returns events for "object_access"', () => {
    const events = getWindowsEventsByCategory('object_access');
    expect(events.length).toBeGreaterThanOrEqual(2);
    const eventIds = events.map((e) => e.eventId);
    expect(eventIds).toContain(4663);
    expect(eventIds).toContain(4670);
  });

  it('returns an empty array for an unknown category', () => {
    expect(getWindowsEventsByCategory('nonexistent')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// getWindowsFieldsForEvent
// ---------------------------------------------------------------------------

describe('getWindowsFieldsForEvent', () => {
  it('returns fields for Event ID 4688 including CommandLine', () => {
    const fields = getWindowsFieldsForEvent(4688);
    expect(fields).toContain('CommandLine');
    expect(fields).toContain('NewProcessName');
    expect(fields).toContain('ParentProcessName');
  });

  it('returns fields for Event ID 4624 including LogonType and IpAddress', () => {
    const fields = getWindowsFieldsForEvent(4624);
    expect(fields).toContain('LogonType');
    expect(fields).toContain('IpAddress');
    expect(fields).toContain('TargetUserName');
  });

  it('returns an empty array for an unknown event ID', () => {
    expect(getWindowsFieldsForEvent(9999)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// getSigmaLogsourceForEvent
// ---------------------------------------------------------------------------

describe('getSigmaLogsourceForEvent', () => {
  it('returns product=windows, service=security for Security log events', () => {
    const result = getSigmaLogsourceForEvent(4688);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('security');
  });

  it('includes the category for process_creation events (4688)', () => {
    const result = getSigmaLogsourceForEvent(4688);
    expect(result.category).toBe('process_creation');
  });

  it('includes the category for logon events (4624)', () => {
    const result = getSigmaLogsourceForEvent(4624);
    expect(result.category).toBe('logon');
  });

  it('returns product=windows, service=system for System log events', () => {
    const result = getSigmaLogsourceForEvent(7045);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('system');
  });

  it('returns a sensible default for unknown event IDs', () => {
    const result = getSigmaLogsourceForEvent(9999);
    expect(result.product).toBe('windows');
    expect(result.service).toBe('security');
  });
});

// ---------------------------------------------------------------------------
// getAllWindowsEventMappings
// ---------------------------------------------------------------------------

describe('getAllWindowsEventMappings', () => {
  it('returns all 20 registered event mappings', () => {
    const all = getAllWindowsEventMappings();
    expect(all.length).toBe(20);
  });

  it('every mapping has a non-empty fields array', () => {
    for (const mapping of getAllWindowsEventMappings()) {
      expect(mapping.fields.length).toBeGreaterThan(0);
    }
  });

  it('every mapping has sigmaProduct = "windows"', () => {
    for (const mapping of getAllWindowsEventMappings()) {
      expect(mapping.sigmaProduct).toBe('windows');
    }
  });
});
