import { describe, it, expect } from 'vitest';
import {
  getSysmonEventMapping,
  getSysmonEventByCategory,
  getSysmonFields,
  getAllSigmaCategories,
  getAllSysmonEventMappings,
} from '@/knowledge/logsource-catalog/sysmon.js';

// ---------------------------------------------------------------------------
// getSysmonEventMapping — test all 29 events
// ---------------------------------------------------------------------------

describe('getSysmonEventMapping', () => {
  it('returns Process Creation for Event ID 1', () => {
    const m = getSysmonEventMapping(1);
    expect(m).toBeDefined();
    expect(m!.eventId).toBe(1);
    expect(m!.name).toBe('ProcessCreate');
    expect(m!.sigmaCategory).toBe('process_creation');
    expect(m!.fields).toContain('CommandLine');
    expect(m!.fields).toContain('ParentCommandLine');
    expect(m!.fields).toContain('Image');
    expect(m!.fields).toContain('ParentImage');
    expect(m!.fields).toContain('User');
    expect(m!.fields).toContain('OriginalFileName');
    expect(m!.fields).toContain('Hashes');
  });

  it('returns File Creation Time Changed for Event ID 2', () => {
    const m = getSysmonEventMapping(2);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('file_change');
    expect(m!.fields).toContain('TargetFilename');
    expect(m!.fields).toContain('PreviousCreationUtcTime');
  });

  it('returns Network Connection for Event ID 3', () => {
    const m = getSysmonEventMapping(3);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('network_connection');
    expect(m!.fields).toContain('DestinationIp');
    expect(m!.fields).toContain('DestinationPort');
    expect(m!.fields).toContain('SourceIp');
    expect(m!.fields).toContain('Protocol');
  });

  it('returns Sysmon Service State Changed for Event ID 4', () => {
    const m = getSysmonEventMapping(4);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('sysmon_status');
    expect(m!.fields).toContain('State');
  });

  it('returns Process Terminated for Event ID 5', () => {
    const m = getSysmonEventMapping(5);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('process_termination');
  });

  it('returns Driver Loaded for Event ID 6', () => {
    const m = getSysmonEventMapping(6);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('driver_load');
    expect(m!.fields).toContain('ImageLoaded');
    expect(m!.fields).toContain('Signed');
  });

  it('returns Image Loaded for Event ID 7', () => {
    const m = getSysmonEventMapping(7);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('image_load');
    expect(m!.fields).toContain('ImageLoaded');
    expect(m!.fields).toContain('OriginalFileName');
  });

  it('returns Create Remote Thread for Event ID 8', () => {
    const m = getSysmonEventMapping(8);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('create_remote_thread');
    expect(m!.fields).toContain('SourceImage');
    expect(m!.fields).toContain('TargetImage');
    expect(m!.fields).toContain('StartAddress');
  });

  it('returns Raw Access Read for Event ID 9', () => {
    const m = getSysmonEventMapping(9);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('raw_access_thread');
    expect(m!.fields).toContain('Device');
  });

  it('returns Process Access for Event ID 10', () => {
    const m = getSysmonEventMapping(10);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('process_access');
    expect(m!.fields).toContain('GrantedAccess');
    expect(m!.fields).toContain('CallTrace');
    expect(m!.fields).toContain('SourceImage');
    expect(m!.fields).toContain('TargetImage');
  });

  it('returns File Created for Event ID 11', () => {
    const m = getSysmonEventMapping(11);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('file_event');
    expect(m!.fields).toContain('TargetFilename');
  });

  it('returns Registry Add/Delete for Event ID 12', () => {
    const m = getSysmonEventMapping(12);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('registry_add');
    expect(m!.fields).toContain('TargetObject');
    expect(m!.fields).toContain('EventType');
  });

  it('returns Registry Value Set for Event ID 13', () => {
    const m = getSysmonEventMapping(13);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('registry_set');
    expect(m!.fields).toContain('TargetObject');
    expect(m!.fields).toContain('Details');
  });

  it('returns Registry Rename for Event ID 14', () => {
    const m = getSysmonEventMapping(14);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('registry_rename');
    expect(m!.fields).toContain('TargetObject');
    expect(m!.fields).toContain('NewName');
  });

  it('returns File Stream Created for Event ID 15', () => {
    const m = getSysmonEventMapping(15);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('file_event');
    expect(m!.fields).toContain('TargetFilename');
    expect(m!.fields).toContain('Contents');
  });

  it('returns Sysmon Config State Changed for Event ID 16', () => {
    const m = getSysmonEventMapping(16);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('sysmon_status');
    expect(m!.fields).toContain('Configuration');
  });

  it('returns Pipe Created for Event ID 17', () => {
    const m = getSysmonEventMapping(17);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('pipe_created');
    expect(m!.fields).toContain('PipeName');
  });

  it('returns Pipe Connected for Event ID 18', () => {
    const m = getSysmonEventMapping(18);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('pipe_connected');
    expect(m!.fields).toContain('PipeName');
  });

  it('returns WMI Event Filter for Event ID 19', () => {
    const m = getSysmonEventMapping(19);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('wmi_event');
    expect(m!.fields).toContain('Query');
    expect(m!.fields).toContain('EventNamespace');
  });

  it('returns WMI Event Consumer for Event ID 20', () => {
    const m = getSysmonEventMapping(20);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('wmi_event');
    expect(m!.fields).toContain('Destination');
    expect(m!.fields).toContain('Type');
  });

  it('returns WMI Event Consumer to Filter for Event ID 21', () => {
    const m = getSysmonEventMapping(21);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('wmi_event');
    expect(m!.fields).toContain('Consumer');
    expect(m!.fields).toContain('Filter');
  });

  it('returns DNS Query for Event ID 22', () => {
    const m = getSysmonEventMapping(22);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('dns_query');
    expect(m!.fields).toContain('QueryName');
    expect(m!.fields).toContain('QueryResults');
  });

  it('returns File Delete for Event ID 23', () => {
    const m = getSysmonEventMapping(23);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('file_delete');
    expect(m!.fields).toContain('TargetFilename');
    expect(m!.fields).toContain('Archived');
  });

  it('returns Clipboard Change for Event ID 24', () => {
    const m = getSysmonEventMapping(24);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('clipboard_change');
    expect(m!.fields).toContain('Session');
    expect(m!.fields).toContain('ClientInfo');
  });

  it('returns Process Tampering for Event ID 25', () => {
    const m = getSysmonEventMapping(25);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('process_tampering');
    expect(m!.fields).toContain('Type');
  });

  it('returns File Delete Detected for Event ID 26', () => {
    const m = getSysmonEventMapping(26);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('file_delete');
    expect(m!.fields).toContain('TargetFilename');
    expect(m!.fields).toContain('IsExecutable');
  });

  it('returns File Block Executable for Event ID 27', () => {
    const m = getSysmonEventMapping(27);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('file_block_executable');
  });

  it('returns File Block Shredding for Event ID 28', () => {
    const m = getSysmonEventMapping(28);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('file_block_shredding');
  });

  it('returns File Executable Detected for Event ID 29', () => {
    const m = getSysmonEventMapping(29);
    expect(m).toBeDefined();
    expect(m!.sigmaCategory).toBe('file_executable_detected');
  });

  it('returns undefined for event ID 0 (no such Sysmon event)', () => {
    expect(getSysmonEventMapping(0)).toBeUndefined();
  });

  it('returns undefined for event ID 30 (out of range)', () => {
    expect(getSysmonEventMapping(30)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// getSysmonEventByCategory
// ---------------------------------------------------------------------------

describe('getSysmonEventByCategory', () => {
  it('returns Event ID 1 for "process_creation"', () => {
    const m = getSysmonEventByCategory('process_creation');
    expect(m).toBeDefined();
    expect(m!.eventId).toBe(1);
  });

  it('returns Event ID 3 for "network_connection"', () => {
    const m = getSysmonEventByCategory('network_connection');
    expect(m).toBeDefined();
    expect(m!.eventId).toBe(3);
  });

  it('returns Event ID 22 for "dns_query"', () => {
    const m = getSysmonEventByCategory('dns_query');
    expect(m).toBeDefined();
    expect(m!.eventId).toBe(22);
  });

  it('returns Event ID 12 for "registry_add"', () => {
    const m = getSysmonEventByCategory('registry_add');
    expect(m).toBeDefined();
    expect(m!.eventId).toBe(12);
  });

  it('returns Event ID 12 for "registry_delete"', () => {
    const m = getSysmonEventByCategory('registry_delete');
    expect(m).toBeDefined();
    expect(m!.eventId).toBe(12);
  });

  it('returns Event ID 13 for "registry_set"', () => {
    const m = getSysmonEventByCategory('registry_set');
    expect(m).toBeDefined();
    expect(m!.eventId).toBe(13);
  });

  it('returns Event ID 23 for "file_delete"', () => {
    const m = getSysmonEventByCategory('file_delete');
    expect(m).toBeDefined();
    expect(m!.eventId).toBe(23);
  });

  it('returns undefined for an unknown category', () => {
    expect(getSysmonEventByCategory('nonexistent')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// getSysmonFields
// ---------------------------------------------------------------------------

describe('getSysmonFields', () => {
  it('returns all 22 fields for Event ID 1 (Process Creation)', () => {
    const fields = getSysmonFields(1);
    expect(fields.length).toBe(22);
    expect(fields).toContain('CommandLine');
    expect(fields).toContain('ParentCommandLine');
    expect(fields).toContain('OriginalFileName');
    expect(fields).toContain('Hashes');
    expect(fields).toContain('IntegrityLevel');
    expect(fields).toContain('ParentUser');
  });

  it('returns fields for Event ID 3 (Network Connection) with IP details', () => {
    const fields = getSysmonFields(3);
    expect(fields).toContain('DestinationIp');
    expect(fields).toContain('DestinationPort');
    expect(fields).toContain('DestinationHostname');
    expect(fields).toContain('SourceIp');
    expect(fields).toContain('Protocol');
    expect(fields).toContain('Initiated');
  });

  it('returns an empty array for a nonexistent event ID', () => {
    expect(getSysmonFields(100)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// getAllSigmaCategories
// ---------------------------------------------------------------------------

describe('getAllSigmaCategories', () => {
  it('returns a non-empty list of sigma categories', () => {
    const categories = getAllSigmaCategories();
    expect(categories.length).toBeGreaterThan(0);
  });

  it('includes well-known categories', () => {
    const categories = getAllSigmaCategories();
    expect(categories).toContain('process_creation');
    expect(categories).toContain('network_connection');
    expect(categories).toContain('dns_query');
    expect(categories).toContain('file_event');
    expect(categories).toContain('registry_set');
    expect(categories).toContain('image_load');
    expect(categories).toContain('process_access');
    expect(categories).toContain('create_remote_thread');
    expect(categories).toContain('pipe_created');
    expect(categories).toContain('pipe_connected');
    expect(categories).toContain('wmi_event');
    expect(categories).toContain('file_delete');
    expect(categories).toContain('clipboard_change');
    expect(categories).toContain('process_tampering');
  });

  it('contains only unique values', () => {
    const categories = getAllSigmaCategories();
    const unique = new Set(categories);
    expect(unique.size).toBe(categories.length);
  });
});

// ---------------------------------------------------------------------------
// getAllSysmonEventMappings
// ---------------------------------------------------------------------------

describe('getAllSysmonEventMappings', () => {
  it('returns exactly 29 mappings (Sysmon events 1-29)', () => {
    const all = getAllSysmonEventMappings();
    expect(all.length).toBe(29);
  });

  it('all mappings have non-empty fields', () => {
    for (const m of getAllSysmonEventMappings()) {
      expect(m.fields.length).toBeGreaterThan(0);
    }
  });

  it('event IDs are sequential 1-29', () => {
    const all = getAllSysmonEventMappings();
    const ids = all.map((m) => m.eventId).sort((a, b) => a - b);
    for (let i = 0; i < 29; i++) {
      expect(ids[i]).toBe(i + 1);
    }
  });

  it('all mappings have a non-empty name', () => {
    for (const m of getAllSysmonEventMappings()) {
      expect(m.name.length).toBeGreaterThan(0);
    }
  });

  it('all mappings have a non-empty sigmaCategory', () => {
    for (const m of getAllSysmonEventMappings()) {
      expect(m.sigmaCategory.length).toBeGreaterThan(0);
    }
  });
});
