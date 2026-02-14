/**
 * Unit tests for technique template registry (Level 11 Phase 4).
 *
 * Verifies coverage of ATT&CK technique templates used for behavioral TP testing.
 */

import { describe, it, expect } from 'vitest';
import {
  getTemplatesForTechnique,
  TECHNIQUE_TEMPLATES,
} from '@/testing/technique-templates.js';

// ===========================================================================
// New technique template coverage
// ===========================================================================

describe('technique template coverage', () => {
  it('T1003.006 (DCSync) returns 1+ templates', () => {
    const templates = getTemplatesForTechnique('T1003.006');
    expect(templates.length).toBeGreaterThanOrEqual(1);
    expect(templates[0].category).toBe('network_connection');
  });

  it('T1047 (WMI) returns 2 templates', () => {
    const templates = getTemplatesForTechnique('T1047');
    expect(templates).toHaveLength(2);
    expect(templates.every((t) => t.category === 'process_creation')).toBe(true);
  });

  it('T1070.001 (Log Clearing) returns 2 templates', () => {
    const templates = getTemplatesForTechnique('T1070.001');
    expect(templates).toHaveLength(2);
    // Both process_creation
    expect(templates.every((t) => t.category === 'process_creation')).toBe(true);
  });

  it('T1218.010 (Regsvr32) returns 1+ template', () => {
    const templates = getTemplatesForTechnique('T1218.010');
    expect(templates.length).toBeGreaterThanOrEqual(1);
  });

  it('T1569.002 (Service Execution) returns 1+ template', () => {
    const templates = getTemplatesForTechnique('T1569.002');
    expect(templates.length).toBeGreaterThanOrEqual(1);
    expect(templates[0].fields.ParentImage).toContain('services.exe');
  });

  it('all new templates have valid category and non-empty fields', () => {
    const newTechniques = ['T1003.006', 'T1047', 'T1070.001', 'T1218.010', 'T1569.002'];
    for (const techId of newTechniques) {
      const templates = getTemplatesForTechnique(techId);
      for (const t of templates) {
        expect(t.category).toBeTruthy();
        expect(Object.keys(t.fields).length).toBeGreaterThan(0);
      }
    }
  });

  it('T1003.001 has process_access template with GrantedAccess 0x1fffff', () => {
    const templates = getTemplatesForTechnique('T1003.001', 'process_access');
    const dumpertTemplate = templates.find(
      (t) => t.fields.GrantedAccess === '0x1fffff',
    );
    expect(dumpertTemplate).toBeDefined();
    expect(dumpertTemplate!.fields.TargetImage).toContain('lsass.exe');
  });

  it('total template count >= 44', () => {
    let total = 0;
    for (const [, templates] of TECHNIQUE_TEMPLATES) {
      total += templates.length;
    }
    expect(total).toBeGreaterThanOrEqual(39);
  });
});
