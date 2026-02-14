/**
 * Unit tests for the OTRF dataset catalog.
 *
 * Validates structural integrity, uniqueness constraints, and format
 * correctness to prevent regressions when adding new datasets.
 */

import { describe, it, expect } from 'vitest';
import {
  DATASET_CATALOG,
  getDatasetsForCategory,
  getDatasetsForTechnique,
} from '@/testing/real-data/dataset-catalog.js';
import { getAllSigmaCategories } from '@/knowledge/logsource-catalog/index.js';

// ===========================================================================
// Structural Integrity
// ===========================================================================

describe('dataset catalog structural integrity', () => {
  it('all catalog entry IDs are unique', () => {
    const ids = DATASET_CATALOG.map((d) => d.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('all technique IDs match ATT&CK format', () => {
    const attackFormat = /^T\d{4}(\.\d{3})?$/;
    for (const entry of DATASET_CATALOG) {
      expect(entry.attackTechniqueId).toMatch(attackFormat);
      if (entry.secondaryTechniques) {
        for (const tech of entry.secondaryTechniques) {
          expect(tech).toMatch(attackFormat);
        }
      }
    }
  });

  it('all sigmaCategories are in the valid category list', () => {
    const validCategories = new Set(getAllSigmaCategories());
    // Also include categories from the log normalizer's category maps
    // that aren't Sysmon-only (authentication, ps_script)
    validCategories.add('authentication');
    validCategories.add('ps_script');

    for (const entry of DATASET_CATALOG) {
      for (const cat of entry.sigmaCategories) {
        expect(validCategories.has(cat)).toBe(true);
      }
    }
  });

  it('no duplicate URLs', () => {
    const urls = DATASET_CATALOG.map((d) => d.url);
    const uniqueUrls = new Set(urls);
    expect(uniqueUrls.size).toBe(urls.length);
  });

  it('all URLs start with the expected OTRF base path', () => {
    for (const entry of DATASET_CATALOG) {
      expect(entry.url).toContain(
        'raw.githubusercontent.com/OTRF/Security-Datasets',
      );
    }
  });

  it('all entries have required fields', () => {
    for (const entry of DATASET_CATALOG) {
      expect(entry.id).toBeTruthy();
      expect(entry.name).toBeTruthy();
      expect(entry.attackTechniqueId).toBeTruthy();
      expect(entry.sigmaCategories.length).toBeGreaterThan(0);
      expect(entry.url).toBeTruthy();
      expect(entry.sizeEstimate).toBeTruthy();
      expect(['zip', 'tar.gz']).toContain(entry.format);
    }
  });

  it('attackPatterns use valid field names when present', () => {
    const knownFields = new Set([
      // Sysmon process_creation fields
      'Image', 'CommandLine', 'ParentImage', 'ParentCommandLine',
      'User', 'OriginalFileName', 'Company', 'Hashes',
      // Sysmon process_access fields
      'SourceImage', 'TargetImage', 'GrantedAccess', 'CallTrace',
      // Sysmon create_remote_thread fields
      'StartFunction',
      // Sysmon network_connection fields
      'DestinationPort', 'DestinationIp',
      // Registry fields
      'TargetObject', 'Details',
      // PowerShell fields
      'ScriptBlockText',
    ]);

    for (const entry of DATASET_CATALOG) {
      if (!entry.attackPatterns) continue;
      for (const pattern of entry.attackPatterns) {
        expect(knownFields.has(pattern.field)).toBe(true);
      }
    }
  });
});

// ===========================================================================
// Query Functions
// ===========================================================================

describe('dataset catalog query functions', () => {
  it('getDatasetsForCategory returns entries matching the category', () => {
    const processCreation = getDatasetsForCategory('process_creation');
    expect(processCreation.length).toBeGreaterThan(0);
    for (const entry of processCreation) {
      expect(entry.sigmaCategories).toContain('process_creation');
    }
  });

  it('getDatasetsForTechnique returns entries matching the technique', () => {
    const t1003_001 = getDatasetsForTechnique('T1003.001');
    expect(t1003_001.length).toBeGreaterThan(0);
    for (const entry of t1003_001) {
      expect(entry.attackTechniqueId).toBe('T1003.001');
    }
  });

  it('getDatasetsForTechnique is case-insensitive', () => {
    const upper = getDatasetsForTechnique('T1003.001');
    const lower = getDatasetsForTechnique('t1003.001');
    expect(upper.length).toBe(lower.length);
  });

  it('getDatasetsForCategory returns empty for unknown category', () => {
    const result = getDatasetsForCategory('nonexistent_category');
    expect(result).toEqual([]);
  });

  it('getDatasetsForTechnique returns empty for unknown technique', () => {
    const result = getDatasetsForTechnique('T9999.999');
    expect(result).toEqual([]);
  });
});

// ===========================================================================
// Coverage Metrics
// ===========================================================================

describe('dataset catalog coverage metrics', () => {
  it('has at least 25 datasets', () => {
    expect(DATASET_CATALOG.length).toBeGreaterThanOrEqual(25);
  });

  it('covers at least 8 unique ATT&CK techniques', () => {
    const techniques = new Set(DATASET_CATALOG.map((d) => d.attackTechniqueId));
    expect(techniques.size).toBeGreaterThanOrEqual(8);
  });

  it('covers process_creation, process_access, and create_remote_thread categories', () => {
    const allCategories = new Set(DATASET_CATALOG.flatMap((d) => d.sigmaCategories));
    expect(allCategories.has('process_creation')).toBe(true);
    expect(allCategories.has('process_access')).toBe(true);
    expect(allCategories.has('create_remote_thread')).toBe(true);
  });
});
