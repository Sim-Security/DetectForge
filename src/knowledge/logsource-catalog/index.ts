/**
 * Unified logsource catalog for DetectForge.
 *
 * Re-exports the Windows, Sysmon, and Linux catalogs and provides a
 * single entry point for resolving Sigma logsource fields from any
 * event source.
 */

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

export type { EventLogMapping } from './windows.js';
export {
  getWindowsEventMapping,
  getWindowsEventsByCategory,
  getWindowsFieldsForEvent,
  getSigmaLogsourceForEvent,
  getAllWindowsEventMappings,
} from './windows.js';

export type { SysmonEventMapping } from './sysmon.js';
export {
  getSysmonEventMapping,
  getSysmonEventByCategory,
  getSysmonFields,
  getAllSigmaCategories,
  getAllSysmonEventMappings,
} from './sysmon.js';

export type { LinuxLogMapping } from './linux.js';
export {
  getLinuxLogMapping,
  getLinuxFieldsForSource,
  getLinuxSigmaLogsource,
  getAllLinuxSources,
} from './linux.js';

// ---------------------------------------------------------------------------
// Internal imports for unified helper functions below.
// We use the non-re-exporting form so TS doesn't complain about duplicates.
// ---------------------------------------------------------------------------

import {
  getSigmaLogsourceForEvent as _getSigmaLogsourceForEvent,
  getWindowsEventsByCategory as _getWindowsEventsByCategory,
  getAllWindowsEventMappings as _getAllWindowsEventMappings,
} from './windows.js';

import {
  getSysmonEventMapping as _getSysmonEventMapping,
  getSysmonEventByCategory as _getSysmonEventByCategory,
  getAllSigmaCategories as _getAllSigmaCategories,
  getAllSysmonEventMappings as _getAllSysmonEventMappings,
} from './sysmon.js';

import {
  getLinuxFieldsForSource as _getLinuxFieldsForSource,
  getLinuxSigmaLogsource as _getLinuxSigmaLogsource,
  getAllLinuxSources as _getAllLinuxSources,
} from './linux.js';

// ---------------------------------------------------------------------------
// getSigmaLogsource
// ---------------------------------------------------------------------------

/**
 * Resolve the Sigma logsource block (product / service / category) from an
 * event source descriptor and optional event ID.
 *
 * Supported `eventSource` values:
 *   - `"windows"` — Windows Event Log (requires `eventId`)
 *   - `"sysmon"`  — Sysmon (requires `eventId`)
 *   - Any Linux source name (`"auditd"`, `"syslog"`, `"auth"`, etc.)
 */
export function getSigmaLogsource(
  eventSource: string,
  eventId?: number,
): { product: string; service?: string; category?: string } {
  const normalized = eventSource.toLowerCase();

  // --- Windows Security / System Event Log ---
  if (normalized === 'windows') {
    if (eventId !== undefined) {
      const logsource = _getSigmaLogsourceForEvent(eventId);
      return {
        product: logsource.product,
        service: logsource.service,
        category: logsource.category,
      };
    }
    return { product: 'windows', service: 'security' };
  }

  // --- Sysmon ---
  if (normalized === 'sysmon') {
    if (eventId !== undefined) {
      const mapping = _getSysmonEventMapping(eventId);
      if (mapping) {
        return {
          product: 'windows',
          service: 'sysmon',
          category: mapping.sigmaCategory,
        };
      }
    }
    return { product: 'windows', service: 'sysmon' };
  }

  // --- Linux log sources ---
  return _getLinuxSigmaLogsource(normalized);
}

// ---------------------------------------------------------------------------
// getFieldsForLogsource
// ---------------------------------------------------------------------------

/**
 * Return the list of fields available for a given Sigma logsource
 * combination.  At least `product` must be provided.
 *
 * Resolution order:
 * 1. If product is "windows" and a category is provided, try Sysmon first
 *    (since Sysmon categories are the most granular), then Windows events.
 * 2. If product is "linux" and a service is provided, use that service
 *    name as the Linux source key.
 */
export function getFieldsForLogsource(
  product: string,
  category?: string,
  service?: string,
): string[] {
  const normalizedProduct = product.toLowerCase();

  if (normalizedProduct === 'windows') {
    // Try Sysmon category first
    if (category) {
      const sysmonMapping = _getSysmonEventByCategory(category);
      if (sysmonMapping) {
        return sysmonMapping.fields;
      }
    }

    // Try Windows events by category
    if (category) {
      const windowsEvents = _getWindowsEventsByCategory(category);
      if (windowsEvents.length > 0) {
        // Merge fields from all events in the category (deduplicated)
        const fieldSet = new Set<string>();
        for (const evt of windowsEvents) {
          for (const f of evt.fields) {
            fieldSet.add(f);
          }
        }
        return [...fieldSet];
      }
    }

    // Fall back: if service is "sysmon" and no category, aggregate all sysmon fields
    if (service?.toLowerCase() === 'sysmon') {
      const allFields = new Set<string>();
      for (const mapping of _getAllSysmonEventMappings()) {
        for (const f of mapping.fields) {
          allFields.add(f);
        }
      }
      return [...allFields];
    }

    // Fall back: aggregate all windows event fields for the given service
    const allFields = new Set<string>();
    for (const mapping of _getAllWindowsEventMappings()) {
      if (service && mapping.sigmaService !== service.toLowerCase()) continue;
      for (const f of mapping.fields) {
        allFields.add(f);
      }
    }
    return [...allFields];
  }

  if (normalizedProduct === 'linux') {
    if (service) {
      // Try direct source lookup
      const fields = _getLinuxFieldsForSource(service.toLowerCase());
      if (fields.length > 0) return fields;
    }

    // Aggregate fields from all Linux sources
    const allFields = new Set<string>();
    for (const mapping of _getAllLinuxSources()) {
      for (const f of mapping.fields) {
        allFields.add(f);
      }
    }
    return [...allFields];
  }

  return [];
}

// ---------------------------------------------------------------------------
// validateSigmaLogsource
// ---------------------------------------------------------------------------

/** Set of all known Sigma categories across all catalogs. */
function buildKnownCategories(): Set<string> {
  const categories = new Set<string>();

  // From Sysmon
  for (const m of _getAllSysmonEventMappings()) {
    categories.add(m.sigmaCategory);
  }

  // From Windows events
  for (const m of _getAllWindowsEventMappings()) {
    categories.add(m.category);
  }

  // From Linux (only auditd has a Sigma category)
  for (const m of _getAllLinuxSources()) {
    if (m.sigmaCategory) {
      categories.add(m.sigmaCategory);
    }
  }

  return categories;
}

/** Set of all known services across all catalogs. */
function buildKnownServices(): Set<string> {
  const services = new Set<string>();

  for (const m of _getAllWindowsEventMappings()) {
    services.add(m.sigmaService);
  }
  services.add('sysmon');

  for (const m of _getAllLinuxSources()) {
    services.add(m.sigmaService);
  }

  return services;
}

const KNOWN_PRODUCTS = new Set(['windows', 'linux']);

/**
 * Validate whether a given Sigma logsource triple (product, category,
 * service) is known to the catalog.
 *
 * Returns `true` when:
 * - The product is recognised, AND
 * - If a category is given, it exists in the catalog, AND
 * - If a service is given, it exists in the catalog.
 */
export function validateSigmaLogsource(
  product: string,
  category?: string,
  service?: string,
): boolean {
  const normalizedProduct = product.toLowerCase();

  if (!KNOWN_PRODUCTS.has(normalizedProduct)) {
    return false;
  }

  if (category) {
    const knownCategories = buildKnownCategories();
    if (!knownCategories.has(category)) {
      return false;
    }
  }

  if (service) {
    const knownServices = buildKnownServices();
    if (!knownServices.has(service.toLowerCase())) {
      return false;
    }
  }

  return true;
}
