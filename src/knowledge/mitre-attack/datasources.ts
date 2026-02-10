/**
 * Data-source helpers for the MITRE ATT&CK knowledge base.
 */

import type { AttackKnowledgeBase } from './loader.js';

/**
 * Return the data-source strings listed on a given technique.
 * These are the ATT&CK-defined "Data Source: Data Component" strings
 * (e.g. "Process: Process Creation").
 */
export function getDataSourcesForTechnique(
  kb: AttackKnowledgeBase,
  techniqueId: string,
): string[] {
  const technique = kb.techniques[techniqueId];
  return technique ? technique.dataSources : [];
}

/**
 * Given a data source name (e.g. "Process"), return all technique IDs that
 * reference it.  The match is case-insensitive and checks whether the
 * technique's dataSources entry starts with the provided name.
 */
export function getTechniquesForDataSource(
  kb: AttackKnowledgeBase,
  dataSource: string,
): string[] {
  const lower = dataSource.toLowerCase();

  // First try to get it from the pre-computed dataSources map
  for (const [_key, ds] of Object.entries(kb.dataSources)) {
    if (ds.name.toLowerCase() === lower) {
      return ds.techniques;
    }
  }

  // Fallback: walk all techniques
  return Object.values(kb.techniques)
    .filter((t) =>
      t.dataSources.some((ds) => ds.toLowerCase().startsWith(lower)),
    )
    .map((t) => t.id);
}

/**
 * Build a short detection-recommendation string for a technique by
 * combining its description snippet and its listed data sources.
 */
export function getDetectionRecommendations(
  kb: AttackKnowledgeBase,
  techniqueId: string,
): string {
  const technique = kb.techniques[techniqueId];
  if (!technique) {
    return `No technique found with ID ${techniqueId}.`;
  }

  const dsSection =
    technique.dataSources.length > 0
      ? `Recommended data sources: ${technique.dataSources.join(', ')}.`
      : 'No specific data sources listed by ATT&CK for this technique.';

  // Use up to the first 300 chars of the description as a brief overview
  const briefDesc =
    technique.description.length > 300
      ? technique.description.slice(0, 300) + '...'
      : technique.description;

  return (
    `Detection recommendations for ${technique.id} (${technique.name}):\n` +
    `${briefDesc}\n\n` +
    dsSection
  );
}
