/**
 * Suricata rule generator.
 *
 * Converts extracted IOCs, TTPs, and ATT&CK mappings into Suricata IDS rules
 * using AI-assisted option generation and template-driven defaults.
 *
 * Flow:
 * 1. Filter IOCs to network-relevant types (domains, IPs, URLs).
 * 2. Group IOCs by suggested template category.
 * 3. For each group, call the AI with the appropriate template prompt.
 * 4. Parse the AI response, build structured SuricataRule objects.
 * 5. Assign sequential SIDs and compose the raw rule text.
 */

import type { AIClient } from '@/ai/client.js';
import type { APIUsage } from '@/types/config.js';
import type {
  SuricataRule,
  SuricataAction,
  SuricataOption,
} from '@/types/detection-rule.js';
import type {
  ExtractedIOC,
  ExtractedTTP,
  AttackMappingResult,
} from '@/types/extraction.js';

import {
  getSuricataTemplate,
  suggestSuricataCategory,
} from '@/generation/suricata/templates.js';
import type { SuricataTemplate } from '@/generation/suricata/templates.js';
import {
  buildSuricataGenerationPrompt,
  parseSuricataAIResponse,
} from '@/ai/prompts/suricata-generation.js';
import type { SuricataAIResponse } from '@/ai/prompts/suricata-generation.js';
import { withRetry } from '@/ai/retry.js';

// ---------------------------------------------------------------------------
// Options & result types
// ---------------------------------------------------------------------------

export interface SuricataGenerationOptions {
  /** AI model tier. Default: 'quality'. */
  modelTier?: 'fast' | 'standard' | 'quality';
  /** Max tokens for AI response. Default: 4096. */
  maxTokens?: number;
  /** Temperature. Default: 0.1. */
  temperature?: number;
  /** Max retries on transient failures. Default: 3. */
  maxRetries?: number;
  /** Starting SID for generated rules. Default: 9000001. */
  sidStart?: number;
}

export interface SuricataGenerationResult {
  /** Generated Suricata rules. */
  rules: SuricataRule[];
  /** Aggregated API usage across all AI calls. */
  usage: APIUsage;
}

// ---------------------------------------------------------------------------
// Network-relevant IOC types
// ---------------------------------------------------------------------------

/** IOC types that are useful for Suricata network detection. */
const NETWORK_IOC_TYPES = new Set(['domain', 'ipv4', 'ipv6', 'url']);

// ---------------------------------------------------------------------------
// Main generation function
// ---------------------------------------------------------------------------

/**
 * Generate Suricata IDS rules from extracted threat intelligence.
 *
 * @param client         - AI client for inference.
 * @param iocs           - Extracted IOCs (will be filtered to network types).
 * @param ttps           - Extracted TTPs for contextual prompting.
 * @param attackMappings - ATT&CK mappings that requested Suricata output.
 * @param options        - Generation options.
 * @returns Generated rules and API usage.
 */
export async function generateSuricataRules(
  client: AIClient,
  iocs: ExtractedIOC[],
  ttps: ExtractedTTP[],
  attackMappings: AttackMappingResult[],
  options?: SuricataGenerationOptions,
): Promise<SuricataGenerationResult> {
  const {
    modelTier = 'quality',
    maxTokens = 16384,
    temperature = 0.1,
    maxRetries = 3,
    sidStart = 9_000_001,
  } = options ?? {};

  // Aggregate usage across all AI calls
  const aggregatedUsage: APIUsage = {
    operation: 'suricata-generation',
    model: '',
    inputTokens: 0,
    outputTokens: 0,
    costUsd: 0,
    durationMs: 0,
    timestamp: new Date().toISOString(),
  };

  // Step 1: Filter to network-relevant IOCs
  const networkIocs = iocs.filter(ioc => NETWORK_IOC_TYPES.has(ioc.type));
  if (networkIocs.length === 0) {
    return { rules: [], usage: aggregatedUsage };
  }

  // Step 2: Determine applicable categories
  const categories = suggestSuricataCategory(networkIocs, ttps);
  if (categories.length === 0) {
    return { rules: [], usage: aggregatedUsage };
  }

  // Step 3: Group IOCs by category
  const iocsByCategory = groupIocsByCategory(networkIocs, categories);

  // Step 4: Generate rules for each category
  const allRules: SuricataRule[] = [];
  let currentSid = sidStart;

  // Pick a relevant mapping (prefer one that suggests suricata)
  const suricataMappings = attackMappings.filter(
    m => m.suggestedRuleFormats.includes('suricata'),
  );
  const fallbackMapping = suricataMappings[0] ?? attackMappings[0];

  if (!fallbackMapping) {
    // No ATT&CK mapping available — cannot generate rules
    return { rules: [], usage: aggregatedUsage };
  }

  for (const [category, categoryIocs] of iocsByCategory.entries()) {
    const template = getSuricataTemplate(category);
    if (!template) continue;

    // Find the best ATT&CK mapping for this category
    const mapping = findBestMapping(suricataMappings, category) ?? fallbackMapping;

    const { system, user } = buildSuricataGenerationPrompt(
      categoryIocs,
      ttps,
      mapping,
      template,
    );

    // Call AI with retry
    const result = await withRetry(
      () =>
        client.prompt(system, user, {
          model: modelTier,
          maxTokens,
          temperature,
          jsonMode: true,
        }),
      { maxRetries },
    );

    // Aggregate usage
    mergeUsage(aggregatedUsage, result.usage);

    // Parse response
    let parsed: SuricataAIResponse;
    try {
      parsed = parseSuricataAIResponse(result.content);
    } catch {
      // If parsing fails, skip this category but continue with others
      continue;
    }

    // Step 5: Build SuricataRule objects
    for (const aiRule of parsed.rules) {
      const rule = buildSuricataRule(aiRule, template, mapping, currentSid);
      allRules.push(rule);
      currentSid++;
    }
  }

  return { rules: allRules, usage: aggregatedUsage };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Group IOCs into the categories they are relevant for.
 */
function groupIocsByCategory(
  iocs: ExtractedIOC[],
  categories: string[],
): Map<string, ExtractedIOC[]> {
  const groups = new Map<string, ExtractedIOC[]>();

  for (const category of categories) {
    const matching: ExtractedIOC[] = [];

    for (const ioc of iocs) {
      if (iocMatchesCategory(ioc, category)) {
        matching.push(ioc);
      }
    }

    if (matching.length > 0) {
      groups.set(category, matching);
    }
  }

  return groups;
}

/**
 * Determine whether an IOC is relevant for a given template category.
 */
function iocMatchesCategory(ioc: ExtractedIOC, category: string): boolean {
  switch (category) {
    case 'dns_query':
    case 'tls_sni':
      return ioc.type === 'domain' || ioc.type === 'url';
    case 'http_request':
      return ioc.type === 'url' || ioc.type === 'domain';
    case 'http_download':
      return ioc.type === 'url';
    case 'tcp_connection':
    case 'udp_connection':
      return ioc.type === 'ipv4' || ioc.type === 'ipv6';
    default:
      return false;
  }
}

/**
 * Find the ATT&CK mapping most relevant to a given template category.
 */
function findBestMapping(
  mappings: AttackMappingResult[],
  category: string,
): AttackMappingResult | undefined {
  // Heuristic: prefer mappings whose tactic aligns with the category
  const tacticHints: Record<string, string[]> = {
    dns_query: ['Command and Control', 'Exfiltration'],
    http_request: ['Command and Control', 'Exfiltration', 'Initial Access'],
    tls_sni: ['Command and Control', 'Exfiltration'],
    http_download: ['Initial Access', 'Execution', 'Defense Evasion'],
    tcp_connection: ['Command and Control', 'Exfiltration', 'Lateral Movement'],
    udp_connection: ['Command and Control', 'Exfiltration'],
  };

  const hints = tacticHints[category] ?? [];
  for (const mapping of mappings) {
    if (hints.some(h => mapping.tactic.toLowerCase().includes(h.toLowerCase()))) {
      return mapping;
    }
  }

  return mappings[0];
}

/**
 * Build a complete SuricataRule from an AI-generated rule response,
 * the template defaults, and the ATT&CK mapping.
 */
function buildSuricataRule(
  aiRule: SuricataAIResponse['rules'][number],
  template: SuricataTemplate,
  mapping: AttackMappingResult,
  sid: number,
): SuricataRule {
  // Assemble options in the correct order
  const options: SuricataOption[] = [];

  // msg always comes first
  options.push({ keyword: 'msg', value: `"DetectForge - ${sanitizeMsg(aiRule.msg)}"` });

  // flow directive for TCP-based protocols
  const hasFlow = aiRule.options.some(o => o.keyword === 'flow');
  if (!hasFlow && ['tcp', 'http', 'tls', 'ssh', 'ftp', 'smtp', 'dns'].includes(template.protocol)) {
    options.push({ keyword: 'flow', value: 'established,to_server' });
  }

  // AI-generated options (skip msg, sid, rev, classtype — we handle those separately)
  const skipKeywords = new Set(['msg', 'sid', 'rev', 'classtype', 'metadata']);
  for (const opt of aiRule.options) {
    if (skipKeywords.has(opt.keyword)) continue;
    options.push({ keyword: opt.keyword, value: opt.value });
  }

  // Metadata with ATT&CK technique
  const metadataParts: string[] = [];
  metadataParts.push(`mitre_attack ${mapping.techniqueId}`);
  if (aiRule.metadata) {
    for (const [key, value] of Object.entries(aiRule.metadata)) {
      if (key !== 'mitre_attack') {
        metadataParts.push(`${key} ${value}`);
      }
    }
  }
  options.push({ keyword: 'metadata', value: metadataParts.join(', ') });

  // classtype
  options.push({
    keyword: 'classtype',
    value: aiRule.classtype || template.commonClasstype,
  });

  // sid and rev
  options.push({ keyword: 'sid', value: String(sid) });
  options.push({ keyword: 'rev', value: '1' });

  // Build raw rule string
  const action: SuricataAction = template.defaultAction;
  const raw = buildRawRule(
    action,
    template.protocol,
    template.defaultSourceIp,
    template.defaultSourcePort,
    template.defaultDirection,
    template.defaultDestIp,
    template.defaultDestPort,
    options,
  );

  return {
    action,
    protocol: template.protocol,
    sourceIp: template.defaultSourceIp,
    sourcePort: template.defaultSourcePort,
    direction: template.defaultDirection,
    destIp: template.defaultDestIp,
    destPort: template.defaultDestPort,
    options,
    sid,
    rev: 1,
    raw,
  };
}

/**
 * Compose the raw Suricata rule text from its components.
 *
 * Format:
 *   action protocol src_ip src_port direction dest_ip dest_port (opt1:val1; opt2; ...;)
 */
function buildRawRule(
  action: SuricataAction,
  protocol: string,
  srcIp: string,
  srcPort: string,
  direction: '->' | '<>',
  destIp: string,
  destPort: string,
  options: SuricataOption[],
): string {
  const header = `${action} ${protocol} ${srcIp} ${srcPort} ${direction} ${destIp} ${destPort}`;

  const optionStrings = options.map(opt => {
    if (opt.value !== undefined) {
      return `${opt.keyword}:${opt.value};`;
    }
    return `${opt.keyword};`;
  });

  return `${header} (${optionStrings.join(' ')})`;
}

/**
 * Sanitize the msg string — strip surrounding quotes if present and
 * remove the "DetectForge - " prefix if the AI already included it.
 */
function sanitizeMsg(msg: string): string {
  let cleaned = msg.trim();
  // Remove surrounding quotes added by the AI
  if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
    cleaned = cleaned.substring(1, cleaned.length - 1);
  }
  // Remove redundant prefix
  if (cleaned.toLowerCase().startsWith('detectforge - ')) {
    cleaned = cleaned.substring('DetectForge - '.length);
  }
  // Escape internal semicolons and backslashes for Suricata
  cleaned = cleaned.replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/"/g, '\\"');
  return cleaned;
}

/**
 * Merge API usage stats from a single call into the aggregate.
 */
function mergeUsage(aggregate: APIUsage, single: APIUsage): void {
  if (!aggregate.model) {
    aggregate.model = single.model;
  }
  aggregate.inputTokens += single.inputTokens;
  aggregate.outputTokens += single.outputTokens;
  aggregate.costUsd += single.costUsd;
  aggregate.durationMs += single.durationMs;
}
