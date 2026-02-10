/**
 * Prompt templates and Zod schema for AI-driven Suricata rule generation.
 *
 * The system prompt provides a concise Suricata syntax reference, keyword
 * documentation, and the specific template defaults so the AI can produce
 * well-formed rule options in JSON.
 */

import { z } from 'zod';
import type { ExtractedIOC, ExtractedTTP, AttackMappingResult } from '@/types/extraction.js';
import type { SuricataTemplate } from '@/generation/suricata/templates.js';
import { extractJsonFromResponse } from '@/ai/response-parser.js';

// ---------------------------------------------------------------------------
// Zod schema for AI response
// ---------------------------------------------------------------------------

/**
 * Schema for a single rule returned by the AI.
 */
const SuricataRuleResponseSchema = z.object({
  /** Human-readable message for the rule (without surrounding quotes). */
  msg: z.string(),
  /** Array of Suricata keyword/value pairs (besides msg, sid, rev, classtype). */
  options: z.array(
    z.object({
      keyword: z.string(),
      value: z.string().optional(),
    }),
  ),
  /** Classtype value, e.g. 'trojan-activity'. */
  classtype: z.string(),
  /** Optional metadata key-value pairs (e.g. mitre_attack). */
  metadata: z.record(z.string()).optional(),
  /** Brief explanation of what the rule detects (for documentation). */
  rationale: z.string(),
});

/**
 * Full AI response schema: an array of rules.
 */
export const SuricataAIResponseSchema = z.object({
  rules: z.array(SuricataRuleResponseSchema),
});

export type SuricataAIResponse = z.infer<typeof SuricataAIResponseSchema>;

// ---------------------------------------------------------------------------
// Prompt builder
// ---------------------------------------------------------------------------

/**
 * Build system + user prompts for Suricata rule generation.
 *
 * @param iocs     - Network IOCs relevant to this generation batch.
 * @param ttps     - Extracted TTPs for context.
 * @param mapping  - ATT&CK mapping that triggered Suricata rule generation.
 * @param template - The Suricata template providing defaults.
 * @returns Object with `system` and `user` prompt strings.
 */
export function buildSuricataGenerationPrompt(
  iocs: ExtractedIOC[],
  ttps: ExtractedTTP[],
  mapping: AttackMappingResult,
  template: SuricataTemplate,
): { system: string; user: string } {
  // -----------------------------------------------------------------------
  // System prompt
  // -----------------------------------------------------------------------
  const system = `You are a senior network detection engineer specializing in Suricata IDS/IPS rule authoring.

SURICATA RULE SYNTAX REFERENCE
===============================
A Suricata rule has the form:

  action protocol src_ip src_port direction dest_ip dest_port (options;)

Actions:  alert | pass | drop | reject | rejectsrc | rejectdst | rejectboth
Protocols: tcp | udp | icmp | ip | http | dns | tls | ssh | ftp | smtp
Direction: -> (unidirectional) | <> (bidirectional)
Variables: $HOME_NET, $EXTERNAL_NET, $HTTP_PORTS, $DNS_SERVERS, any

KEYWORD REFERENCE
=================
- msg:"<text>"             — Rule description shown on alert.
- flow:established,to_server — Match only established TCP flows going to server.
- content:"<string>"       — Match literal bytes in payload. Use |XX XX| for hex.
- nocase                   — Make preceding content match case-insensitive.
- depth:<n>                — Limit content match to first n bytes.
- offset:<n>               — Start content match at byte offset n.
- distance:<n>             — Require next content match at least n bytes after previous.
- within:<n>               — Require next content match within n bytes of previous.
- dns.query                — Sticky buffer: DNS query name.
- http.method              — Sticky buffer: HTTP method (GET, POST, etc.).
- http.uri                 — Sticky buffer: HTTP URI path.
- http.host                — Sticky buffer: HTTP Host header.
- http.header              — Sticky buffer: full HTTP header block.
- http.user_agent          — Sticky buffer: HTTP User-Agent header.
- http.content_type        — Sticky buffer: HTTP Content-Type header.
- file_data                — Sticky buffer: file transfer data (HTTP body).
- tls.sni                  — Sticky buffer: TLS Server Name Indication.
- pcre:"/<regex>/<flags>"  — PCRE regex match.
- metadata:<key> <value>   — Arbitrary metadata (e.g. mitre_attack T1071.004).
- classtype:<class>        — Classification (trojan-activity, policy-violation, etc.).
- sid:<number>             — Unique rule identifier.
- rev:<number>             — Rule revision.
- reference:url,<url>      — External reference.
- threshold: type <type>, track <track>, count <n>, seconds <s> — Rate limiting.

TEMPLATE DEFAULTS (use these unless you have a good reason to change):
- Category:    ${template.category}
- Protocol:    ${template.protocol}
- Source:      ${template.defaultSourceIp} ${template.defaultSourcePort}
- Direction:   ${template.defaultDirection}
- Destination: ${template.defaultDestIp} ${template.defaultDestPort}
- Classtype:   ${template.commonClasstype}
- Required:    ${template.requiredKeywords.join(', ')}

QUALITY GUIDELINES:
1. Always include a flow directive for TCP-based protocols (flow:established,to_server).
2. Use nocase for domain and hostname matching.
3. Escape special Suricata characters in content strings (semicolons, quotes).
4. Use sticky buffers (dns.query, http.uri, tls.sni) instead of raw content where possible.
5. Keep msg strings concise and prefixed with "DetectForge - ".
6. Include metadata with mitre_attack key mapping to the ATT&CK technique.
7. Generate one focused rule per IOC or tightly related IOC group.
8. Do NOT include sid or rev in options — they are assigned automatically.

OUTPUT FORMAT (strict JSON):
{
  "rules": [
    {
      "msg": "DetectForge - DNS query to C2 domain evil.com",
      "options": [
        { "keyword": "dns.query" },
        { "keyword": "content", "value": "\\"evil.com\\"" },
        { "keyword": "nocase" },
        { "keyword": "flow", "value": "established,to_server" }
      ],
      "classtype": "trojan-activity",
      "metadata": {
        "mitre_attack": "T1071.004"
      },
      "rationale": "Detects DNS resolution of known C2 domain used by APT group."
    }
  ]
}

IMPORTANT:
- Content values must include surrounding double quotes as they would appear in the rule (e.g. "\\"evil.com\\"").
- Each option that takes a value should have the value as a string exactly as it appears after the keyword in Suricata syntax.
- Keywords without values (dns.query, nocase, file_data) should omit the value field.
- Generate rules ONLY for the provided IOCs — do not invent indicators.`;

  // -----------------------------------------------------------------------
  // User prompt
  // -----------------------------------------------------------------------
  const iocList = iocs
    .map((ioc, idx) => `  ${idx + 1}. [${ioc.type}] ${ioc.value} — ${ioc.context}`)
    .join('\n');

  const ttpList = ttps
    .map((ttp, idx) => {
      const tools = ttp.tools.length > 0 ? ` (Tools: ${ttp.tools.join(', ')})` : '';
      return `  ${idx + 1}. ${ttp.description}${tools}`;
    })
    .join('\n');

  const user = `Generate Suricata ${template.category} rules for the following threat intelligence.

ATT&CK TECHNIQUE: ${mapping.techniqueId} — ${mapping.techniqueName} (${mapping.tactic})
Reasoning: ${mapping.reasoning}

NETWORK IOCs:
${iocList}

RELATED TTPs:
${ttpList}

Using the ${template.category} template (${template.protocol} protocol), generate one Suricata rule per IOC.
Provide the rules in strict JSON format as specified.`;

  return { system, user };
}

// ---------------------------------------------------------------------------
// Response parser
// ---------------------------------------------------------------------------

/**
 * Parse a raw AI response string into a validated SuricataAIResponse.
 *
 * Extracts JSON from potential markdown wrappers, then validates against
 * the Zod schema.
 *
 * @param raw - Raw AI response text.
 * @returns Validated response object.
 * @throws {Error} If parsing or validation fails.
 */
export function parseSuricataAIResponse(raw: string): SuricataAIResponse {
  const extracted = extractJsonFromResponse(raw);
  try {
    return SuricataAIResponseSchema.parse(extracted);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors
        .map(err => `  - ${err.path.join('.')}: ${err.message}`)
        .join('\n');
      throw new Error(
        `Suricata AI response validation failed:\n${formattedErrors}\n\nRaw response:\n${raw.substring(0, 500)}`,
      );
    }
    throw error;
  }
}
