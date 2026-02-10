/**
 * Suricata rule templates organized by protocol and detection category.
 *
 * Each template provides sensible defaults for a common detection scenario
 * (DNS C2 beaconing, HTTP requests, TLS SNI, file downloads, raw TCP/UDP).
 * The generator uses these templates as a starting point and fills in
 * IOC-specific values and AI-generated options.
 */

import type {
  SuricataAction,
  SuricataOption,
} from '@/types/detection-rule.js';
import type { ExtractedIOC, ExtractedTTP } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Template interface
// ---------------------------------------------------------------------------

export interface SuricataTemplate {
  /** Unique category identifier, e.g. 'dns_query', 'http_request'. */
  category: string;
  /** Suricata protocol keyword (dns, http, tls, tcp, udp). */
  protocol: string;
  /** Human-readable description of what this template detects. */
  description: string;
  /** Default rule action. */
  defaultAction: SuricataAction;
  /** Default traffic direction. */
  defaultDirection: '->' | '<>';
  /** Default source IP variable. */
  defaultSourceIp: string;
  /** Default source port. */
  defaultSourcePort: string;
  /** Default destination IP variable. */
  defaultDestIp: string;
  /** Default destination port. */
  defaultDestPort: string;
  /** Keywords that should always be present in rules of this category. */
  requiredKeywords: string[];
  /** Example options that demonstrate typical usage. */
  exampleOptions: SuricataOption[];
  /** Suggested classtype for the rule. */
  commonClasstype: string;
}

// ---------------------------------------------------------------------------
// Template definitions
// ---------------------------------------------------------------------------

const DNS_QUERY_TEMPLATE: SuricataTemplate = {
  category: 'dns_query',
  protocol: 'dns',
  description: 'DNS lookups to known C2 or malicious domains',
  defaultAction: 'alert',
  defaultDirection: '->',
  defaultSourceIp: '$HOME_NET',
  defaultSourcePort: 'any',
  defaultDestIp: 'any',
  defaultDestPort: '53',
  requiredKeywords: ['dns.query', 'content', 'nocase'],
  exampleOptions: [
    { keyword: 'msg', value: '"DetectForge - DNS query to malicious domain"' },
    { keyword: 'dns.query' },
    { keyword: 'content', value: '"evil.com"' },
    { keyword: 'nocase' },
    { keyword: 'flow', value: 'established,to_server' },
    { keyword: 'classtype', value: 'trojan-activity' },
    { keyword: 'sid', value: '9000001' },
    { keyword: 'rev', value: '1' },
  ],
  commonClasstype: 'trojan-activity',
};

const HTTP_REQUEST_TEMPLATE: SuricataTemplate = {
  category: 'http_request',
  protocol: 'http',
  description: 'HTTP requests to C2 or malicious download servers',
  defaultAction: 'alert',
  defaultDirection: '->',
  defaultSourceIp: '$HOME_NET',
  defaultSourcePort: 'any',
  defaultDestIp: '$EXTERNAL_NET',
  defaultDestPort: '$HTTP_PORTS',
  requiredKeywords: ['http.method', 'http.uri', 'http.host', 'http.header', 'content'],
  exampleOptions: [
    { keyword: 'msg', value: '"DetectForge - HTTP request to malicious host"' },
    { keyword: 'flow', value: 'established,to_server' },
    { keyword: 'http.host' },
    { keyword: 'content', value: '"malicious.example.com"' },
    { keyword: 'nocase' },
    { keyword: 'classtype', value: 'trojan-activity' },
    { keyword: 'sid', value: '9000002' },
    { keyword: 'rev', value: '1' },
  ],
  commonClasstype: 'trojan-activity',
};

const TLS_SNI_TEMPLATE: SuricataTemplate = {
  category: 'tls_sni',
  protocol: 'tls',
  description: 'TLS connections matched by Server Name Indication (SNI)',
  defaultAction: 'alert',
  defaultDirection: '->',
  defaultSourceIp: '$HOME_NET',
  defaultSourcePort: 'any',
  defaultDestIp: '$EXTERNAL_NET',
  defaultDestPort: '443',
  requiredKeywords: ['tls.sni', 'content'],
  exampleOptions: [
    { keyword: 'msg', value: '"DetectForge - TLS connection to suspicious domain"' },
    { keyword: 'flow', value: 'established,to_server' },
    { keyword: 'tls.sni' },
    { keyword: 'content', value: '"malicious.example.com"' },
    { keyword: 'nocase' },
    { keyword: 'classtype', value: 'trojan-activity' },
    { keyword: 'sid', value: '9000003' },
    { keyword: 'rev', value: '1' },
  ],
  commonClasstype: 'trojan-activity',
};

const HTTP_DOWNLOAD_TEMPLATE: SuricataTemplate = {
  category: 'http_download',
  protocol: 'http',
  description: 'File downloads over HTTP (e.g. malware payloads)',
  defaultAction: 'alert',
  defaultDirection: '->',
  defaultSourceIp: '$HOME_NET',
  defaultSourcePort: 'any',
  defaultDestIp: '$EXTERNAL_NET',
  defaultDestPort: '$HTTP_PORTS',
  requiredKeywords: ['http.uri', 'file_data', 'content'],
  exampleOptions: [
    { keyword: 'msg', value: '"DetectForge - Suspicious file download over HTTP"' },
    { keyword: 'flow', value: 'established,to_server' },
    { keyword: 'http.uri' },
    { keyword: 'content', value: '"/malware/payload.exe"' },
    { keyword: 'nocase' },
    { keyword: 'classtype', value: 'policy-violation' },
    { keyword: 'sid', value: '9000004' },
    { keyword: 'rev', value: '1' },
  ],
  commonClasstype: 'policy-violation',
};

const TCP_CONNECTION_TEMPLATE: SuricataTemplate = {
  category: 'tcp_connection',
  protocol: 'tcp',
  description: 'Raw TCP connections to suspicious IPs or ports',
  defaultAction: 'alert',
  defaultDirection: '->',
  defaultSourceIp: '$HOME_NET',
  defaultSourcePort: 'any',
  defaultDestIp: '$EXTERNAL_NET',
  defaultDestPort: 'any',
  requiredKeywords: ['flow'],
  exampleOptions: [
    { keyword: 'msg', value: '"DetectForge - TCP connection to suspicious IP"' },
    { keyword: 'flow', value: 'established,to_server' },
    { keyword: 'classtype', value: 'trojan-activity' },
    { keyword: 'sid', value: '9000005' },
    { keyword: 'rev', value: '1' },
  ],
  commonClasstype: 'trojan-activity',
};

const UDP_CONNECTION_TEMPLATE: SuricataTemplate = {
  category: 'udp_connection',
  protocol: 'udp',
  description: 'UDP traffic to suspicious destinations',
  defaultAction: 'alert',
  defaultDirection: '->',
  defaultSourceIp: '$HOME_NET',
  defaultSourcePort: 'any',
  defaultDestIp: '$EXTERNAL_NET',
  defaultDestPort: 'any',
  requiredKeywords: ['content'],
  exampleOptions: [
    { keyword: 'msg', value: '"DetectForge - UDP traffic to suspicious destination"' },
    { keyword: 'content', value: '"|de ad be ef|"' },
    { keyword: 'classtype', value: 'trojan-activity' },
    { keyword: 'sid', value: '9000006' },
    { keyword: 'rev', value: '1' },
  ],
  commonClasstype: 'trojan-activity',
};

// ---------------------------------------------------------------------------
// Template registry
// ---------------------------------------------------------------------------

/** All available templates keyed by category. */
const TEMPLATE_MAP = new Map<string, SuricataTemplate>([
  ['dns_query', DNS_QUERY_TEMPLATE],
  ['http_request', HTTP_REQUEST_TEMPLATE],
  ['tls_sni', TLS_SNI_TEMPLATE],
  ['http_download', HTTP_DOWNLOAD_TEMPLATE],
  ['tcp_connection', TCP_CONNECTION_TEMPLATE],
  ['udp_connection', UDP_CONNECTION_TEMPLATE],
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Retrieve a template by its category identifier.
 *
 * @param category - Template category, e.g. 'dns_query'.
 * @returns The matching template or `undefined` if not found.
 */
export function getSuricataTemplate(category: string): SuricataTemplate | undefined {
  return TEMPLATE_MAP.get(category);
}

/**
 * Return all registered Suricata templates.
 */
export function getAllSuricataTemplates(): SuricataTemplate[] {
  return [...TEMPLATE_MAP.values()];
}

/**
 * Suggest which template categories are applicable given a set of IOCs and TTPs.
 *
 * Heuristics:
 * - Domains without a URL -> dns_query + tls_sni
 * - URLs with http/https  -> http_request (+ http_download if path looks like a file)
 * - IPv4 / IPv6 addresses -> tcp_connection (+ udp_connection if TTPs mention UDP)
 * - TTPs referencing network artifacts -> tcp_connection
 */
export function suggestSuricataCategory(
  iocs: ExtractedIOC[],
  ttps: ExtractedTTP[],
): string[] {
  const categories = new Set<string>();

  // Check TTPs for UDP references
  const ttpText = ttps
    .map(t => `${t.description} ${t.artifacts.map(a => a.description).join(' ')}`)
    .join(' ')
    .toLowerCase();
  const mentionsUdp = ttpText.includes('udp');

  for (const ioc of iocs) {
    switch (ioc.type) {
      case 'domain': {
        categories.add('dns_query');
        categories.add('tls_sni');
        break;
      }
      case 'url': {
        const lower = ioc.value.toLowerCase();
        if (lower.startsWith('http://') || lower.startsWith('https://')) {
          categories.add('http_request');
        }
        // If the URL path ends with a file extension, suggest download template too
        if (/\.\w{2,5}(\?|$)/.test(lower)) {
          categories.add('http_download');
        }
        // Domain portion also warrants DNS + TLS rules
        categories.add('dns_query');
        categories.add('tls_sni');
        break;
      }
      case 'ipv4':
      case 'ipv6': {
        categories.add('tcp_connection');
        if (mentionsUdp) {
          categories.add('udp_connection');
        }
        break;
      }
      default:
        // Non-network IOC types (hashes, file paths, etc.) are not relevant
        break;
    }
  }

  // TTPs with network artifacts always warrant tcp_connection
  for (const ttp of ttps) {
    for (const artifact of ttp.artifacts) {
      if (artifact.type === 'network') {
        categories.add('tcp_connection');
      }
    }
  }

  return [...categories];
}
