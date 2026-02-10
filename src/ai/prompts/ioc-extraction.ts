/**
 * Prompt templates for AI-enhanced IOC extraction.
 *
 * These prompts work alongside regex extraction to:
 * - Disambiguate IOCs from benign references
 * - Extract IOCs mentioned in natural language
 * - Classify IOC context and relationships
 */

export interface CandidateIOC {
  value: string;
  type: string;
  context: string;
}

/**
 * Build a prompt for full IOC extraction from a threat report.
 * Use this when you need the AI to discover all IOCs, including those in natural language.
 */
export function buildIocExtractionPrompt(reportText: string): { system: string; user: string } {
  const system = `You are a cybersecurity threat intelligence analyst specializing in extracting Indicators of Compromise (IOCs) from threat reports.

Your task is to extract ALL indicators of compromise from the provided report, including:
- IP addresses (IPv4 and IPv6)
- Domain names
- URLs
- File hashes (MD5, SHA-1, SHA-256)
- Email addresses
- File paths (Windows and Linux)
- Registry keys
- CVE identifiers
- ATT&CK technique IDs

CRITICAL DISAMBIGUATION:
- Distinguish between malicious IOCs and benign/legitimate references
- "google.com" mentioned as an example is NOT an IOC
- "192.168.1.1" in a network diagram may not be an IOC
- C2 domains, phishing sites, malware download URLs ARE IOCs
- Use context to determine if a value is part of the threat

For each IOC, provide:
1. value: The IOC value (refanged if defanged in report)
2. type: One of: ipv4, ipv6, domain, url, md5, sha1, sha256, email, filepath_windows, filepath_linux, registry_key, cve, attack_technique
3. context: Surrounding text explaining how this IOC is used (20-50 words)
4. confidence: high (explicitly stated as malicious), medium (strongly implied), low (possible/uncertain)
5. defanged: true if the IOC was defanged in the original report (e.g., hxxp, [.], [@])
6. originalValue: The exact string as it appeared in the report (before refanging)
7. relationships: Array of {relatedIOC, relationship} pairs describing connections

Relationship examples:
- "domain resolves to IP"
- "URL hosted on domain"
- "file downloaded from URL"
- "hash of payload from URL"

OUTPUT FORMAT (strict JSON):
{
  "iocs": [
    {
      "value": "malicious.example.com",
      "type": "domain",
      "context": "C2 server used by the threat actor to exfiltrate data after initial compromise.",
      "confidence": "high",
      "defanged": true,
      "originalValue": "malicious[.]example[.]com",
      "relationships": [
        { "relatedIOC": "192.0.2.1", "relationship": "resolves to" }
      ]
    },
    {
      "value": "192.0.2.1",
      "type": "ipv4",
      "context": "IP address hosting the C2 infrastructure, located in AS12345.",
      "confidence": "high",
      "defanged": false,
      "originalValue": "192.0.2.1",
      "relationships": [
        { "relatedIOC": "malicious.example.com", "relationship": "hosts" }
      ]
    }
  ]
}

IMPORTANT:
- Extract IOCs mentioned in prose (e.g., "attackers used a domain registered to...")
- If an IOC appears multiple times, include it once with the most informative context
- If confidence is low, still include it but mark confidence as "low"
- Preserve all IOCs found, even if there are many`;

  const user = `Extract all Indicators of Compromise from the following threat intelligence report. Use context to determine whether each value is truly malicious.

REPORT:
${reportText}

Provide the IOC extraction results in strict JSON format as specified.`;

  return { system, user };
}

/**
 * Build a prompt for disambiguating candidate IOCs (extracted via regex).
 * Use this when regex has found potential IOCs and you need AI to filter false positives.
 */
export function buildIocDisambiguationPrompt(iocs: CandidateIOC[]): { system: string; user: string } {
  const system = `You are a cybersecurity analyst reviewing a list of candidate Indicators of Compromise (IOCs) that were extracted from a threat report using pattern matching.

Your task is to:
1. Determine if each candidate is a TRUE IOC (part of the threat) or a FALSE POSITIVE (benign reference)
2. Enhance the confidence level based on context
3. Add relationships between IOCs if they exist

CLASSIFICATION RULES:
- TRUE IOC: The value is directly associated with malicious activity
  Examples: C2 domains, malware hashes, attacker IPs, phishing URLs
- FALSE POSITIVE: The value is benign or not part of the threat
  Examples: "google.com" used as an example, internal IP in network diagram, vendor domain

For each candidate, classify it and provide:
- isMalicious: true or false
- confidence: high, medium, or low (if malicious)
- reasoning: Brief explanation (10-20 words)
- relationships: Array of {relatedIOC, relationship} describing connections to other IOCs

OUTPUT FORMAT (strict JSON):
{
  "results": [
    {
      "value": "malicious.example.com",
      "type": "domain",
      "isMalicious": true,
      "confidence": "high",
      "reasoning": "Identified as C2 server in report, used for data exfiltration.",
      "relationships": [
        { "relatedIOC": "192.0.2.1", "relationship": "resolves to" }
      ]
    },
    {
      "value": "google.com",
      "type": "domain",
      "isMalicious": false,
      "confidence": null,
      "reasoning": "Mentioned as example of legitimate domain for comparison.",
      "relationships": []
    }
  ]
}`;

  const candidateList = iocs.map((ioc, idx) =>
    `${idx + 1}. ${ioc.value} (${ioc.type})\n   Context: ${ioc.context}`
  ).join('\n\n');

  const user = `Review the following candidate IOCs and classify each as malicious or false positive.

CANDIDATE IOCs:
${candidateList}

Provide the classification results in strict JSON format as specified.`;

  return { system, user };
}
