/**
 * Network validation utilities.
 * IP address, domain, and URL validation and parsing.
 */

const IPV4_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const DOMAIN_PATTERN = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
const URL_PATTERN = /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i;
const EMAIL_PATTERN = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// Private/reserved IPv4 ranges
const PRIVATE_RANGES = [
  { start: [10, 0, 0, 0], end: [10, 255, 255, 255] },
  { start: [172, 16, 0, 0], end: [172, 31, 255, 255] },
  { start: [192, 168, 0, 0], end: [192, 168, 255, 255] },
  { start: [127, 0, 0, 0], end: [127, 255, 255, 255] },
];

export function isValidIPv4(value: string): boolean {
  const match = IPV4_PATTERN.exec(value);
  if (!match) return false;
  return match.slice(1).every(octet => {
    const n = parseInt(octet, 10);
    return n >= 0 && n <= 255;
  });
}

export function isPrivateIP(value: string): boolean {
  const match = IPV4_PATTERN.exec(value);
  if (!match) return false;
  const octets = match.slice(1).map(o => parseInt(o, 10));
  return PRIVATE_RANGES.some(range =>
    octets.every((o, i) => o >= range.start[i] && o <= range.end[i])
  );
}

export function isValidDomain(value: string): boolean {
  return DOMAIN_PATTERN.test(value) && value.length <= 253;
}

export function isValidUrl(value: string): boolean {
  return URL_PATTERN.test(value);
}

export function isValidEmail(value: string): boolean {
  return EMAIL_PATTERN.test(value);
}

/**
 * Extract the domain from a URL.
 */
export function extractDomain(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return null;
  }
}
