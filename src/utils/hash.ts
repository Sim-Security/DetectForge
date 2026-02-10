/**
 * Hash validation utilities.
 * Validates MD5, SHA1, SHA256 hash formats.
 */

const HASH_PATTERNS = {
  md5: /^[a-fA-F0-9]{32}$/,
  sha1: /^[a-fA-F0-9]{40}$/,
  sha256: /^[a-fA-F0-9]{64}$/,
} as const;

export type HashType = keyof typeof HASH_PATTERNS;

/**
 * Detect the type of a hash string.
 */
export function detectHashType(value: string): HashType | null {
  const trimmed = value.trim();
  if (HASH_PATTERNS.md5.test(trimmed)) return 'md5';
  if (HASH_PATTERNS.sha1.test(trimmed)) return 'sha1';
  if (HASH_PATTERNS.sha256.test(trimmed)) return 'sha256';
  return null;
}

/**
 * Validate that a string is a valid hash of the specified type.
 */
export function isValidHash(value: string, type: HashType): boolean {
  return HASH_PATTERNS[type].test(value.trim());
}

/**
 * Check if a string looks like any known hash type.
 */
export function isHash(value: string): boolean {
  return detectHashType(value) !== null;
}

/**
 * Normalize a hash to lowercase.
 */
export function normalizeHash(value: string): string {
  return value.trim().toLowerCase();
}
