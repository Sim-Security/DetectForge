import { describe, it, expect } from 'vitest';
import { detectHashType, isValidHash, isHash, normalizeHash } from '../../../src/utils/hash.js';

describe('detectHashType', () => {
  it('detects MD5 hashes (32 hex chars)', () => {
    expect(detectHashType('d41d8cd98f00b204e9800998ecf8427e')).toBe('md5');
  });

  it('detects SHA1 hashes (40 hex chars)', () => {
    expect(detectHashType('da39a3ee5e6b4b0d3255bfef95601890afd80709')).toBe('sha1');
  });

  it('detects SHA256 hashes (64 hex chars)', () => {
    expect(detectHashType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe('sha256');
  });

  it('returns null for non-hashes', () => {
    expect(detectHashType('not-a-hash')).toBeNull();
    expect(detectHashType('123')).toBeNull();
    expect(detectHashType('')).toBeNull();
  });

  it('handles uppercase hashes', () => {
    expect(detectHashType('D41D8CD98F00B204E9800998ECF8427E')).toBe('md5');
  });

  it('handles whitespace trimming', () => {
    expect(detectHashType('  d41d8cd98f00b204e9800998ecf8427e  ')).toBe('md5');
  });
});

describe('isValidHash', () => {
  it('validates correct MD5', () => {
    expect(isValidHash('d41d8cd98f00b204e9800998ecf8427e', 'md5')).toBe(true);
  });

  it('rejects wrong length for MD5', () => {
    expect(isValidHash('d41d8cd98f00b204e9800998ecf8427', 'md5')).toBe(false);
  });

  it('rejects non-hex chars', () => {
    expect(isValidHash('g41d8cd98f00b204e9800998ecf8427e', 'md5')).toBe(false);
  });
});

describe('isHash', () => {
  it('returns true for valid hashes', () => {
    expect(isHash('d41d8cd98f00b204e9800998ecf8427e')).toBe(true);
    expect(isHash('da39a3ee5e6b4b0d3255bfef95601890afd80709')).toBe(true);
  });

  it('returns false for non-hashes', () => {
    expect(isHash('hello world')).toBe(false);
  });
});

describe('normalizeHash', () => {
  it('lowercases hashes', () => {
    expect(normalizeHash('D41D8CD98F00B204E9800998ECF8427E')).toBe('d41d8cd98f00b204e9800998ecf8427e');
  });

  it('trims whitespace', () => {
    expect(normalizeHash('  d41d8cd98f00b204e9800998ecf8427e  ')).toBe('d41d8cd98f00b204e9800998ecf8427e');
  });
});
