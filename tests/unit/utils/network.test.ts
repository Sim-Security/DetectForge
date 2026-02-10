import { describe, it, expect } from 'vitest';
import { isValidIPv4, isPrivateIP, isValidDomain, isValidUrl, isValidEmail, extractDomain } from '../../../src/utils/network.js';

describe('isValidIPv4', () => {
  it('validates correct IPs', () => {
    expect(isValidIPv4('192.168.1.1')).toBe(true);
    expect(isValidIPv4('10.0.0.1')).toBe(true);
    expect(isValidIPv4('255.255.255.255')).toBe(true);
    expect(isValidIPv4('0.0.0.0')).toBe(true);
  });

  it('rejects invalid IPs', () => {
    expect(isValidIPv4('256.1.1.1')).toBe(false);
    expect(isValidIPv4('1.1.1')).toBe(false);
    expect(isValidIPv4('not an ip')).toBe(false);
    expect(isValidIPv4('')).toBe(false);
  });
});

describe('isPrivateIP', () => {
  it('identifies private IPs', () => {
    expect(isPrivateIP('10.0.0.1')).toBe(true);
    expect(isPrivateIP('172.16.0.1')).toBe(true);
    expect(isPrivateIP('192.168.1.1')).toBe(true);
    expect(isPrivateIP('127.0.0.1')).toBe(true);
  });

  it('identifies public IPs', () => {
    expect(isPrivateIP('8.8.8.8')).toBe(false);
    expect(isPrivateIP('1.1.1.1')).toBe(false);
    expect(isPrivateIP('203.0.113.1')).toBe(false);
  });
});

describe('isValidDomain', () => {
  it('validates correct domains', () => {
    expect(isValidDomain('example.com')).toBe(true);
    expect(isValidDomain('sub.example.com')).toBe(true);
    expect(isValidDomain('evil-domain.co.uk')).toBe(true);
  });

  it('rejects invalid domains', () => {
    expect(isValidDomain('-evil.com')).toBe(false);
    expect(isValidDomain('evil')).toBe(false);
    expect(isValidDomain('')).toBe(false);
  });
});

describe('isValidUrl', () => {
  it('validates correct URLs', () => {
    expect(isValidUrl('http://example.com')).toBe(true);
    expect(isValidUrl('https://example.com/path?q=1')).toBe(true);
    expect(isValidUrl('ftp://files.example.com')).toBe(true);
  });

  it('rejects invalid URLs', () => {
    expect(isValidUrl('not-a-url')).toBe(false);
    expect(isValidUrl('example.com')).toBe(false);
  });
});

describe('isValidEmail', () => {
  it('validates correct emails', () => {
    expect(isValidEmail('user@example.com')).toBe(true);
    expect(isValidEmail('admin@sub.example.co.uk')).toBe(true);
  });

  it('rejects invalid emails', () => {
    expect(isValidEmail('not-an-email')).toBe(false);
    expect(isValidEmail('@example.com')).toBe(false);
  });
});

describe('extractDomain', () => {
  it('extracts domain from URL', () => {
    expect(extractDomain('https://evil.com/payload')).toBe('evil.com');
    expect(extractDomain('http://sub.evil.com:8080/path')).toBe('sub.evil.com');
  });

  it('returns null for invalid URLs', () => {
    expect(extractDomain('not-a-url')).toBeNull();
  });
});
