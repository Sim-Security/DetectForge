import { describe, it, expect } from 'vitest';
import { defang, refang } from '../../../src/utils/defang.js';

describe('defang', () => {
  it('defangs domains', () => {
    expect(defang('evil.com')).toBe('evil[.]com');
  });

  it('defangs URLs with http', () => {
    const result = defang('http://evil.com/payload');
    expect(result).toContain('hxxp');
    expect(result).toContain('[.]');
  });

  it('defangs URLs with https', () => {
    const result = defang('https://evil.com/payload');
    expect(result).toContain('hxxps');
    expect(result).toContain('[.]');
  });

  it('defangs IPv4 addresses', () => {
    const result = defang('192.168.1.1');
    expect(result).toContain('[.]');
  });

  it('defangs email addresses', () => {
    const result = defang('attacker@evil.com');
    expect(result).toContain('[@]');
  });
});

describe('refang', () => {
  it('refangs domains with [.]', () => {
    expect(refang('evil[.]com')).toBe('evil.com');
  });

  it('refangs domains with (.)', () => {
    expect(refang('evil(.)com')).toBe('evil.com');
  });

  it('refangs domains with [dot]', () => {
    expect(refang('evil[dot]com')).toBe('evil.com');
  });

  it('refangs hxxp to http', () => {
    expect(refang('hxxp://evil[.]com')).toBe('http://evil.com');
  });

  it('refangs hxxps to https', () => {
    expect(refang('hxxps://evil[.]com')).toBe('https://evil.com');
  });

  it('refangs email [@]', () => {
    expect(refang('user[@]evil[.]com')).toBe('user@evil.com');
  });

  it('refangs email [at]', () => {
    expect(refang('user[at]evil[.]com')).toBe('user@evil.com');
  });

  it('roundtrips: defang then refang returns original', () => {
    const originals = ['evil.com', 'http://evil.com/path', '192.168.1.1'];
    for (const original of originals) {
      expect(refang(defang(original))).toBe(original);
    }
  });
});
