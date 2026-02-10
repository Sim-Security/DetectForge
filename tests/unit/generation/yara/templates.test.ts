import { describe, it, expect } from 'vitest';
import {
  getYaraTemplate,
  getAllYaraTemplates,
  suggestYaraCategory,
} from '@/generation/yara/templates.js';
import type { ExtractedIOC, ExtractedTTP } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Helpers — factory functions for test data
// ---------------------------------------------------------------------------

function makeIOC(overrides: Partial<ExtractedIOC> = {}): ExtractedIOC {
  return {
    value: '192.168.1.1',
    type: 'ipv4',
    context: '',
    confidence: 'high',
    defanged: false,
    originalValue: '192.168.1.1',
    relationships: [],
    ...overrides,
  };
}

function makeTTP(overrides: Partial<ExtractedTTP> = {}): ExtractedTTP {
  return {
    description: '',
    tools: [],
    targetPlatforms: [],
    artifacts: [],
    detectionOpportunities: [],
    confidence: 'high',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// All 7 known template categories
// ---------------------------------------------------------------------------

const ALL_CATEGORIES = [
  'malicious_document',
  'script_powershell',
  'script_vbs',
  'script_javascript',
  'binary_pe',
  'binary_elf',
  'webshell',
] as const;

// ===========================================================================
// getYaraTemplate
// ===========================================================================

describe('getYaraTemplate', () => {
  it.each(ALL_CATEGORIES)(
    'returns a template for the "%s" category',
    (category) => {
      const template = getYaraTemplate(category);
      expect(template).toBeDefined();
      expect(template!.category).toBe(category);
    },
  );

  it('returns undefined for an unknown category', () => {
    expect(getYaraTemplate('non_existent_category')).toBeUndefined();
  });

  it('returns undefined for an empty string', () => {
    expect(getYaraTemplate('')).toBeUndefined();
  });
});

// ===========================================================================
// getAllYaraTemplates
// ===========================================================================

describe('getAllYaraTemplates', () => {
  it('returns exactly 7 templates', () => {
    const templates = getAllYaraTemplates();
    expect(templates).toHaveLength(7);
  });

  it('contains every expected category', () => {
    const templates = getAllYaraTemplates();
    const categories = templates.map((t) => t.category);
    for (const expected of ALL_CATEGORIES) {
      expect(categories).toContain(expected);
    }
  });

  it.each(ALL_CATEGORIES)(
    'template "%s" has all required fields',
    (category) => {
      const template = getYaraTemplate(category)!;
      expect(template).toHaveProperty('category');
      expect(template).toHaveProperty('description');
      expect(template).toHaveProperty('commonStrings');
      expect(template).toHaveProperty('conditionTemplate');
      expect(template).toHaveProperty('exampleMeta');

      expect(typeof template.category).toBe('string');
      expect(typeof template.description).toBe('string');
      expect(Array.isArray(template.commonStrings)).toBe(true);
      expect(template.commonStrings.length).toBeGreaterThan(0);
      expect(typeof template.conditionTemplate).toBe('string');
      expect(template.conditionTemplate.length).toBeGreaterThan(0);
      expect(typeof template.exampleMeta).toBe('object');
    },
  );
});

// ===========================================================================
// Magic bytes presence
// ===========================================================================

describe('template magicBytes', () => {
  it.each(['binary_pe', 'binary_elf', 'malicious_document'] as const)(
    '"%s" has magicBytes defined',
    (category) => {
      const template = getYaraTemplate(category)!;
      expect(template.magicBytes).toBeDefined();
      expect(Array.isArray(template.magicBytes)).toBe(true);
      expect(template.magicBytes!.length).toBeGreaterThan(0);
    },
  );

  it.each([
    'script_powershell',
    'script_vbs',
    'script_javascript',
    'webshell',
  ] as const)('"%s" does NOT have magicBytes', (category) => {
    const template = getYaraTemplate(category)!;
    expect(template.magicBytes).toBeUndefined();
  });
});

// ===========================================================================
// suggestYaraCategory
// ===========================================================================

describe('suggestYaraCategory', () => {
  // ---- IOC-based scoring ----

  it('returns binary_pe first when given a SHA256 file hash IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        type: 'sha256',
        context: 'Malware sample hash',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0]).toBe('binary_pe');
    // binary_elf should also appear since hashes give it +1
    expect(result).toContain('binary_elf');
  });

  it('returns script_powershell when given a .ps1 filepath_windows IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'C:\\Users\\Admin\\malware.ps1',
        type: 'filepath_windows',
        context: 'Dropped PowerShell script',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    expect(result).toContain('script_powershell');
    expect(result[0]).toBe('script_powershell');
  });

  it('returns binary_pe when given a .exe filepath_windows IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'C:\\Windows\\Temp\\payload.exe',
        type: 'filepath_windows',
        context: 'Dropped executable',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    expect(result).toContain('binary_pe');
    expect(result[0]).toBe('binary_pe');
  });

  it('returns script_vbs when given a .vbs filepath_windows IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'C:\\Users\\Admin\\dropper.vbs',
        type: 'filepath_windows',
        context: 'VBScript dropper',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    expect(result[0]).toBe('script_vbs');
  });

  it('returns script_javascript when given a .js filepath_windows IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'C:\\Users\\Admin\\loader.js',
        type: 'filepath_windows',
        context: 'JScript loader',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    expect(result[0]).toBe('script_javascript');
  });

  it('returns malicious_document when given a .docx filepath_windows IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'C:\\Users\\Admin\\invoice.docx',
        type: 'filepath_windows',
        context: 'Malicious document',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    expect(result[0]).toBe('malicious_document');
  });

  it('returns webshell when given a .php filepath_linux IOC', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: '/var/www/html/shell.php',
        type: 'filepath_linux',
        context: 'PHP web shell on server',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    expect(result).toContain('webshell');
    // webshell gets +4, binary_elf gets +2 from filepath_linux
    expect(result[0]).toBe('webshell');
  });

  it('boosts binary_elf for filepath_linux IOCs with /bin/ path', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: '/usr/bin/backdoor',
        type: 'filepath_linux',
        context: 'Linux binary',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    // binary_elf gets +2 (filepath_linux base) + +2 (/bin/ path) = 4
    expect(result).toContain('binary_elf');
    expect(result[0]).toBe('binary_elf');
  });

  it('boosts categories based on hash context clues', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'd41d8cd98f00b204e9800998ecf8427e',
        type: 'md5',
        context: 'Hash of malicious document with macro payload',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    // binary_pe gets +2 (hash base), malicious_document gets +3 (context 'document' + 'macro')
    expect(result).toContain('malicious_document');
    expect(result).toContain('binary_pe');
  });

  // ---- TTP-based scoring ----

  it('returns script_powershell when TTP description mentions powershell', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Uses PowerShell to download and execute second-stage payload',
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    expect(result).toContain('script_powershell');
    expect(result[0]).toBe('script_powershell');
  });

  it('returns webshell first when TTP description mentions webshell', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Attacker deployed a webshell on the web server for persistent access',
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    expect(result[0]).toBe('webshell');
  });

  it('returns malicious_document when TTP description mentions macro', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Malicious macro in Excel document drops payload on open',
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    expect(result).toContain('malicious_document');
    expect(result[0]).toBe('malicious_document');
  });

  it('returns malicious_document when TTP description mentions spearphish', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Spearphishing attachment with weaponized document',
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    expect(result).toContain('malicious_document');
  });

  it('returns script_vbs when TTP description mentions vbscript', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Attacker uses a VBScript dropper to install the implant',
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    expect(result).toContain('script_vbs');
    expect(result[0]).toBe('script_vbs');
  });

  it('returns script_javascript when TTP description mentions javascript', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Malicious JavaScript file delivered via email attachment',
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    expect(result).toContain('script_javascript');
    expect(result[0]).toBe('script_javascript');
  });

  it('boosts binary_pe when TTP description mentions executable', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Custom trojan executable compiled for Windows',
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    // 'executable' => binary_pe+3, 'trojan' => binary_pe+3 again
    expect(result).toContain('binary_pe');
    expect(result[0]).toBe('binary_pe');
  });

  it('boosts binary_elf when TTP description mentions linux', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Linux-based ELF backdoor communicates over port 443',
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    // 'linux' => binary_elf+4, 'elf' => binary_elf+4, 'backdoor' => binary_pe+3, binary_elf+1
    expect(result).toContain('binary_elf');
    expect(result[0]).toBe('binary_elf');
  });

  // ---- TTP platform-based scoring ----

  it('boosts binary_elf when TTP has linux target platform', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Deploys a backdoor binary',
        targetPlatforms: ['linux'],
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    // 'backdoor' => binary_pe+3, binary_elf+1; platform 'linux' => binary_elf+2
    expect(result).toContain('binary_elf');
  });

  it('boosts binary_pe and script_powershell when TTP has windows platform', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Generic threat activity',
        targetPlatforms: ['windows'],
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    expect(result).toContain('binary_pe');
    expect(result).toContain('script_powershell');
  });

  // ---- TTP artifact-based scoring ----

  it('boosts webshell for file artifact with .php value', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Uploads a web shell to the server',
        artifacts: [
          { type: 'file', description: 'PHP web shell', value: 'cmd.php' },
        ],
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    // 'web shell' in description => webshell+6; artifact .php => webshell+3
    expect(result[0]).toBe('webshell');
  });

  it('boosts binary_pe for file artifact with .exe value', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Drops malware binary to disk',
        artifacts: [
          { type: 'file', description: 'Dropped PE file', value: 'payload.exe' },
        ],
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    expect(result).toContain('binary_pe');
  });

  it('boosts script_powershell for file artifact with .ps1 value', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Executes downloaded script',
        artifacts: [
          { type: 'file', description: 'PowerShell script file', value: 'stage2.ps1' },
        ],
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    // artifact .ps1 => script_powershell+2; artifact description 'script' => script_powershell+2
    expect(result).toContain('script_powershell');
  });

  it('boosts webshell for file artifact with .jsp value', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Deploys JSP web shell',
        artifacts: [
          { type: 'file', description: 'Java web shell', value: 'shell.jsp' },
        ],
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    // 'web shell' => webshell+6; artifact .jsp => webshell+3
    expect(result).toContain('webshell');
  });

  // ---- Edge cases ----

  it('returns an empty array when no IOCs or TTPs are provided', () => {
    const result = suggestYaraCategory([], []);
    expect(result).toEqual([]);
  });

  it('excludes categories with zero score', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'C:\\Users\\Admin\\malware.ps1',
        type: 'filepath_windows',
        context: 'Dropped script',
      }),
    ];
    const result = suggestYaraCategory(iocs, []);
    // Only script_powershell should have a score; all others should be 0 and excluded
    expect(result).toContain('script_powershell');
    // Categories that got no points should not appear
    for (const category of result) {
      expect(category).not.toBe('binary_elf');
      expect(category).not.toBe('webshell');
    }
  });

  it('returns categories sorted by score in descending order', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        type: 'sha256',
        context: 'Sample hash',
      }),
    ];
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'PowerShell encoded command execution',
      }),
    ];
    const result = suggestYaraCategory(iocs, ttps);
    // script_powershell gets +5 from TTP description
    // binary_pe gets +2 from hash
    // binary_elf gets +1 from hash
    expect(result[0]).toBe('script_powershell');
    const peIdx = result.indexOf('binary_pe');
    const elfIdx = result.indexOf('binary_elf');
    expect(peIdx).toBeLessThan(elfIdx);
  });

  it('combines IOC and TTP scores for the same category', () => {
    const iocs: ExtractedIOC[] = [
      makeIOC({
        value: 'C:\\Windows\\Temp\\payload.exe',
        type: 'filepath_windows',
        context: 'Executable path',
      }),
    ];
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Deploys a trojan executable',
      }),
    ];
    const result = suggestYaraCategory(iocs, ttps);
    // binary_pe: +4 (filepath .exe) + 3 (executable) + 3 (trojan) = 10
    expect(result[0]).toBe('binary_pe');
  });

  it('handles TTP with powershell in tools list', () => {
    const ttps: ExtractedTTP[] = [
      makeTTP({
        description: 'Scripting-based attack',
        tools: ['PowerShell'],
      }),
    ];
    const result = suggestYaraCategory([], ttps);
    expect(result).toContain('script_powershell');
  });
});
