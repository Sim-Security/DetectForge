/**
 * YARA rule templates organized by file type and threat category.
 *
 * Each template provides:
 * - Magic bytes for file type identification
 * - Common string patterns typical of that threat category
 * - Condition templates for rule generation
 * - Example metadata for reference
 *
 * Used by the YARA generator to seed AI-assisted rule creation
 * with domain-specific knowledge for each threat category.
 */

import type { ExtractedIOC, ExtractedTTP } from '@/types/extraction.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface YaraTemplate {
  /** Category identifier (e.g., 'malicious_document', 'binary_pe'). */
  category: string;
  /** Human-readable description of what this template targets. */
  description: string;
  /** Hex magic byte sequences for file type detection. */
  magicBytes?: string[];
  /** Typical string patterns encountered in this threat category. */
  commonStrings: string[];
  /** Skeleton YARA condition that can be customized per rule. */
  conditionTemplate: string;
  /** Example meta fields demonstrating best practices. */
  exampleMeta: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Template Definitions
// ---------------------------------------------------------------------------

const TEMPLATES: Map<string, YaraTemplate> = new Map();

/** Malicious OLE / OOXML documents with macros, DDE, or embedded objects. */
const maliciousDocument: YaraTemplate = {
  category: 'malicious_document',
  description:
    'Detects malicious OLE/OOXML documents containing macros, DDE exploitation, or embedded objects commonly used for initial access.',
  magicBytes: ['D0CF11E0', '504B0304'],
  commonStrings: [
    'AutoOpen',
    'Document_Open',
    'Auto_Open',
    'Workbook_Open',
    'Shell',
    'WScript',
    'WScript.Shell',
    'Powershell',
    'cmd.exe',
    'CreateObject',
    'VBA',
    'Macro',
    'DDEAUTO',
    'DDE',
  ],
  conditionTemplate:
    '(uint32(0) == 0xE011CFD0 or uint32(0) == 0x04034B50) and filesize < 10MB and <string_condition>',
  exampleMeta: {
    description: 'Detects malicious document with embedded VBA macro dropper',
    author: 'DetectForge',
    date: '2026-02-10',
    reference: 'https://example.com/report',
    mitre_attack: 'T1566.001',
  },
};

/** Malicious or obfuscated PowerShell scripts. */
const scriptPowershell: YaraTemplate = {
  category: 'script_powershell',
  description:
    'Detects malicious PowerShell scripts using encoded commands, download cradles, or obfuscation techniques.',
  commonStrings: [
    '-EncodedCommand',
    '-enc',
    'Invoke-Expression',
    'IEX',
    'Invoke-WebRequest',
    'downloadstring',
    'Net.WebClient',
    'DownloadFile',
    'Start-Process',
    'New-Object',
    'System.Net.WebClient',
    'FromBase64String',
    'IO.MemoryStream',
    'IO.Compression',
    'Reflection.Assembly',
    'bitstransfer',
    '[Convert]::',
    'bypass',
    '-nop',
    '-w hidden',
  ],
  conditionTemplate: 'filesize < 5MB and <string_condition>',
  exampleMeta: {
    description: 'Detects PowerShell download cradle with encoded payload',
    author: 'DetectForge',
    date: '2026-02-10',
    reference: 'https://example.com/report',
    mitre_attack: 'T1059.001',
  },
};

/** Malicious VBScript files. */
const scriptVbs: YaraTemplate = {
  category: 'script_vbs',
  description:
    'Detects malicious VBScript files that spawn processes, access the file system, or download secondary payloads.',
  commonStrings: [
    'WScript.Shell',
    'CreateObject',
    'Scripting.FileSystemObject',
    'Shell.Application',
    'ADODB.Stream',
    'MSXML2.XMLHTTP',
    'WinHTTP',
    'Run',
    'Exec',
    'GetObject',
    'RegWrite',
    'Environment',
    'Wscript.Sleep',
  ],
  conditionTemplate: 'filesize < 5MB and <string_condition>',
  exampleMeta: {
    description: 'Detects VBScript dropper creating persistence and downloading payloads',
    author: 'DetectForge',
    date: '2026-02-10',
    reference: 'https://example.com/report',
    mitre_attack: 'T1059.005',
  },
};

/** Malicious JavaScript (e.g., JScript droppers, Node.js backdoors). */
const scriptJavascript: YaraTemplate = {
  category: 'script_javascript',
  description:
    'Detects malicious JavaScript or JScript files using eval, ActiveX, or shell execution to compromise hosts.',
  commonStrings: [
    'eval',
    'ActiveXObject',
    'WScript.Shell',
    'Scripting.FileSystemObject',
    'new Function',
    'charCodeAt',
    'fromCharCode',
    'String.fromCharCode',
    'unescape',
    'document.write',
    'ADODB.Stream',
    'ShellExecute',
    'cmd.exe',
    'powershell',
  ],
  conditionTemplate: 'filesize < 5MB and <string_condition>',
  exampleMeta: {
    description: 'Detects obfuscated JavaScript dropper using ActiveX for payload delivery',
    author: 'DetectForge',
    date: '2026-02-10',
    reference: 'https://example.com/report',
    mitre_attack: 'T1059.007',
  },
};

/** Portable Executable (PE) binaries and DLLs. */
const binaryPe: YaraTemplate = {
  category: 'binary_pe',
  description:
    'Detects malicious Windows PE executables or DLLs using suspicious API calls, packing indicators, or known malware traits.',
  magicBytes: ['4D5A'],
  commonStrings: [
    'VirtualAlloc',
    'VirtualProtect',
    'WriteProcessMemory',
    'CreateRemoteThread',
    'NtUnmapViewOfSection',
    'IsDebuggerPresent',
    'GetProcAddress',
    'LoadLibraryA',
    'InternetOpenA',
    'URLDownloadToFileA',
    'WinExec',
    'ShellExecuteA',
    'RegSetValueExA',
    'CryptEncrypt',
    'This program cannot be run in DOS mode',
    'UPX0',
    'UPX1',
  ],
  conditionTemplate:
    'uint16(0) == 0x5A4D and filesize < 20MB and <string_condition>',
  exampleMeta: {
    description: 'Detects packed PE binary with process injection capabilities',
    author: 'DetectForge',
    date: '2026-02-10',
    reference: 'https://example.com/report',
    mitre_attack: 'T1055',
  },
};

/** Linux ELF binaries. */
const binaryElf: YaraTemplate = {
  category: 'binary_elf',
  description:
    'Detects malicious Linux ELF binaries such as backdoors, rootkits, or crypto-miners.',
  magicBytes: ['7F454C46'],
  commonStrings: [
    '/bin/sh',
    '/bin/bash',
    '/etc/shadow',
    '/etc/passwd',
    '/proc/self',
    '/dev/null',
    'socket',
    'connect',
    'execve',
    'fork',
    'ptrace',
    'LD_PRELOAD',
    'libcrypto',
    'curl',
    'wget',
  ],
  conditionTemplate:
    'uint32(0) == 0x464C457F and filesize < 20MB and <string_condition>',
  exampleMeta: {
    description: 'Detects ELF backdoor with reverse shell capability',
    author: 'DetectForge',
    date: '2026-02-10',
    reference: 'https://example.com/report',
    mitre_attack: 'T1059.004',
  },
};

/** Web shells (PHP, ASP, JSP). */
const webshell: YaraTemplate = {
  category: 'webshell',
  description:
    'Detects web shells in PHP, ASP, and JSP that provide remote command execution or file management on compromised web servers.',
  commonStrings: [
    'eval',
    'exec',
    'system',
    'passthru',
    'shell_exec',
    'popen',
    'proc_open',
    'base64_decode',
    'assert',
    'preg_replace',
    'cmd.exe',
    '/bin/sh',
    'Runtime.getRuntime',
    'ProcessBuilder',
    'Request.Form',
    'Server.CreateObject',
    'Response.Write',
    '$_GET',
    '$_POST',
    '$_REQUEST',
  ],
  conditionTemplate: 'filesize < 1MB and <string_condition>',
  exampleMeta: {
    description: 'Detects PHP web shell providing remote command execution',
    author: 'DetectForge',
    date: '2026-02-10',
    reference: 'https://example.com/report',
    mitre_attack: 'T1505.003',
  },
};

// Register all templates
TEMPLATES.set(maliciousDocument.category, maliciousDocument);
TEMPLATES.set(scriptPowershell.category, scriptPowershell);
TEMPLATES.set(scriptVbs.category, scriptVbs);
TEMPLATES.set(scriptJavascript.category, scriptJavascript);
TEMPLATES.set(binaryPe.category, binaryPe);
TEMPLATES.set(binaryElf.category, binaryElf);
TEMPLATES.set(webshell.category, webshell);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Retrieve a YARA template by category name.
 *
 * @param category - The template category identifier.
 * @returns The matching template, or `undefined` if not found.
 */
export function getYaraTemplate(category: string): YaraTemplate | undefined {
  return TEMPLATES.get(category);
}

/**
 * Return every registered YARA template.
 */
export function getAllYaraTemplates(): YaraTemplate[] {
  return Array.from(TEMPLATES.values());
}

/**
 * Suggest the most relevant YARA template categories given a set of extracted
 * IOCs and TTPs.
 *
 * Scoring is based on:
 * - IOC types (file hashes, file paths, etc.)
 * - TTP tool names and descriptions
 * - TTP artifact types
 * - TTP target platforms
 *
 * Returns categories ordered by relevance (highest first).
 */
export function suggestYaraCategory(
  iocs: ExtractedIOC[],
  ttps: ExtractedTTP[],
): string[] {
  const scores: Record<string, number> = {};

  for (const category of TEMPLATES.keys()) {
    scores[category] = 0;
  }

  // --- Score based on IOC types -----------------------------------------

  for (const ioc of iocs) {
    const val = ioc.value.toLowerCase();
    const ctx = ioc.context.toLowerCase();

    // File hash IOCs suggest binary analysis
    if (['md5', 'sha1', 'sha256'].includes(ioc.type)) {
      scores['binary_pe'] += 2;
      scores['binary_elf'] += 1;

      // Context clues
      if (ctx.includes('dll') || ctx.includes('.exe') || ctx.includes('pe ')) {
        scores['binary_pe'] += 3;
      }
      if (ctx.includes('elf') || ctx.includes('linux')) {
        scores['binary_elf'] += 3;
      }
      if (ctx.includes('document') || ctx.includes('macro') || ctx.includes('.doc')) {
        scores['malicious_document'] += 3;
      }
      if (ctx.includes('webshell') || ctx.includes('web shell') || ctx.includes('.php')) {
        scores['webshell'] += 3;
      }
    }

    // File path IOCs
    if (ioc.type === 'filepath_windows') {
      if (val.endsWith('.ps1') || val.includes('powershell')) {
        scores['script_powershell'] += 4;
      } else if (val.endsWith('.vbs') || val.endsWith('.vbe')) {
        scores['script_vbs'] += 4;
      } else if (val.endsWith('.js') || val.endsWith('.jse')) {
        scores['script_javascript'] += 4;
      } else if (val.endsWith('.exe') || val.endsWith('.dll')) {
        scores['binary_pe'] += 4;
      } else if (val.endsWith('.doc') || val.endsWith('.docx') || val.endsWith('.xls') || val.endsWith('.xlsm')) {
        scores['malicious_document'] += 4;
      }
    }

    if (ioc.type === 'filepath_linux') {
      scores['binary_elf'] += 2;
      if (val.endsWith('.php') || val.endsWith('.jsp') || val.endsWith('.asp') || val.endsWith('.aspx')) {
        scores['webshell'] += 4;
      }
      if (val.includes('/bin/') || val.includes('/sbin/')) {
        scores['binary_elf'] += 2;
      }
    }
  }

  // --- Score based on TTPs -----------------------------------------------

  for (const ttp of ttps) {
    const desc = ttp.description.toLowerCase();
    const toolNames = ttp.tools.map(t => t.toLowerCase());

    // PowerShell indicators
    if (desc.includes('powershell') || toolNames.includes('powershell')) {
      scores['script_powershell'] += 5;
    }

    // VBScript indicators
    if (desc.includes('vbscript') || desc.includes('vbs')) {
      scores['script_vbs'] += 5;
    }

    // JavaScript indicators
    if (desc.includes('javascript') || desc.includes('jscript')) {
      scores['script_javascript'] += 5;
    }

    // Document/macro indicators
    if (
      desc.includes('macro') ||
      desc.includes('document') ||
      desc.includes('spearphish') ||
      desc.includes('phishing attachment')
    ) {
      scores['malicious_document'] += 5;
    }

    // Web shell indicators
    if (desc.includes('webshell') || desc.includes('web shell')) {
      scores['webshell'] += 6;
    }

    // Binary / PE indicators
    if (
      desc.includes('executable') ||
      desc.includes('trojan') ||
      desc.includes('implant') ||
      desc.includes('backdoor') ||
      desc.includes('dll') ||
      desc.includes('payload')
    ) {
      scores['binary_pe'] += 3;
      scores['binary_elf'] += 1;
    }

    // Linux indicators
    if (desc.includes('linux') || desc.includes('elf')) {
      scores['binary_elf'] += 4;
    }

    // Artifact-based scoring
    for (const artifact of ttp.artifacts) {
      if (artifact.type === 'file') {
        const artifactDesc = artifact.description.toLowerCase();
        const artifactVal = (artifact.value ?? '').toLowerCase();
        if (artifactDesc.includes('script') || artifactVal.endsWith('.ps1')) {
          scores['script_powershell'] += 2;
        }
        if (artifactVal.endsWith('.php') || artifactVal.endsWith('.jsp')) {
          scores['webshell'] += 3;
        }
        if (artifactVal.endsWith('.exe') || artifactVal.endsWith('.dll')) {
          scores['binary_pe'] += 3;
        }
      }
    }

    // Platform-based scoring
    for (const platform of ttp.targetPlatforms) {
      const p = platform.toLowerCase();
      if (p === 'windows') {
        scores['binary_pe'] += 1;
        scores['script_powershell'] += 1;
      }
      if (p === 'linux') {
        scores['binary_elf'] += 2;
      }
    }
  }

  // --- Return categories sorted by score (descending), excluding zeros ---

  return Object.entries(scores)
    .filter(([, score]) => score > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([category]) => category);
}
