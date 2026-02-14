/**
 * Static catalog of OTRF Security-Datasets for real attack log testing.
 *
 * Each entry maps an ATT&CK technique to a downloadable dataset archive
 * containing Windows Sysmon / Security event logs captured during attack
 * simulations.
 *
 * Source: https://github.com/OTRF/Security-Datasets
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DatasetAttackPattern {
  /** Field to check */
  field: string;
  /** Substring to match (case-insensitive) */
  contains?: string;
  /** Regex to match */
  regex?: RegExp;
  /** Only apply this pattern to logs from this category. Omit = all categories. */
  category?: string;
}

export interface DatasetEntry {
  /** Unique identifier, e.g. "t1059.001_powershell" */
  id: string;
  /** Human-readable name */
  name: string;
  /** ATT&CK technique ID */
  attackTechniqueId: string;
  /** Secondary ATT&CK techniques used as means during the attack */
  secondaryTechniques?: string[];
  /** Sigma logsource categories this dataset covers */
  sigmaCategories: string[];
  /** Raw GitHub URL for the archive (.zip or .tar.gz) */
  url: string;
  /** Approximate download size */
  sizeEstimate: string;
  /** Archive format */
  format: 'zip' | 'tar.gz';
  /** Dataset-specific attack patterns (supplements defaults in log-normalizer) */
  attackPatterns?: DatasetAttackPattern[];
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

const BASE =
  'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets';

export const DATASET_CATALOG: DatasetEntry[] = [
  // --- Execution ---
  {
    id: 't1059.001_powershell_http',
    name: 'PowerShell HTTP Listener',
    attackTechniqueId: 'T1059.001',
    sigmaCategories: ['process_creation', 'ps_script', 'network_connection'],
    url: `${BASE}/atomic/windows/execution/host/psh_powershell_httplistener.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
  },

  // --- Credential Access ---
  {
    id: 't1003.001_mimikatz_logonpasswords',
    name: 'Empire Mimikatz LogonPasswords',
    attackTechniqueId: 'T1003.001',
    sigmaCategories: ['process_creation', 'image_load', 'registry_set', 'process_access'],
    url: `${BASE}/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip`,
    sizeEstimate: '500KB',
    format: 'zip',
    attackPatterns: [
      { field: 'Image', contains: 'mimikatz' },
      { field: 'CommandLine', contains: 'sekurlsa' },
      { field: 'CommandLine', contains: 'logonpasswords' },
      // process_access: only LSASS targeting is attack
      { field: 'TargetImage', contains: 'lsass', category: 'process_access' },
    ],
  },
  {
    id: 't1003.001_lsass_comsvcs',
    name: 'LSASS Memory Dump via Comsvcs.dll',
    attackTechniqueId: 'T1003.001',
    sigmaCategories: ['process_creation', 'image_load', 'process_access'],
    url: `${BASE}/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
    attackPatterns: [
      { field: 'CommandLine', contains: 'comsvcs' },
      { field: 'CommandLine', contains: 'MiniDump' },
      { field: 'Image', contains: 'rundll32' },
      // process_access: only LSASS targeting is attack
      { field: 'TargetImage', contains: 'lsass', category: 'process_access' },
    ],
  },

  // --- Lateral Movement ---
  {
    id: 't1021.002_empire_smbexec',
    name: 'Empire Invoke SMBExec',
    attackTechniqueId: 'T1021.002',
    secondaryTechniques: ['T1569.002'],  // service execution
    sigmaCategories: ['network_connection', 'process_creation', 'file_event'],
    url: `${BASE}/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip`,
    sizeEstimate: '400KB',
    format: 'zip',
    attackPatterns: [
      { field: 'ParentImage', contains: 'services.exe' },
      { field: 'DestinationPort', contains: '445' },
    ],
  },
  {
    id: 't1021.002_covenant_sc',
    name: 'Covenant SC.exe Utility Query',
    attackTechniqueId: 'T1021.002',
    secondaryTechniques: ['T1569.002'],  // service execution
    sigmaCategories: ['network_connection', 'process_creation'],
    url: `${BASE}/atomic/windows/lateral_movement/host/covenant_sc_query_dcerpc_smb_svcctl.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
    attackPatterns: [
      { field: 'Image', contains: 'sc.exe' },
      { field: 'DestinationPort', contains: '445' },
    ],
  },

  // --- Persistence ---
  {
    id: 't1547.001_registry_run_keys_user',
    name: 'Empire Userland Registry Run Keys',
    attackTechniqueId: 'T1547.001',
    sigmaCategories: ['registry_set', 'process_creation'],
    url: `${BASE}/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
  },
  {
    id: 't1547.001_registry_run_keys_elevated',
    name: 'Empire Elevated Registry Run Keys',
    attackTechniqueId: 'T1547.001',
    sigmaCategories: ['registry_set', 'process_creation'],
    url: `${BASE}/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
  },

  // --- Defense Evasion / Process Injection ---
  // t1055_mavinject_injection removed — HTTP 404 (dataset no longer available)
  {
    id: 't1055_process_herpaderping',
    name: 'Process Herpaderping Mimikatz',
    attackTechniqueId: 'T1055',
    secondaryTechniques: ['T1036', 'T1036.003', 'T1574.002'],
    sigmaCategories: ['process_creation', 'image_load', 'file_event', 'create_remote_thread'],
    url: `${BASE}/atomic/windows/defense_evasion/host/cmd_process_herpaderping_mimiexplorer.zip`,
    sizeEstimate: '400KB',
    format: 'zip',
    attackPatterns: [
      { field: 'Image', contains: 'mimiexplorer' },
      { field: 'OriginalFileName', contains: 'mimikatz' },
    ],
  },

  // --- Defense Evasion / Registry Modification ---
  // t1112_wdigest_downgrade removed — corrupt tar.gz archive
  {
    id: 't1112_monologue_netntlm',
    name: 'Empire Invoke InternalMonologue',
    attackTechniqueId: 'T1112',
    sigmaCategories: ['registry_set', 'process_creation'],
    url: `${BASE}/atomic/windows/defense_evasion/host/empire_monologue_netntlm_downgrade.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
  },

  // --- Scheduled Tasks ---
  {
    id: 't1053.005_schtasks_user',
    name: 'Empire Userland Scheduled Tasks',
    attackTechniqueId: 'T1053.005',
    sigmaCategories: ['process_creation', 'file_event', 'create_remote_thread'],
    url: `${BASE}/atomic/windows/persistence/host/empire_schtasks_creation_standard_user.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
  },
  {
    id: 't1053.005_schtasks_elevated',
    name: 'Empire Elevated Scheduled Tasks',
    attackTechniqueId: 'T1053.005',
    secondaryTechniques: ['T1055.001'],  // svchost injection context
    sigmaCategories: ['process_creation', 'file_event', 'create_remote_thread'],
    url: `${BASE}/atomic/windows/persistence/host/empire_schtasks_creation_execution_elevated_user.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
  },

  // --- Discovery ---
  {
    id: 't1018_seatbelt_discovery',
    name: 'Seatbelt Group User Discovery',
    attackTechniqueId: 'T1018',
    secondaryTechniques: ['T1082', 'T1057', 'T1135'],
    sigmaCategories: ['process_creation', 'network_connection'],
    url: `${BASE}/atomic/windows/discovery/host/cmd_seatbelt_group_user.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
    attackPatterns: [
      { field: 'Image', contains: 'seatbelt' },
      { field: 'CommandLine', contains: 'seatbelt' },
    ],
  },

  // --- Defense Evasion / Masquerading ---
  {
    id: 't1036_herpaderping_snippingtool',
    name: 'Process Herpaderping SnippingTool',
    attackTechniqueId: 'T1036',
    sigmaCategories: ['process_creation', 'file_event'],
    url: `${BASE}/atomic/windows/defense_evasion/host/cmd_process_herpaderping_snippingtool.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
  },

  // --- Credential Access: NTDS.DIT ---
  {
    id: 't1003.003_ntdsutil',
    name: 'NTDS.DIT Dump via Ntdsutil',
    attackTechniqueId: 'T1003.003',
    sigmaCategories: ['process_creation'],
    url: `${BASE}/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
    attackPatterns: [
      { field: 'CommandLine', contains: 'ntdsutil' },
      { field: 'CommandLine', contains: 'ntds.dit' },
      { field: 'CommandLine', contains: 'ifm' },
    ],
  },
  {
    id: 't1003.003_vss_ntds',
    name: 'NTDS.DIT Dump via Volume Shadow Copy',
    attackTechniqueId: 'T1003.003',
    secondaryTechniques: ['T1003'],
    sigmaCategories: ['process_creation'],
    url: `${BASE}/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_volume_shadow_copy.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
    attackPatterns: [
      { field: 'CommandLine', contains: 'vssadmin' },
      { field: 'CommandLine', contains: 'ntds.dit' },
      { field: 'CommandLine', contains: 'shadow' },
    ],
  },

  // --- Credential Access: Registry SAM Dump ---
  {
    id: 't1003.002_empire_reg_dump_sam',
    name: 'Empire Registry SAM Dump',
    attackTechniqueId: 'T1003.002',
    sigmaCategories: ['process_creation', 'registry_set'],
    url: `${BASE}/atomic/windows/credential_access/host/empire_shell_reg_dump_sam.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
    attackPatterns: [
      { field: 'CommandLine', contains: 'reg save' },
      { field: 'CommandLine', contains: 'sam' },
      { field: 'CommandLine', contains: 'system' },
      { field: 'CommandLine', contains: 'security' },
    ],
  },

  // --- Credential Access: LSASS via Task Manager ---
  {
    id: 't1003.001_rdp_taskmgr_lsass',
    name: 'LSASS Dump via Task Manager over RDP',
    attackTechniqueId: 'T1003.001',
    sigmaCategories: ['process_creation', 'process_access', 'file_event'],
    url: `${BASE}/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip`,
    sizeEstimate: '400KB',
    format: 'zip',
    attackPatterns: [
      // process_creation: taskmgr launch is the attack action
      { field: 'Image', contains: 'taskmgr' },
      { field: 'CommandLine', contains: 'taskmgr' },
      // process_access: only taskmgr→lsass is attack, not svchost→lsass routine monitoring
      { field: 'TargetImage', contains: 'lsass', category: 'process_access' },
      { field: 'SourceImage', contains: 'taskmgr', category: 'process_access' },
    ],
  },

  // --- Defense Evasion / Process Injection: DLL Injection ---
  {
    id: 't1055.001_empire_dll_injection',
    name: 'Empire DLL Injection via CreateRemoteThread',
    attackTechniqueId: 'T1055.001',
    sigmaCategories: ['process_creation', 'image_load', 'create_remote_thread'],
    url: `${BASE}/atomic/windows/defense_evasion/host/empire_dllinjection_LoadLibrary_CreateRemoteThread.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
    attackPatterns: [
      { field: 'CallTrace', contains: 'UNKNOWN' },
      { field: 'Image', contains: 'powershell' },
      { field: 'StartFunction', contains: 'LoadLibrary' },
      { field: 'SourceImage', contains: 'powershell' },
    ],
  },

  // --- Command and Control: Ingress Tool Transfer ---
  // t1105_bitsadmin_download removed — HTTP 404 (dataset no longer available)

  // --- Defense Evasion: MSHTA Execution ---
  {
    id: 't1218.005_mshta_vbscript',
    name: 'MSHTA VBScript Execute PowerShell',
    attackTechniqueId: 'T1218.005',
    secondaryTechniques: ['T1204.002'],  // user execution IS the technique
    sigmaCategories: ['process_creation', 'network_connection'],
    url: `${BASE}/atomic/windows/defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
    attackPatterns: [
      { field: 'Image', contains: 'mshta' },
      { field: 'CommandLine', contains: 'mshta' },
      { field: 'CommandLine', contains: 'vbscript' },
      { field: 'ParentImage', contains: 'mshta' },
    ],
  },

  // --- Defense Evasion: CMSTP UAC Bypass ---
  {
    id: 't1218.003_cmstp_uac_bypass',
    name: 'CMSTP Execution UAC Bypass',
    attackTechniqueId: 'T1218.003',
    sigmaCategories: ['process_creation'],
    url: `${BASE}/atomic/windows/defense_evasion/host/psh_cmstp_execution_bypassuac.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
    attackPatterns: [
      { field: 'Image', contains: 'cmstp' },
      { field: 'CommandLine', contains: 'cmstp' },
    ],
  },

  // --- Discovery: Network Share ---
  {
    id: 't1135_empire_find_localadmin',
    name: 'Empire Find-LocalAdminAccess SMB',
    attackTechniqueId: 'T1135',
    sigmaCategories: ['process_creation', 'network_connection'],
    url: `${BASE}/atomic/windows/discovery/host/empire_find_localadmin_smb_svcctl_OpenSCManager.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
    attackPatterns: [
      { field: 'CommandLine', contains: 'find-localadminaccess' },
      { field: 'CommandLine', contains: 'invoke-' },
    ],
  },

  // --- Credential Access: LSASS Dump via Dumpert (Syscalls) ---
  {
    id: 't1003.001_lsass_dumpert',
    name: 'LSASS Memory Dump via Dumpert Syscalls',
    attackTechniqueId: 'T1003.001',
    sigmaCategories: ['process_creation', 'process_access'],
    url: `${BASE}/atomic/windows/credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
    attackPatterns: [
      // process_creation: dumpert tool launch
      { field: 'Image', contains: 'dumpert' },
      { field: 'CommandLine', contains: 'dumpert' },
      // process_access: only dumpert→lsass is attack, not svchost→lsass routine monitoring
      { field: 'SourceImage', contains: 'dumpert', category: 'process_access' },
      { field: 'TargetImage', contains: 'lsass', category: 'process_access' },
    ],
  },

  // --- Credential Access: DCSync via DRS ---
  {
    id: 't1003.006_empire_dcsync',
    name: 'Empire DCSync via DRSUAPI',
    attackTechniqueId: 'T1003.006',
    sigmaCategories: ['process_creation', 'network_connection'],
    url: `${BASE}/atomic/windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip`,
    sizeEstimate: '400KB',
    format: 'zip',
    attackPatterns: [
      { field: 'CommandLine', contains: 'dcsync' },
      { field: 'CommandLine', contains: 'lsadump' },
      { field: 'CommandLine', contains: 'DsGetNCChanges' },
    ],
  },

  // --- Lateral Movement: PSExec ---
  {
    id: 't1021.002_empire_psexec',
    name: 'Empire PSExec Lateral Movement',
    attackTechniqueId: 'T1021.002',
    secondaryTechniques: ['T1569.002'],  // service execution
    sigmaCategories: ['process_creation', 'network_connection', 'file_event'],
    url: `${BASE}/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip`,
    sizeEstimate: '400KB',
    format: 'zip',
    attackPatterns: [
      { field: 'ParentImage', contains: 'services.exe' },
      { field: 'DestinationPort', contains: '445' },
    ],
  },

  // --- Defense Evasion: Regsvr32 Proxy Execution ---
  {
    id: 't1218.010_empire_regsvr32',
    name: 'Empire Regsvr32 SCT Launcher',
    attackTechniqueId: 'T1218.010',
    sigmaCategories: ['process_creation', 'network_connection'],
    url: `${BASE}/atomic/windows/defense_evasion/host/empire_launcher_sct_regsvr32.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
    attackPatterns: [
      { field: 'Image', contains: 'regsvr32' },
      { field: 'CommandLine', contains: 'regsvr32' },
      { field: 'CommandLine', contains: 'scrobj' },
    ],
  },

  // --- Execution: WMI ---
  {
    id: 't1047_empire_wmi',
    name: 'Empire WMI Lateral Execution',
    attackTechniqueId: 'T1047',
    sigmaCategories: ['process_creation', 'network_connection'],
    url: `${BASE}/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip`,
    sizeEstimate: '300KB',
    format: 'zip',
    attackPatterns: [
      { field: 'Image', contains: 'wmiprvse' },
      { field: 'ParentImage', contains: 'wmiprvse' },
      { field: 'CommandLine', contains: 'wmic' },
    ],
  },

  // --- Defense Evasion: Log Clearing ---
  {
    id: 't1070.001_wevtutil',
    name: 'Security Log Modification via Wevtutil',
    attackTechniqueId: 'T1070.001',
    sigmaCategories: ['process_creation'],
    url: `${BASE}/atomic/windows/defense_evasion/host/cmd_wevtutil_modify_security_eventlog_path.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
    attackPatterns: [
      { field: 'Image', contains: 'wevtutil' },
      { field: 'CommandLine', contains: 'wevtutil' },
      { field: 'CommandLine', contains: 'security' },
    ],
  },

  // --- Defense Evasion: Disable Security Tools ---
  {
    id: 't1562.001_disable_eventlog',
    name: 'PowerShell Disable EventLog Service',
    attackTechniqueId: 'T1562.001',
    sigmaCategories: ['process_creation', 'registry_set'],
    url: `${BASE}/atomic/windows/defense_evasion/host/psh_disable_eventlog_service_startuptype_modification.zip`,
    sizeEstimate: '200KB',
    format: 'zip',
    attackPatterns: [
      { field: 'CommandLine', contains: 'eventlog' },
      { field: 'CommandLine', contains: 'set-service' },
      { field: 'CommandLine', contains: 'stop-service' },
    ],
  },
];

/**
 * Get datasets that cover a given Sigma logsource category.
 */
export function getDatasetsForCategory(category: string): DatasetEntry[] {
  return DATASET_CATALOG.filter((d) => d.sigmaCategories.includes(category));
}

/**
 * Get datasets matching a specific ATT&CK technique ID.
 */
export function getDatasetsForTechnique(techniqueId: string): DatasetEntry[] {
  return DATASET_CATALOG.filter(
    (d) => d.attackTechniqueId.toUpperCase() === techniqueId.toUpperCase(),
  );
}
