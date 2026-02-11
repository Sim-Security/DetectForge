#!/usr/bin/env bun
/**
 * Smoke test — exercises the real pipeline with actual API calls.
 *
 * Run:  bun run scripts/smoke-test.ts
 *
 * This is NOT a unit test.  It hits the OpenRouter API, costs real tokens,
 * and takes 30-60 seconds.  Use it to verify the end-to-end pipeline works.
 */

import 'dotenv/config';
import chalk from 'chalk';
import { AIClient } from '../src/ai/client.js';
import { normalizeReport } from '../src/ingestion/index.js';
import { extractIocs } from '../src/extraction/index.js';
import { extractTtps } from '../src/extraction/ttp-extractor.js';
import { mapToAttack } from '../src/extraction/attack-mapper.js';
import { generateSigmaRules } from '../src/generation/sigma/generator.js';
import { validateSigmaRule } from '../src/generation/sigma/validator.js';
import { scoreRuleQuality } from '../src/testing/quality-scorer.js';
import type { GeneratedRule } from '../src/types/index.js';

// ---------------------------------------------------------------------------
// Sample threat report (short, real-ish APT29 snippet)
// ---------------------------------------------------------------------------

const SAMPLE_REPORT = `
# APT29 Midnight Blizzard: Spear-Phishing Campaign Analysis

## Executive Summary
In January 2024, APT29 (also tracked as Midnight Blizzard / Cozy Bear) launched
a targeted spear-phishing campaign against European government entities. The
campaign used malicious ISO files delivered via phishing emails that, when mounted,
executed a DLL side-loading chain culminating in a Cobalt Strike beacon.

## Indicators of Compromise

### Network IOCs
- C2 server: 185.220.101.42
- Payload hosting: malware-cdn.example[.]com
- DNS beacon domain: updates.windowspatch[.]net
- Exfiltration endpoint: https://storage.cloudservice-api[.]com/upload

### File IOCs
- ISO dropper SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- Cobalt Strike loader: C:\\Users\\Public\\Documents\\msedge.dll
- Persistence script: C:\\ProgramData\\WindowsUpdate\\updater.bat

## Attack Chain

1. **Initial Access (T1566.001)**: Spear-phishing email with ISO attachment
   disguised as a policy document from a partner ministry.

2. **Execution (T1059.001)**: PowerShell script inside the ISO executes on mount.
   The script runs encoded commands to download the next stage payload.
   Command observed: powershell.exe -enc JABjAGwA... (base64 encoded)

3. **Persistence (T1547.001)**: Registry Run key added at
   HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate
   pointing to the updater.bat file.

4. **Defense Evasion (T1574.002)**: DLL side-loading via a legitimate Microsoft
   Edge binary (msedge.exe) loading the malicious msedge.dll from the same
   directory.

5. **Command and Control (T1071.001)**: Cobalt Strike beacon communicating over
   HTTPS to 185.220.101.42 on port 443. Beacon interval: 60 seconds with
   10% jitter. User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

6. **Exfiltration (T1041)**: Collected data exfiltrated to cloud storage endpoint
   using HTTPS POST requests with AES-256 encrypted payloads.

## Recommendations
- Block listed IOCs at perimeter
- Enable PowerShell Script Block Logging (Event ID 4104)
- Monitor for ISO file mounting events
- Deploy Sysmon for enhanced process creation visibility
`;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const startTime = Date.now();

  console.log(chalk.cyan.bold('\n=== DetectForge Smoke Test (Real API Calls) ===\n'));

  // --- Step 1: Create AI client ---
  console.log(chalk.yellow('1. Creating AI client from .env...'));
  const client = AIClient.fromEnv();
  console.log(chalk.green('   OK — API key loaded'));

  // --- Step 2: Normalize the report ---
  console.log(chalk.yellow('2. Normalizing threat report...'));
  const report = await normalizeReport(SAMPLE_REPORT);
  console.log(chalk.green(`   OK — ${report.sections.length} sections, ${report.rawText.length} chars`));

  // --- Step 3: Extract IOCs (regex-based, no API call) ---
  console.log(chalk.yellow('3. Extracting IOCs (regex)...'));
  const iocs = extractIocs(report.rawText);
  console.log(chalk.green(`   OK — ${iocs.length} IOCs extracted`));
  for (const ioc of iocs.slice(0, 5)) {
    console.log(chalk.gray(`       ${ioc.type}: ${ioc.value} (${ioc.confidence})`));
  }
  if (iocs.length > 5) {
    console.log(chalk.gray(`       ... and ${iocs.length - 5} more`));
  }

  // --- Step 4: Extract TTPs (REAL API CALL) ---
  console.log(chalk.yellow('4. Extracting TTPs via AI (real API call)...'));
  const ttpStart = Date.now();
  const ttpResult = await extractTtps(client, report.rawText, { modelTier: 'fast' });
  const ttps = ttpResult.ttps;
  const ttpDuration = Date.now() - ttpStart;
  console.log(chalk.green(`   OK — ${ttps.length} TTPs extracted in ${(ttpDuration / 1000).toFixed(1)}s`));
  for (const ttp of ttps.slice(0, 3)) {
    console.log(chalk.gray(`       ${ttp.description.substring(0, 80)}...`));
  }

  // --- Step 5: Map to ATT&CK (REAL API CALL) ---
  console.log(chalk.yellow('5. Mapping to ATT&CK via AI (real API call)...'));
  const mapStart = Date.now();
  const mapResult = await mapToAttack(client, ttps, { modelTier: 'fast' });
  const mappings = mapResult.mappings;
  const mapDuration = Date.now() - mapStart;
  console.log(chalk.green(`   OK — ${mappings.length} ATT&CK mappings in ${(mapDuration / 1000).toFixed(1)}s`));
  for (const m of mappings.slice(0, 5)) {
    console.log(chalk.gray(`       ${m.techniqueId} ${m.techniqueName} [${m.tactic}] (${m.confidence})`));
  }

  // --- Step 6: Generate Sigma rules (REAL API CALL) ---
  console.log(chalk.yellow('6. Generating Sigma rules via AI (real API call)...'));
  const genStart = Date.now();
  const genResult = await generateSigmaRules(client, ttps, mappings, iocs, { modelTier: 'fast' });
  const sigmaRules = genResult.rules;
  const genDuration = Date.now() - genStart;
  console.log(chalk.green(`   OK — ${sigmaRules.length} Sigma rules generated in ${(genDuration / 1000).toFixed(1)}s`));

  // --- Step 7: Validate rules ---
  console.log(chalk.yellow('7. Validating Sigma rules...'));
  let validCount = 0;
  for (const rule of sigmaRules) {
    const validation = validateSigmaRule(rule);
    if (validation.valid) validCount++;
    const status = validation.valid ? chalk.green('PASS') : chalk.red('FAIL');
    console.log(chalk.gray(`       ${status} ${rule.title || 'Untitled'}`));
    if (!validation.valid) {
      for (const err of validation.errors) {
        console.log(chalk.red(`           Error: ${err}`));
      }
    }
  }
  console.log(chalk.green(`   Validation: ${validCount}/${sigmaRules.length} passed`));

  // --- Step 8: Quality score ---
  console.log(chalk.yellow('8. Scoring rule quality...'));
  for (const rule of sigmaRules) {
    // Wrap SigmaRule into GeneratedRule for the quality scorer
    const genRule: GeneratedRule = {
      format: 'sigma',
      sigma: rule,
      sourceReportId: 'smoke-test',
      confidence: 'medium',
      validation: validateSigmaRule(rule),
    };
    const score = scoreRuleQuality(genRule);
    const color = score.overallScore >= 7 ? chalk.green : score.overallScore >= 5 ? chalk.yellow : chalk.red;
    console.log(chalk.gray(`       ${color(`${score.overallScore.toFixed(1)}/10`)} ${rule.title || 'Untitled'}`));
  }

  // --- Summary ---
  const totalDuration = Date.now() - startTime;
  const cost = client.getCostSummary();

  console.log(chalk.cyan.bold('\n=== Smoke Test Results ==='));
  console.log(`  IOCs extracted:   ${iocs.length}`);
  console.log(`  TTPs extracted:   ${ttps.length}`);
  console.log(`  ATT&CK mappings:  ${mappings.length}`);
  console.log(`  Sigma rules:      ${sigmaRules.length}`);
  console.log(`  Valid rules:      ${validCount}/${sigmaRules.length}`);
  console.log(`  API calls:        ${cost.requestCount}`);
  console.log(`  Total tokens:     ${cost.totalTokens.toLocaleString()}`);
  console.log(`  Total cost:       $${cost.totalCostUsd.toFixed(4)}`);
  console.log(`  Total time:       ${(totalDuration / 1000).toFixed(1)}s`);
  console.log(chalk.cyan.bold('\n=== Done ===\n'));

  if (cost.requestCount === 0) {
    console.log(chalk.red.bold('WARNING: No API calls were made! Something is wrong.'));
    process.exit(1);
  }

  if (sigmaRules.length === 0) {
    console.log(chalk.red.bold('WARNING: No rules were generated! Check API responses.'));
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(chalk.red.bold('\nSmoke test FAILED:'));
  console.error(err);
  process.exit(1);
});
