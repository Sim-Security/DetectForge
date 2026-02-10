/**
 * Tests for AI prompt templates.
 */

import { describe, it, expect } from 'vitest';
import {
  buildIocExtractionPrompt,
  buildIocDisambiguationPrompt,
  type CandidateIOC,
} from '@/ai/prompts/ioc-extraction.js';
import {
  buildTtpExtractionPrompt,
  buildAttackMappingPrompt,
  type CandidateTTP,
} from '@/ai/prompts/ttp-extraction.js';

describe('buildIocExtractionPrompt', () => {
  it('should return system and user prompts', () => {
    const report = 'Sample threat report about malicious activity.';
    const { system, user } = buildIocExtractionPrompt(report);

    expect(system).toBeTruthy();
    expect(user).toBeTruthy();
    expect(typeof system).toBe('string');
    expect(typeof user).toBe('string');
  });

  it('should include report text in user prompt', () => {
    const report = 'The attacker used malicious.example.com as C2.';
    const { user } = buildIocExtractionPrompt(report);

    expect(user).toContain(report);
  });

  it('should mention JSON output in system prompt', () => {
    const report = 'Test report';
    const { system } = buildIocExtractionPrompt(report);

    expect(system.toLowerCase()).toContain('json');
  });

  it('should instruct on IOC types', () => {
    const report = 'Test report';
    const { system } = buildIocExtractionPrompt(report);

    expect(system).toContain('ipv4');
    expect(system).toContain('domain');
    expect(system).toContain('url');
    expect(system).toContain('md5');
    expect(system).toContain('sha256');
  });

  it('should mention disambiguation', () => {
    const report = 'Test report';
    const { system } = buildIocExtractionPrompt(report);

    expect(system.toLowerCase()).toContain('disambiguat');
  });

  it('should mention confidence levels', () => {
    const report = 'Test report';
    const { system } = buildIocExtractionPrompt(report);

    expect(system).toContain('confidence');
    expect(system).toContain('high');
    expect(system).toContain('medium');
    expect(system).toContain('low');
  });

  it('should mention relationships', () => {
    const report = 'Test report';
    const { system } = buildIocExtractionPrompt(report);

    expect(system.toLowerCase()).toContain('relationship');
  });

  it('should handle empty report', () => {
    const report = '';
    const { system, user } = buildIocExtractionPrompt(report);

    expect(system).toBeTruthy();
    expect(user).toBeTruthy();
  });

  it('should handle very long report', () => {
    const report = 'A'.repeat(10000);
    const { user } = buildIocExtractionPrompt(report);

    expect(user).toContain(report);
  });
});

describe('buildIocDisambiguationPrompt', () => {
  it('should return system and user prompts', () => {
    const iocs: CandidateIOC[] = [
      {
        value: 'malicious.com',
        type: 'domain',
        context: 'C2 server mentioned in report',
      },
    ];

    const { system, user } = buildIocDisambiguationPrompt(iocs);

    expect(system).toBeTruthy();
    expect(user).toBeTruthy();
  });

  it('should include IOC values in user prompt', () => {
    const iocs: CandidateIOC[] = [
      {
        value: 'malicious.com',
        type: 'domain',
        context: 'C2 server',
      },
      {
        value: '192.0.2.1',
        type: 'ipv4',
        context: 'IP address in report',
      },
    ];

    const { user } = buildIocDisambiguationPrompt(iocs);

    expect(user).toContain('malicious.com');
    expect(user).toContain('192.0.2.1');
  });

  it('should include context for each IOC', () => {
    const iocs: CandidateIOC[] = [
      {
        value: 'test.com',
        type: 'domain',
        context: 'Important context about this domain',
      },
    ];

    const { user } = buildIocDisambiguationPrompt(iocs);

    expect(user).toContain('Important context about this domain');
  });

  it('should mention JSON output format', () => {
    const iocs: CandidateIOC[] = [{ value: 'test.com', type: 'domain', context: 'test' }];
    const { system } = buildIocDisambiguationPrompt(iocs);

    expect(system.toLowerCase()).toContain('json');
  });

  it('should handle empty IOC list', () => {
    const iocs: CandidateIOC[] = [];
    const { system, user } = buildIocDisambiguationPrompt(iocs);

    expect(system).toBeTruthy();
    expect(user).toBeTruthy();
  });

  it('should handle many IOCs', () => {
    const iocs: CandidateIOC[] = Array.from({ length: 50 }, (_, i) => ({
      value: `ioc-${i}.com`,
      type: 'domain',
      context: `Context for IOC ${i}`,
    }));

    const { user } = buildIocDisambiguationPrompt(iocs);

    expect(user).toContain('ioc-0.com');
    expect(user).toContain('ioc-49.com');
  });
});

describe('buildTtpExtractionPrompt', () => {
  it('should return system and user prompts', () => {
    const report = 'Attacker used PowerShell to download payload.';
    const { system, user } = buildTtpExtractionPrompt(report);

    expect(system).toBeTruthy();
    expect(user).toBeTruthy();
  });

  it('should include report text in user prompt', () => {
    const report = 'Mimikatz was used for credential dumping.';
    const { user } = buildTtpExtractionPrompt(report);

    expect(user).toContain(report);
  });

  it('should mention JSON output format', () => {
    const report = 'Test report';
    const { system } = buildTtpExtractionPrompt(report);

    expect(system.toLowerCase()).toContain('json');
  });

  it('should instruct on TTP components', () => {
    const report = 'Test report';
    const { system } = buildTtpExtractionPrompt(report);

    expect(system.toLowerCase()).toContain('description');
    expect(system.toLowerCase()).toContain('tools');
    expect(system.toLowerCase()).toContain('artifacts');
    expect(system.toLowerCase()).toContain('detection');
  });

  it('should mention artifact types', () => {
    const report = 'Test report';
    const { system } = buildTtpExtractionPrompt(report);

    expect(system).toContain('file');
    expect(system).toContain('registry');
    expect(system).toContain('event_log');
    expect(system).toContain('network');
    expect(system).toContain('process');
  });

  it('should emphasize detection opportunities', () => {
    const report = 'Test report';
    const { system } = buildTtpExtractionPrompt(report);

    expect(system.toLowerCase()).toContain('detection');
    expect(system.toLowerCase()).toContain('monitor');
  });

  it('should handle empty report', () => {
    const report = '';
    const { system, user } = buildTtpExtractionPrompt(report);

    expect(system).toBeTruthy();
    expect(user).toBeTruthy();
  });
});

describe('buildAttackMappingPrompt', () => {
  it('should return system and user prompts', () => {
    const ttps: CandidateTTP[] = [
      {
        description: 'PowerShell execution',
        tools: ['PowerShell'],
        artifacts: ['powershell.exe process'],
      },
    ];

    const { system, user } = buildAttackMappingPrompt(ttps);

    expect(system).toBeTruthy();
    expect(user).toBeTruthy();
  });

  it('should include TTP descriptions in user prompt', () => {
    const ttps: CandidateTTP[] = [
      {
        description: 'Credential dumping via LSASS access',
        tools: ['Mimikatz'],
        artifacts: ['LSASS memory'],
      },
    ];

    const { user } = buildAttackMappingPrompt(ttps);

    expect(user).toContain('Credential dumping via LSASS access');
  });

  it('should include tools in user prompt', () => {
    const ttps: CandidateTTP[] = [
      {
        description: 'Lateral movement',
        tools: ['PsExec', 'WMI'],
        artifacts: ['service creation'],
      },
    ];

    const { user } = buildAttackMappingPrompt(ttps);

    expect(user).toContain('PsExec');
    expect(user).toContain('WMI');
  });

  it('should mention subtechnique preference', () => {
    const ttps: CandidateTTP[] = [
      { description: 'Test', tools: [], artifacts: [] },
    ];

    const { system } = buildAttackMappingPrompt(ttps);

    expect(system.toLowerCase()).toContain('subtechnique');
  });

  it('should mention JSON output format', () => {
    const ttps: CandidateTTP[] = [
      { description: 'Test', tools: [], artifacts: [] },
    ];

    const { system } = buildAttackMappingPrompt(ttps);

    expect(system.toLowerCase()).toContain('json');
  });

  it('should mention suggested rule formats', () => {
    const ttps: CandidateTTP[] = [
      { description: 'Test', tools: [], artifacts: [] },
    ];

    const { system } = buildAttackMappingPrompt(ttps);

    expect(system).toContain('sigma');
    expect(system).toContain('yara');
    expect(system).toContain('suricata');
  });

  it('should handle empty tools and artifacts', () => {
    const ttps: CandidateTTP[] = [
      {
        description: 'Behavioral pattern observed',
        tools: [],
        artifacts: [],
      },
    ];

    const { user } = buildAttackMappingPrompt(ttps);

    expect(user).toContain('Behavioral pattern observed');
  });

  it('should handle multiple TTPs', () => {
    const ttps: CandidateTTP[] = [
      {
        description: 'Initial access via phishing',
        tools: ['Email'],
        artifacts: ['malicious attachment'],
      },
      {
        description: 'Execution via macro',
        tools: ['Excel'],
        artifacts: ['macro-enabled document'],
      },
    ];

    const { user } = buildAttackMappingPrompt(ttps);

    expect(user).toContain('Initial access via phishing');
    expect(user).toContain('Execution via macro');
  });

  it('should mention technique ID format', () => {
    const ttps: CandidateTTP[] = [
      { description: 'Test', tools: [], artifacts: [] },
    ];

    const { system } = buildAttackMappingPrompt(ttps);

    expect(system).toMatch(/T\d{4}/);
  });
});
