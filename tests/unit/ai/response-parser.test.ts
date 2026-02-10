/**
 * Tests for AI response parser with Zod validation.
 */

import { describe, it, expect } from 'vitest';
import {
  extractJsonFromResponse,
  parseIocResponse,
  parseTtpResponse,
  parseAttackMappingResponse,
  parseIocDisambiguationResponse,
  type IocResponse,
  type TtpResponse,
  type AttackMappingResponse,
} from '@/ai/response-parser.js';

describe('extractJsonFromResponse', () => {
  it('should extract raw JSON', () => {
    const raw = '{"key": "value"}';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ key: 'value' });
  });

  it('should extract JSON from markdown code block', () => {
    const raw = '```json\n{"key": "value"}\n```';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ key: 'value' });
  });

  it('should extract JSON from code block without language specifier', () => {
    const raw = '```\n{"key": "value"}\n```';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ key: 'value' });
  });

  it('should extract JSON with extra text before', () => {
    const raw = 'Here is the result:\n{"key": "value"}';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ key: 'value' });
  });

  it('should extract JSON with extra text after', () => {
    const raw = '{"key": "value"}\n\nHope this helps!';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ key: 'value' });
  });

  it('should extract nested JSON', () => {
    const raw = '```json\n{"outer": {"inner": "value"}}\n```';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ outer: { inner: 'value' } });
  });

  it('should handle JSON with arrays', () => {
    const raw = '{"items": [1, 2, 3]}';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ items: [1, 2, 3] });
  });

  it('should repair trailing commas', () => {
    const raw = '{"key": "value",}';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ key: 'value' });
  });

  it('should repair unclosed braces', () => {
    const raw = '{"key": "value"';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ key: 'value' });
  });

  it('should repair unclosed brackets', () => {
    const raw = '{"items": [1, 2, 3}';
    const result = extractJsonFromResponse(raw);
    expect(result).toEqual({ items: [1, 2, 3] });
  });

  it('should throw on invalid JSON', () => {
    const raw = 'not json at all';
    expect(() => extractJsonFromResponse(raw)).toThrow();
  });
});

describe('parseIocResponse', () => {
  it('should parse valid IOC response', () => {
    const raw = JSON.stringify({
      iocs: [
        {
          value: 'malicious.example.com',
          type: 'domain',
          context: 'C2 server used for data exfiltration.',
          confidence: 'high',
          defanged: true,
          originalValue: 'malicious[.]example[.]com',
          relationships: [
            { relatedIOC: '192.0.2.1', relationship: 'resolves to' },
          ],
        },
      ],
    });

    const result = parseIocResponse(raw);
    expect(result.iocs).toHaveLength(1);
    expect(result.iocs[0].value).toBe('malicious.example.com');
    expect(result.iocs[0].type).toBe('domain');
    expect(result.iocs[0].relationships).toHaveLength(1);
  });

  it('should apply default for missing relationships', () => {
    const raw = JSON.stringify({
      iocs: [
        {
          value: '192.0.2.1',
          type: 'ipv4',
          context: 'C2 IP address',
          confidence: 'high',
          defanged: false,
          originalValue: '192.0.2.1',
        },
      ],
    });

    const result = parseIocResponse(raw);
    expect(result.iocs[0].relationships).toEqual([]);
  });

  it('should validate IOC types', () => {
    const raw = JSON.stringify({
      iocs: [
        {
          value: 'test',
          type: 'invalid_type',
          context: 'context',
          confidence: 'high',
          defanged: false,
          originalValue: 'test',
        },
      ],
    });

    expect(() => parseIocResponse(raw)).toThrow(/validation failed/);
  });

  it('should validate confidence levels', () => {
    const raw = JSON.stringify({
      iocs: [
        {
          value: 'test.com',
          type: 'domain',
          context: 'context',
          confidence: 'invalid',
          defanged: false,
          originalValue: 'test.com',
        },
      ],
    });

    expect(() => parseIocResponse(raw)).toThrow(/validation failed/);
  });

  it('should handle multiple IOCs', () => {
    const raw = JSON.stringify({
      iocs: [
        {
          value: 'malicious.com',
          type: 'domain',
          context: 'C2',
          confidence: 'high',
          defanged: false,
          originalValue: 'malicious.com',
        },
        {
          value: '192.0.2.1',
          type: 'ipv4',
          context: 'C2 IP',
          confidence: 'high',
          defanged: false,
          originalValue: '192.0.2.1',
        },
      ],
    });

    const result = parseIocResponse(raw);
    expect(result.iocs).toHaveLength(2);
  });

  it('should parse from markdown wrapped response', () => {
    const raw = '```json\n' + JSON.stringify({
      iocs: [
        {
          value: 'test.com',
          type: 'domain',
          context: 'test',
          confidence: 'medium',
          defanged: false,
          originalValue: 'test.com',
          relationships: [],
        },
      ],
    }) + '\n```';

    const result = parseIocResponse(raw);
    expect(result.iocs).toHaveLength(1);
  });
});

describe('parseTtpResponse', () => {
  it('should parse valid TTP response', () => {
    const raw = JSON.stringify({
      ttps: [
        {
          description: 'PowerShell used to download second-stage payload.',
          tools: ['PowerShell'],
          targetPlatforms: ['Windows'],
          artifacts: [
            {
              type: 'process',
              description: 'powershell.exe with network connection',
            },
          ],
          detectionOpportunities: [
            'Monitor PowerShell with network connections',
            'Alert on encoded commands',
          ],
          confidence: 'high',
        },
      ],
    });

    const result = parseTtpResponse(raw);
    expect(result.ttps).toHaveLength(1);
    expect(result.ttps[0].tools).toContain('PowerShell');
    expect(result.ttps[0].artifacts).toHaveLength(1);
  });

  it('should apply defaults for optional fields', () => {
    const raw = JSON.stringify({
      ttps: [
        {
          description: 'Credential dumping observed.',
          confidence: 'medium',
        },
      ],
    });

    const result = parseTtpResponse(raw);
    expect(result.ttps[0].tools).toEqual([]);
    expect(result.ttps[0].targetPlatforms).toEqual([]);
    expect(result.ttps[0].artifacts).toEqual([]);
    expect(result.ttps[0].detectionOpportunities).toEqual([]);
  });

  it('should validate artifact types', () => {
    const raw = JSON.stringify({
      ttps: [
        {
          description: 'Test',
          confidence: 'high',
          artifacts: [
            {
              type: 'invalid_type',
              description: 'test',
            },
          ],
        },
      ],
    });

    expect(() => parseTtpResponse(raw)).toThrow(/validation failed/);
  });

  it('should handle artifacts with optional value', () => {
    const raw = JSON.stringify({
      ttps: [
        {
          description: 'Registry persistence',
          confidence: 'high',
          artifacts: [
            {
              type: 'registry',
              description: 'Run key created',
              value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            },
          ],
        },
      ],
    });

    const result = parseTtpResponse(raw);
    expect(result.ttps[0].artifacts[0].value).toBeDefined();
  });

  it('should handle multiple TTPs', () => {
    const raw = JSON.stringify({
      ttps: [
        {
          description: 'Initial access via phishing',
          confidence: 'high',
        },
        {
          description: 'Lateral movement via PsExec',
          confidence: 'high',
        },
      ],
    });

    const result = parseTtpResponse(raw);
    expect(result.ttps).toHaveLength(2);
  });
});

describe('parseAttackMappingResponse', () => {
  it('should parse valid ATT&CK mapping', () => {
    const raw = JSON.stringify({
      mappings: [
        {
          techniqueId: 'T1059.001',
          techniqueName: 'PowerShell',
          tactic: 'Execution',
          confidence: 'high',
          reasoning: 'PowerShell explicitly used for execution',
          suggestedRuleFormats: ['sigma'],
        },
      ],
    });

    const result = parseAttackMappingResponse(raw);
    expect(result.mappings).toHaveLength(1);
    expect(result.mappings[0].techniqueId).toBe('T1059.001');
  });

  it('should validate technique ID format', () => {
    const raw = JSON.stringify({
      mappings: [
        {
          techniqueId: 'INVALID',
          techniqueName: 'Test',
          tactic: 'Execution',
          confidence: 'high',
          reasoning: 'test',
        },
      ],
    });

    expect(() => parseAttackMappingResponse(raw)).toThrow(/Invalid ATT&CK technique ID/);
  });

  it('should accept parent technique IDs', () => {
    const raw = JSON.stringify({
      mappings: [
        {
          techniqueId: 'T1059',
          techniqueName: 'Command and Scripting Interpreter',
          tactic: 'Execution',
          confidence: 'medium',
          reasoning: 'General scripting observed',
          suggestedRuleFormats: ['sigma'],
        },
      ],
    });

    const result = parseAttackMappingResponse(raw);
    expect(result.mappings[0].techniqueId).toBe('T1059');
  });

  it('should accept subtechnique IDs', () => {
    const raw = JSON.stringify({
      mappings: [
        {
          techniqueId: 'T1003.001',
          techniqueName: 'LSASS Memory',
          tactic: 'Credential Access',
          confidence: 'high',
          reasoning: 'LSASS memory access detected',
          suggestedRuleFormats: ['sigma', 'yara'],
        },
      ],
    });

    const result = parseAttackMappingResponse(raw);
    expect(result.mappings[0].techniqueId).toBe('T1003.001');
  });

  it('should apply default suggested rule formats', () => {
    const raw = JSON.stringify({
      mappings: [
        {
          techniqueId: 'T1547.001',
          techniqueName: 'Registry Run Keys',
          tactic: 'Persistence',
          confidence: 'high',
          reasoning: 'Run key created',
        },
      ],
    });

    const result = parseAttackMappingResponse(raw);
    expect(result.mappings[0].suggestedRuleFormats).toEqual(['sigma']);
  });

  it('should validate suggested rule formats', () => {
    const raw = JSON.stringify({
      mappings: [
        {
          techniqueId: 'T1059.001',
          techniqueName: 'PowerShell',
          tactic: 'Execution',
          confidence: 'high',
          reasoning: 'test',
          suggestedRuleFormats: ['invalid'],
        },
      ],
    });

    expect(() => parseAttackMappingResponse(raw)).toThrow(/validation failed/);
  });

  it('should handle multiple mappings', () => {
    const raw = JSON.stringify({
      mappings: [
        {
          techniqueId: 'T1059.001',
          techniqueName: 'PowerShell',
          tactic: 'Execution',
          confidence: 'high',
          reasoning: 'PowerShell execution',
          suggestedRuleFormats: ['sigma'],
        },
        {
          techniqueId: 'T1547.001',
          techniqueName: 'Registry Run Keys',
          tactic: 'Persistence',
          confidence: 'high',
          reasoning: 'Registry persistence',
          suggestedRuleFormats: ['sigma'],
        },
      ],
    });

    const result = parseAttackMappingResponse(raw);
    expect(result.mappings).toHaveLength(2);
  });
});

describe('parseIocDisambiguationResponse', () => {
  it('should parse valid disambiguation response', () => {
    const raw = JSON.stringify({
      results: [
        {
          value: 'malicious.com',
          type: 'domain',
          isMalicious: true,
          confidence: 'high',
          reasoning: 'Identified as C2 server',
          relationships: [],
        },
        {
          value: 'google.com',
          type: 'domain',
          isMalicious: false,
          confidence: null,
          reasoning: 'Mentioned as example only',
          relationships: [],
        },
      ],
    });

    const result = parseIocDisambiguationResponse(raw);
    expect(result.results).toHaveLength(2);
    expect(result.results[0].isMalicious).toBe(true);
    expect(result.results[1].isMalicious).toBe(false);
    expect(result.results[1].confidence).toBeNull();
  });

  it('should apply default for missing relationships', () => {
    const raw = JSON.stringify({
      results: [
        {
          value: 'test.com',
          type: 'domain',
          isMalicious: true,
          confidence: 'medium',
          reasoning: 'Suspicious domain',
        },
      ],
    });

    const result = parseIocDisambiguationResponse(raw);
    expect(result.results[0].relationships).toEqual([]);
  });
});

describe('Error handling', () => {
  it('should provide helpful error messages for IOC validation failures', () => {
    const raw = JSON.stringify({
      iocs: [
        {
          value: 'test',
          // Missing required fields
        },
      ],
    });

    expect(() => parseIocResponse(raw)).toThrow(/validation failed/);
  });

  it('should include partial raw response in error message', () => {
    const raw = 'invalid json response';

    try {
      parseIocResponse(raw);
      expect.fail('Should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toContain('invalid');
    }
  });

  it('should truncate very long responses in error messages', () => {
    const longRaw = 'a'.repeat(1000);

    try {
      parseIocResponse(longRaw);
      expect.fail('Should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message.length).toBeLessThan(1000);
    }
  });
});
