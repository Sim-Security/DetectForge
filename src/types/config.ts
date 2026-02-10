/**
 * Configuration types for DetectForge.
 */

export interface DetectForgeConfig {
  ai: AIConfig;
  output: OutputConfig;
  logging: LogConfig;
}

export interface AIConfig {
  provider: 'openrouter' | 'anthropic';
  openrouter: {
    apiKey: string;
    models: {
      fast: string;       // Cheap, for extraction/classification
      standard: string;   // Balanced, for general tasks
      quality: string;    // Best, for rule generation
    };
    baseUrl: string;
  };
  anthropic?: {
    apiKey: string;
    model: string;
  };
  costTracking: boolean;
  maxTokensPerRequest: number;
  temperature: number;
}

export interface OutputConfig {
  formats: ('sigma' | 'yara' | 'suricata')[];
  outputDir: string;
  includeDocumentation: boolean;
  includeBenchmarks: boolean;
  sarif: boolean;
  navigatorLayer: boolean;
  jsonReport: boolean;
  markdownReport: boolean;
}

export interface LogConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  file?: string;
}

// Cost tracking

export interface APIUsage {
  operation: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  durationMs: number;
  timestamp: string;
}

export interface CostReport {
  totalCostUsd: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  byOperation: Record<string, { count: number; costUsd: number; tokens: number }>;
  byModel: Record<string, { count: number; costUsd: number; tokens: number }>;
}
