/**
 * OpenRouter AI Client for DetectForge.
 *
 * Uses OpenRouter as the inference provider for cost-efficient model selection.
 * Supports three model tiers:
 *   - fast:     Cheap models for extraction, classification, simple tasks
 *   - standard: Balanced models for general tasks
 *   - quality:  Best models for rule generation, complex reasoning
 *
 * Tracks token usage and costs for transparency.
 */

import type { AIConfig, APIUsage } from '../types/config.js';

export type ModelTier = 'fast' | 'standard' | 'quality';

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface InferenceOptions {
  model?: ModelTier;
  temperature?: number;
  maxTokens?: number;
  jsonMode?: boolean;
}

export interface InferenceResult {
  content: string;
  usage: APIUsage;
}

// OpenRouter pricing per million tokens (approximate, updated as needed)
const MODEL_PRICING: Record<string, { input: number; output: number }> = {
  'google/gemini-2.0-flash-001':    { input: 0.10, output: 0.40 },
  'anthropic/claude-3.5-haiku':     { input: 0.80, output: 4.00 },
  'anthropic/claude-sonnet-4':      { input: 3.00, output: 15.00 },
  'meta-llama/llama-3.1-8b-instruct': { input: 0.06, output: 0.06 },
  'google/gemini-2.0-flash-lite-001': { input: 0.075, output: 0.30 },
};

export class AIClient {
  private config: AIConfig;
  private usageLog: APIUsage[] = [];

  constructor(config: AIConfig) {
    this.config = config;
  }

  /**
   * Create an AIClient from environment variables.
   */
  static fromEnv(): AIClient {
    const config: AIConfig = {
      provider: 'openrouter',
      openrouter: {
        apiKey: process.env.OPENROUTER_API_KEY || '',
        models: {
          fast: process.env.OPENROUTER_MODEL_FAST || 'google/gemini-2.0-flash-001',
          standard: process.env.OPENROUTER_MODEL_STANDARD || 'anthropic/claude-3.5-haiku',
          quality: process.env.OPENROUTER_MODEL_QUALITY || 'anthropic/claude-sonnet-4',
        },
        baseUrl: 'https://openrouter.ai/api/v1',
      },
      costTracking: process.env.TRACK_API_COSTS !== 'false',
      maxTokensPerRequest: 4096,
      temperature: 0.1,
    };

    if (!config.openrouter.apiKey) {
      throw new Error(
        'OPENROUTER_API_KEY is required. Set it in .env or environment.\n' +
        'Get a key at https://openrouter.ai/keys'
      );
    }

    return new AIClient(config);
  }

  /**
   * Run inference with the specified model tier.
   */
  async infer(
    messages: ChatMessage[],
    options: InferenceOptions = {}
  ): Promise<InferenceResult> {
    const tier = options.model || 'standard';
    const modelId = this.getModelId(tier);
    const startTime = Date.now();

    const body: Record<string, unknown> = {
      model: modelId,
      messages,
      temperature: options.temperature ?? this.config.temperature,
      max_tokens: options.maxTokens ?? this.config.maxTokensPerRequest,
    };

    if (options.jsonMode) {
      body.response_format = { type: 'json_object' };
    }

    const response = await fetch(`${this.config.openrouter.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.openrouter.apiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://github.com/Sim-Security/DetectForge',
        'X-Title': 'DetectForge',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`OpenRouter API error (${response.status}): ${errorText}`);
    }

    const data = await response.json() as {
      choices: Array<{ message: { content: string } }>;
      usage?: { prompt_tokens: number; completion_tokens: number };
    };

    const content = data.choices?.[0]?.message?.content || '';
    const inputTokens = data.usage?.prompt_tokens || 0;
    const outputTokens = data.usage?.completion_tokens || 0;
    const durationMs = Date.now() - startTime;
    const costUsd = this.calculateCost(modelId, inputTokens, outputTokens);

    const usage: APIUsage = {
      operation: 'inference',
      model: modelId,
      inputTokens,
      outputTokens,
      costUsd,
      durationMs,
      timestamp: new Date().toISOString(),
    };

    if (this.config.costTracking) {
      this.usageLog.push(usage);
    }

    return { content, usage };
  }

  /**
   * Convenience: single prompt inference.
   */
  async prompt(
    systemPrompt: string,
    userPrompt: string,
    options: InferenceOptions = {}
  ): Promise<InferenceResult> {
    return this.infer(
      [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      options
    );
  }

  /**
   * Convenience: JSON mode inference — returns parsed JSON.
   */
  async promptJson<T = unknown>(
    systemPrompt: string,
    userPrompt: string,
    options: InferenceOptions = {}
  ): Promise<{ data: T; usage: APIUsage }> {
    const result = await this.prompt(systemPrompt, userPrompt, {
      ...options,
      jsonMode: true,
    });

    // Try to parse JSON from the response
    let data: T;
    try {
      // Handle potential markdown code blocks wrapping JSON
      let jsonStr = result.content.trim();
      if (jsonStr.startsWith('```')) {
        jsonStr = jsonStr.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '');
      }
      data = JSON.parse(jsonStr) as T;
    } catch {
      throw new Error(
        `Failed to parse JSON response from AI:\n${result.content.substring(0, 500)}`
      );
    }

    return { data, usage: result.usage };
  }

  /**
   * Get the model ID for a given tier.
   */
  private getModelId(tier: ModelTier): string {
    return this.config.openrouter.models[tier];
  }

  /**
   * Calculate cost based on model pricing.
   */
  private calculateCost(modelId: string, inputTokens: number, outputTokens: number): number {
    const pricing = MODEL_PRICING[modelId];
    if (!pricing) {
      // Unknown model, estimate conservatively
      return (inputTokens * 1.0 + outputTokens * 3.0) / 1_000_000;
    }
    return (inputTokens * pricing.input + outputTokens * pricing.output) / 1_000_000;
  }

  /**
   * Get usage statistics.
   */
  getUsageLog(): APIUsage[] {
    return [...this.usageLog];
  }

  /**
   * Get cost summary.
   */
  getCostSummary(): {
    totalCostUsd: number;
    totalTokens: number;
    requestCount: number;
    byModel: Record<string, { count: number; costUsd: number }>;
  } {
    const byModel: Record<string, { count: number; costUsd: number }> = {};
    let totalCost = 0;
    let totalTokens = 0;

    for (const entry of this.usageLog) {
      totalCost += entry.costUsd;
      totalTokens += entry.inputTokens + entry.outputTokens;
      if (!byModel[entry.model]) {
        byModel[entry.model] = { count: 0, costUsd: 0 };
      }
      byModel[entry.model].count++;
      byModel[entry.model].costUsd += entry.costUsd;
    }

    return {
      totalCostUsd: Math.round(totalCost * 10000) / 10000,
      totalTokens,
      requestCount: this.usageLog.length,
      byModel,
    };
  }

  /**
   * Reset usage tracking.
   */
  resetUsage(): void {
    this.usageLog = [];
  }
}
