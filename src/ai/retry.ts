/**
 * Retry logic with exponential backoff for AI API calls.
 *
 * Features:
 * - Exponential backoff with jitter
 * - Respects Retry-After headers
 * - Configurable max retries and delays
 * - Callback hook for logging
 * - Only retries on retryable errors (429, 5xx, network)
 */

export interface RetryOptions {
  maxRetries?: number;         // default: 3
  initialDelayMs?: number;     // default: 1000
  maxDelayMs?: number;         // default: 30000
  backoffMultiplier?: number;  // default: 2
  retryableErrors?: number[];  // HTTP status codes to retry (default: [429, 500, 502, 503, 504])
  onRetry?: (error: Error, attempt: number) => void;
  /** Custom retryable check. Return true to retry, false to not, undefined to fall through to defaults. */
  isRetryable?: (error: Error) => boolean | undefined;
}

export class RetryableError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public retryAfterMs?: number
  ) {
    super(message);
    this.name = 'RetryableError';
  }
}

const DEFAULT_OPTIONS: Required<Omit<RetryOptions, 'onRetry' | 'isRetryable'>> = {
  maxRetries: 3,
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  backoffMultiplier: 2,
  retryableErrors: [429, 500, 502, 503, 504],
};

/**
 * Execute a function with retry logic.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  let lastError: Error;

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      // Check if error is retryable
      if (!isRetryableError(error, opts.retryableErrors, options.isRetryable)) {
        throw error;
      }

      // Don't retry after max attempts
      if (attempt === opts.maxRetries) {
        throw error;
      }

      // Calculate delay with exponential backoff and jitter
      const retryAfterMs = extractRetryAfter(error);
      const baseDelay = retryAfterMs || calculateBackoff(attempt, opts.initialDelayMs, opts.backoffMultiplier);
      const delayMs = Math.min(addJitter(baseDelay), opts.maxDelayMs);

      // Invoke retry callback if provided
      if (options.onRetry) {
        options.onRetry(error as Error, attempt + 1);
      }

      // Wait before retrying
      await sleep(delayMs);
    }
  }

  // Should never reach here, but TypeScript needs it
  throw lastError!;
}

/**
 * Check if an error is retryable.
 */
function isRetryableError(
  error: unknown,
  retryableStatuses: number[],
  customCheck?: (error: Error) => boolean | undefined,
): boolean {
  // Check custom retryable function first
  if (customCheck && error instanceof Error) {
    const result = customCheck(error);
    if (result !== undefined) return result;
  }

  if (error instanceof RetryableError) {
    return true;
  }

  // Check for HTTP status codes in error message (common pattern)
  if (error instanceof Error) {
    // OpenRouter API error format: "OpenRouter API error (429): ..."
    const statusMatch = error.message.match(/\((\d{3})\)/);
    if (statusMatch) {
      const status = parseInt(statusMatch[1], 10);
      return retryableStatuses.includes(status);
    }

    // Network errors (fetch failures)
    if (
      error.message.includes('fetch failed') ||
      error.message.includes('ECONNREFUSED') ||
      error.message.includes('ETIMEDOUT') ||
      error.message.includes('ENOTFOUND')
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Extract Retry-After value from error message.
 * Returns milliseconds or null if not found.
 */
function extractRetryAfter(error: unknown): number | null {
  if (!(error instanceof Error)) {
    return null;
  }

  // Look for "Retry-After: 5" or "retry after 5 seconds" patterns
  const retryAfterMatch = error.message.match(/retry[- ]after[:\s]+(\d+)/i);
  if (retryAfterMatch) {
    const seconds = parseInt(retryAfterMatch[1], 10);
    return seconds * 1000;
  }

  return null;
}

/**
 * Calculate exponential backoff delay.
 */
function calculateBackoff(attempt: number, initialDelayMs: number, multiplier: number): number {
  return initialDelayMs * Math.pow(multiplier, attempt);
}

/**
 * Add jitter to prevent thundering herd.
 * Returns a value between 0.5x and 1.5x the input.
 */
function addJitter(delayMs: number): number {
  const jitterFactor = 0.5 + Math.random(); // Random value between 0.5 and 1.5
  return Math.floor(delayMs * jitterFactor);
}

/**
 * Sleep for the specified duration.
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
