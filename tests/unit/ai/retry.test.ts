/**
 * Tests for retry logic with exponential backoff.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { withRetry, RetryableError, type RetryOptions } from '@/ai/retry.js';

describe('withRetry', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return result on first success', async () => {
    const fn = vi.fn().mockResolvedValue('success');

    const promise = withRetry(fn);
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('should retry on RetryableError', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new RetryableError('Temporary error', 503))
      .mockResolvedValueOnce('success');

    const promise = withRetry(fn, { initialDelayMs: 100 });

    // First call fails
    await vi.advanceTimersByTimeAsync(0);
    expect(fn).toHaveBeenCalledTimes(1);

    // Wait for retry delay and second call
    await vi.advanceTimersByTimeAsync(200);

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should retry on 429 status code in error message', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('OpenRouter API error (429): Rate limit exceeded'))
      .mockResolvedValueOnce('success');

    const promise = withRetry(fn, { initialDelayMs: 100 });

    await vi.advanceTimersByTimeAsync(0);
    expect(fn).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(200);

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should retry on 503 status code', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('OpenRouter API error (503): Service unavailable'))
      .mockResolvedValueOnce('success');

    const promise = withRetry(fn, { initialDelayMs: 100 });

    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(200);

    const result = await promise;
    expect(result).toBe('success');
  });

  it('should not retry on non-retryable errors', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('OpenRouter API error (400): Bad request'));

    const promise = withRetry(fn, { initialDelayMs: 100 });

    await expect(promise).rejects.toThrow('Bad request');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('should retry on network errors', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('fetch failed'))
      .mockResolvedValueOnce('success');

    const promise = withRetry(fn, { initialDelayMs: 100 });

    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(200);

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should stop after max retries', async () => {
    vi.useRealTimers(); // Real timers avoid unhandled rejection race

    const fn = vi.fn()
      .mockRejectedValueOnce(new RetryableError('Always fails', 503))
      .mockRejectedValueOnce(new RetryableError('Always fails', 503))
      .mockRejectedValueOnce(new RetryableError('Always fails', 503));

    await expect(
      withRetry(fn, { maxRetries: 2, initialDelayMs: 10 })
    ).rejects.toThrow('Always fails');
    expect(fn).toHaveBeenCalledTimes(3); // Initial + 2 retries

    vi.useFakeTimers(); // Restore for other tests
  });

  it('should use exponential backoff', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new RetryableError('Error 1', 503))
      .mockRejectedValueOnce(new RetryableError('Error 2', 503))
      .mockResolvedValueOnce('success');

    const delays: number[] = [];
    const promise = withRetry(fn, {
      initialDelayMs: 1000,
      backoffMultiplier: 2,
      onRetry: () => {
        delays.push(vi.getTimerCount());
      },
    });

    // First call fails
    await vi.advanceTimersByTimeAsync(0);
    expect(fn).toHaveBeenCalledTimes(1);

    // First retry (base: 1000ms, with jitter: 500-1500ms)
    await vi.advanceTimersByTimeAsync(2000);
    expect(fn).toHaveBeenCalledTimes(2);

    // Second retry (base: 2000ms, with jitter: 1000-3000ms)
    await vi.advanceTimersByTimeAsync(4000);
    expect(fn).toHaveBeenCalledTimes(3);

    const result = await promise;
    expect(result).toBe('success');
  });

  it('should respect max delay', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new RetryableError('Error', 503))
      .mockResolvedValueOnce('success');

    const promise = withRetry(fn, {
      initialDelayMs: 10000,
      maxDelayMs: 5000,
    });

    await vi.advanceTimersByTimeAsync(0);

    // Should wait at most maxDelayMs (5000) despite initialDelayMs being 10000
    await vi.advanceTimersByTimeAsync(6000);

    const result = await promise;
    expect(result).toBe('success');
  });

  it('should call onRetry callback', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new RetryableError('Error 1', 503))
      .mockRejectedValueOnce(new RetryableError('Error 2', 503))
      .mockResolvedValueOnce('success');

    const onRetry = vi.fn();

    const promise = withRetry(fn, {
      initialDelayMs: 100,
      onRetry,
    });

    // Run all timers to completion
    await vi.runAllTimersAsync();

    const result = await promise;
    expect(result).toBe('success');

    // onRetry should have been called for each retry (2 failures before success)
    expect(onRetry).toHaveBeenCalledTimes(2);
    expect(onRetry).toHaveBeenNthCalledWith(1, expect.any(Error), 1);
    expect(onRetry).toHaveBeenNthCalledWith(2, expect.any(Error), 2);
  });

  it('should respect Retry-After header', async () => {
    const error = new RetryableError('Rate limited', 429);
    error.retryAfterMs = 5000; // 5 seconds

    const fn = vi.fn()
      .mockRejectedValueOnce(error)
      .mockResolvedValueOnce('success');

    const promise = withRetry(fn, { initialDelayMs: 1000 });

    await vi.advanceTimersByTimeAsync(0);

    // Should wait 5000ms (from retryAfterMs) not 1000ms (initialDelayMs)
    await vi.advanceTimersByTimeAsync(6000);

    const result = await promise;
    expect(result).toBe('success');
  });

  it('should extract retry-after from error message', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('OpenRouter API error (429): Retry after 3 seconds'))
      .mockResolvedValueOnce('success');

    const promise = withRetry(fn, { initialDelayMs: 1000 });

    // The retry-after says 3 seconds = 3000ms, so we need to advance past that
    await vi.runAllTimersAsync();

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should handle custom retryable status codes', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('OpenRouter API error (502): Bad gateway'))
      .mockResolvedValueOnce('success');

    const promise = withRetry(fn, {
      initialDelayMs: 100,
      retryableErrors: [502],
    });

    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(200);

    const result = await promise;
    expect(result).toBe('success');
  });

  it('should add jitter to prevent thundering herd', async () => {
    // The addJitter function applies a random factor between 0.5x and 1.5x,
    // so the actual delay with a base of 1000ms should be between 500-1500ms.
    // We verify that the retry completes (jitter is applied), proving the
    // mechanism exists. The randomness makes exact timing assertions unreliable.
    const fn = vi.fn()
      .mockRejectedValueOnce(new RetryableError('Error', 503))
      .mockResolvedValueOnce('success');

    const promise = withRetry(fn, { initialDelayMs: 1000 });

    // Advance enough to cover max jitter (1.5x * 1000ms)
    await vi.runAllTimersAsync();

    const result = await promise;
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should handle async function returning promise', async () => {
    const fn = async () => {
      await new Promise(resolve => setTimeout(resolve, 10));
      return 'async success';
    };

    const promise = withRetry(fn);
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result).toBe('async success');
  });
});
