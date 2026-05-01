/**
 * Per-key rate limiter with TTL-based windowing.
 *
 * Tracks failure counts per key (e.g. client IP) inside a sliding window so
 * repeated authentication failures from the same source can be temporarily
 * blocked without an external dependency. Used by the WebSocket handshake to
 * mitigate brute-force token/password guessing.
 */

export type RateLimiterOptions = {
  /** Maximum failures permitted within the window before checkLimit() denies. */
  threshold: number;
  /** Window length in milliseconds. */
  windowMs: number;
};

export type RateLimitDecision = {
  allowed: boolean;
  retryAfterMs?: number;
};

type Entry = {
  count: number;
  windowStartMs: number;
};

export type RateLimiter = {
  readonly name: string;
  readonly options: RateLimiterOptions;
  checkLimit(key: string): RateLimitDecision;
  recordFailure(key: string, ttlMs?: number): void;
  reset(key?: string): void;
};

const DEFAULT_THRESHOLD = 5;
const DEFAULT_WINDOW_MS = 60_000;

const limiters = new Map<string, RateLimiter>();

function createRateLimiter(name: string, options: RateLimiterOptions): RateLimiter {
  const entries = new Map<string, Entry>();

  function pruneIfExpired(key: string, now: number, windowMs: number): Entry | undefined {
    const entry = entries.get(key);
    if (!entry) {
      return undefined;
    }
    if (now - entry.windowStartMs >= windowMs) {
      entries.delete(key);
      return undefined;
    }
    return entry;
  }

  return {
    name,
    options,
    checkLimit(key: string): RateLimitDecision {
      const { threshold, windowMs } = this.options;
      if (threshold <= 0 || windowMs <= 0) {
        return { allowed: true };
      }
      const now = Date.now();
      const entry = pruneIfExpired(key, now, windowMs);
      if (!entry) {
        return { allowed: true };
      }
      if (entry.count >= threshold) {
        const retryAfterMs = Math.max(0, windowMs - (now - entry.windowStartMs));
        return { allowed: false, retryAfterMs };
      }
      return { allowed: true };
    },
    recordFailure(key: string, ttlMs?: number): void {
      const windowMs = ttlMs && ttlMs > 0 ? ttlMs : this.options.windowMs;
      if (windowMs <= 0) {
        return;
      }
      const now = Date.now();
      const existing = pruneIfExpired(key, now, windowMs);
      if (!existing) {
        entries.set(key, { count: 1, windowStartMs: now });
        return;
      }
      existing.count += 1;
      entries.set(key, existing);
    },
    reset(key?: string): void {
      if (typeof key === "string") {
        entries.delete(key);
        return;
      }
      entries.clear();
    },
  };
}

/**
 * Returns a named rate limiter, creating it lazily on first use. Subsequent
 * calls with the same name return the same instance so callers can share
 * counters across modules.
 */
export function getRateLimiter(
  name: string,
  options: Partial<RateLimiterOptions> = {},
): RateLimiter {
  const existing = limiters.get(name);
  if (existing) {
    if (options.threshold !== undefined && options.threshold !== existing.options.threshold) {
      existing.options.threshold = options.threshold;
    }
    if (options.windowMs !== undefined && options.windowMs !== existing.options.windowMs) {
      existing.options.windowMs = options.windowMs;
    }
    return existing;
  }
  const limiter = createRateLimiter(name, {
    threshold: options.threshold ?? DEFAULT_THRESHOLD,
    windowMs: options.windowMs ?? DEFAULT_WINDOW_MS,
  });
  limiters.set(name, limiter);
  return limiter;
}

/** Test helper: forget every limiter and its counters. */
export function __resetAllRateLimiters(): void {
  for (const limiter of limiters.values()) {
    limiter.reset();
  }
  limiters.clear();
}
