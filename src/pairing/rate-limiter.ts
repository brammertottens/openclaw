/**
 * Pairing-code rate limiter.
 *
 * Tracks failed pairing-code attempts per (channel, sender) pair so a single
 * attacker on a messaging channel cannot brute-force the short pairing code.
 * Defaults: 3 attempts per 60-second window (0 disables).
 */

import { loadConfig } from "../config/config.js";
import { getRateLimiter, type RateLimitDecision } from "../gateway/rate-limiter.js";

const PAIRING_LIMITER_NAME = "pairing-code";
const DEFAULT_PAIRING_THRESHOLD = 3;
const DEFAULT_PAIRING_WINDOW_MS = 60_000;

function readEnvNumber(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw) {
    return undefined;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

function resolvePairingLimits(): { threshold: number; windowMs: number } {
  let cfg: ReturnType<typeof loadConfig> | undefined;
  try {
    cfg = loadConfig();
  } catch {
    cfg = undefined;
  }
  const pairingCfg = cfg?.pairing;
  const threshold =
    readEnvNumber("OPENCLAW_PAIRING_CODE_RATE_LIMIT_PER_SENDER") ??
    pairingCfg?.codeRateLimitPerSender ??
    DEFAULT_PAIRING_THRESHOLD;
  const windowMs =
    readEnvNumber("OPENCLAW_PAIRING_CODE_RATE_LIMIT_WINDOW_MS") ??
    pairingCfg?.codeRateLimitWindowMs ??
    DEFAULT_PAIRING_WINDOW_MS;
  return { threshold, windowMs };
}

function makeKey(channel: string, senderId: string): string {
  const safeChannel =
    String(channel ?? "")
      .trim()
      .toLowerCase() || "unknown";
  const safeSender =
    String(senderId ?? "")
      .trim()
      .toLowerCase() || "unknown";
  return `${safeChannel}:${safeSender}`;
}

/**
 * Returns whether another pairing-code attempt is allowed for this
 * (channel, senderId). When `senderId` is "unknown" the limit still applies
 * but is shared across all unidentified senders for that channel — useful as a
 * coarse fallback when callers cannot extract a sender identity.
 */
export function checkPairingCodeLimit(
  channel: string,
  senderId: string,
): { allowed: boolean; retryAfterMs?: number } {
  const { threshold, windowMs } = resolvePairingLimits();
  const limiter = getRateLimiter(PAIRING_LIMITER_NAME, { threshold, windowMs });
  const decision: RateLimitDecision = limiter.checkLimit(makeKey(channel, senderId));
  return decision;
}

/**
 * Records a failed pairing-code attempt. Counts toward the threshold checked
 * by `checkPairingCodeLimit`.
 */
export function recordPairingCodeFailure(channel: string, senderId: string): void {
  const { threshold, windowMs } = resolvePairingLimits();
  const limiter = getRateLimiter(PAIRING_LIMITER_NAME, { threshold, windowMs });
  limiter.recordFailure(makeKey(channel, senderId), windowMs);
}
