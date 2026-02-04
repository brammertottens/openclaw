/**
 * Session security service that integrates secure session key management
 * with rate limiting, diagnostic events, and the existing session system.
 */

import { emitDiagnosticEvent, isDiagnosticsEnabled } from "../infra/diagnostic-events.js";
import type { OpenClawConfig } from "../config/config.js";
import {
  generateSecureToken,
  isValidSecureToken,
  compareTokens,
  hashTokenForLog,
  createSecureSession,
  registerSecureSession,
  validateSecureSession,
  lookupTokenByLegacyKey,
  rotateSecureSession,
  revokeSecureSession,
  pruneExpiredSessions,
  getSessionsNeedingRotation,
  type SecureSessionConfig,
  type SecureSessionEntry,
  type SecureSessionMetadata,
} from "./secure-session-key.js";

// Rate limiting state
type RateLimitEntry = {
  count: number;
  windowStartMs: number;
};

const rateLimitMap = new Map<string, RateLimitEntry>();
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute window
const DEFAULT_RATE_LIMIT_PER_MINUTE = 100;

/**
 * Extract session security config from OpenClaw config.
 */
export function getSessionSecurityConfig(config?: OpenClawConfig): SecureSessionConfig {
  const security = config?.session?.security;
  return {
    enabled: security?.enabled ?? false,
    tokenBytes: security?.tokenBytes ?? 32,
    ttlMs: security?.ttlMs ?? 24 * 60 * 60 * 1000,
    rotationEnabled: security?.rotationEnabled ?? false,
    rotationIntervalMs: security?.rotationIntervalMs ?? 24 * 60 * 60 * 1000,
    rotationGraceMs: security?.rotationGraceMs ?? 5 * 60 * 1000,
  };
}

/**
 * Get rate limit from config.
 */
function getRateLimit(config?: OpenClawConfig): number {
  return config?.session?.security?.rateLimitPerMinute ?? DEFAULT_RATE_LIMIT_PER_MINUTE;
}

/**
 * Check if session creation is rate limited for a given context.
 */
export function isSessionRateLimited(
  contextKey: string,
  config?: OpenClawConfig,
): { limited: boolean; count: number; windowMs: number } {
  const limit = getRateLimit(config);
  if (limit <= 0) {
    return { limited: false, count: 0, windowMs: RATE_LIMIT_WINDOW_MS };
  }

  const now = Date.now();
  let entry = rateLimitMap.get(contextKey);

  // Reset window if expired
  if (entry && now - entry.windowStartMs >= RATE_LIMIT_WINDOW_MS) {
    entry = undefined;
    rateLimitMap.delete(contextKey);
  }

  const count = entry?.count ?? 0;
  return {
    limited: count >= limit,
    count,
    windowMs: RATE_LIMIT_WINDOW_MS,
  };
}

/**
 * Record a session creation for rate limiting.
 */
function recordSessionCreation(contextKey: string): void {
  const now = Date.now();
  let entry = rateLimitMap.get(contextKey);

  if (!entry || now - entry.windowStartMs >= RATE_LIMIT_WINDOW_MS) {
    entry = { count: 0, windowStartMs: now };
  }

  entry.count++;
  rateLimitMap.set(contextKey, entry);
}

/**
 * Create and register a new secure session with rate limiting and diagnostic events.
 */
export async function createSecureSessionWithSecurity(params: {
  agentId: string;
  legacyKey?: string;
  channel?: string;
  scope?: string;
  peerId?: string;
  accountId?: string;
  config?: OpenClawConfig;
  baseDir?: string;
}): Promise<SecureSessionEntry | null> {
  const securityConfig = getSessionSecurityConfig(params.config);

  // Check rate limit (key by agentId + channel)
  const rateLimitKey = `${params.agentId}:${params.channel ?? "default"}`;
  const rateCheck = isSessionRateLimited(rateLimitKey, params.config);

  if (rateCheck.limited) {
    if (isDiagnosticsEnabled(params.config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "rate.limited",
        agentId: params.agentId,
        channel: params.channel,
        reason: `Rate limit exceeded: ${rateCheck.count} sessions in ${rateCheck.windowMs}ms`,
        metadata: {
          rateLimitWindowMs: rateCheck.windowMs,
          rateLimitCount: rateCheck.count,
        },
      });
    }
    return null;
  }

  // Create the session
  const entry = createSecureSession({
    agentId: params.agentId,
    legacyKey: params.legacyKey,
    channel: params.channel,
    scope: params.scope,
    peerId: params.peerId,
    accountId: params.accountId,
    config: securityConfig,
  });

  // Register the session
  await registerSecureSession(entry, params.baseDir);

  // Record for rate limiting
  recordSessionCreation(rateLimitKey);

  // Emit diagnostic event
  if (isDiagnosticsEnabled(params.config)) {
    emitDiagnosticEvent({
      type: "session.security",
      action: "token.created",
      sessionKey: params.legacyKey,
      tokenHash: hashTokenForLog(entry.token),
      agentId: params.agentId,
      channel: params.channel,
      metadata: {
        expiresAtMs: entry.metadata.expiresAtMs,
      },
    });
  }

  return entry;
}

/**
 * Validate a session token with diagnostic events.
 */
export function validateSessionToken(
  token: string,
  config?: OpenClawConfig,
  baseDir?: string,
): SecureSessionMetadata | null {
  const metadata = validateSecureSession(token, baseDir);

  if (isDiagnosticsEnabled(config)) {
    if (metadata) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validated",
        sessionKey: metadata.legacyKey,
        tokenHash: hashTokenForLog(token),
        agentId: metadata.agentId,
        channel: metadata.channel,
      });
    } else {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validation.failed",
        tokenHash: isValidSecureToken(token) ? hashTokenForLog(token) : "invalid-format",
        reason: isValidSecureToken(token) ? "Token not found or expired" : "Invalid token format",
      });
    }
  }

  return metadata;
}

/**
 * Rotate a session token with diagnostic events.
 */
export async function rotateSessionToken(
  currentToken: string,
  config?: OpenClawConfig,
  baseDir?: string,
): Promise<SecureSessionEntry | null> {
  const securityConfig = getSessionSecurityConfig(config);
  const oldHash = hashTokenForLog(currentToken);

  const result = await rotateSecureSession(currentToken, securityConfig, baseDir);

  if (isDiagnosticsEnabled(config)) {
    if (result) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.rotated",
        sessionKey: result.metadata.legacyKey,
        tokenHash: hashTokenForLog(result.token),
        agentId: result.metadata.agentId,
        channel: result.metadata.channel,
        metadata: {
          rotatedFromHash: oldHash,
          expiresAtMs: result.metadata.expiresAtMs,
        },
      });
    }
  }

  return result;
}

/**
 * Revoke a session token with diagnostic events.
 */
export async function revokeSessionToken(
  token: string,
  config?: OpenClawConfig,
  baseDir?: string,
): Promise<boolean> {
  // Get metadata before revoking for diagnostic
  const metadata = validateSecureSession(token, baseDir);
  const result = await revokeSecureSession(token, baseDir);

  if (result && isDiagnosticsEnabled(config)) {
    emitDiagnosticEvent({
      type: "session.security",
      action: "token.revoked",
      sessionKey: metadata?.legacyKey,
      tokenHash: hashTokenForLog(token),
      agentId: metadata?.agentId,
      channel: metadata?.channel,
    });
  }

  return result;
}

/**
 * Get or create a secure session token for a legacy key.
 * If secure sessions are disabled, returns null (use legacy system).
 */
export async function getOrCreateSecureToken(params: {
  agentId: string;
  legacyKey: string;
  channel?: string;
  scope?: string;
  peerId?: string;
  accountId?: string;
  config?: OpenClawConfig;
  baseDir?: string;
}): Promise<string | null> {
  const securityConfig = getSessionSecurityConfig(params.config);

  if (!securityConfig.enabled) {
    return null;
  }

  // Try to find existing token for this legacy key
  const existingToken = lookupTokenByLegacyKey(params.legacyKey, params.baseDir);
  if (existingToken) {
    const metadata = validateSecureSession(existingToken, params.baseDir);
    if (metadata) {
      return existingToken;
    }
    // Token exists but is invalid/expired - create new one
  }

  // Create new secure session
  const entry = await createSecureSessionWithSecurity({
    agentId: params.agentId,
    legacyKey: params.legacyKey,
    channel: params.channel,
    scope: params.scope,
    peerId: params.peerId,
    accountId: params.accountId,
    config: params.config,
    baseDir: params.baseDir,
  });

  return entry?.token ?? null;
}

/**
 * Run maintenance tasks: prune expired sessions and rotate as needed.
 */
export async function runSessionSecurityMaintenance(
  config?: OpenClawConfig,
  baseDir?: string,
): Promise<{ pruned: number; rotated: number }> {
  const securityConfig = getSessionSecurityConfig(config);

  // Prune expired sessions
  const pruned = await pruneExpiredSessions(baseDir);

  // Emit events for pruned sessions
  if (pruned > 0 && isDiagnosticsEnabled(config)) {
    emitDiagnosticEvent({
      type: "session.security",
      action: "token.expired",
      reason: `Pruned ${pruned} expired sessions`,
    });
  }

  // Rotate sessions if enabled
  let rotated = 0;
  if (securityConfig.rotationEnabled) {
    const needsRotation = getSessionsNeedingRotation(securityConfig, baseDir);
    for (const entry of needsRotation) {
      const result = await rotateSessionToken(entry.token, config, baseDir);
      if (result) {
        rotated++;
      }
    }
  }

  return { pruned, rotated };
}

/**
 * Clear rate limit entries (for testing).
 */
export function clearRateLimitForTest(): void {
  rateLimitMap.clear();
}

// Re-export core functions for convenience
export {
  generateSecureToken,
  isValidSecureToken,
  compareTokens,
  hashTokenForLog,
  validateSecureSession,
  lookupTokenByLegacyKey,
  type SecureSessionConfig,
  type SecureSessionEntry,
  type SecureSessionMetadata,
};
