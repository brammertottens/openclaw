/**
 * Cryptographically secure session key generation and validation.
 *
 * This module provides:
 * - Secure random session token generation using CSPRNG
 * - Timing-safe validation to prevent timing attacks
 * - Session key mapping to associate tokens with metadata
 * - Session key rotation capabilities
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";

// Session token configuration
const SESSION_TOKEN_BYTES = 32; // 256 bits of entropy
const SESSION_TOKEN_HEX_LENGTH = SESSION_TOKEN_BYTES * 2; // 64 hex chars
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const DEFAULT_ROTATION_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Regex for validating secure session token format
const SECURE_TOKEN_RE = /^[a-f0-9]{64}$/i;

export type SecureSessionMetadata = {
  /** Original agent ID this session belongs to */
  agentId: string;
  /** Original session key (deterministic format) for backwards compatibility */
  legacyKey?: string;
  /** Channel this session originated from */
  channel?: string;
  /** Session scope (e.g., dm, group, channel) */
  scope?: string;
  /** Peer ID for peer-scoped sessions */
  peerId?: string;
  /** Account ID for account-scoped sessions */
  accountId?: string;
  /** Timestamp when the secure token was created */
  createdAtMs: number;
  /** Timestamp when the token was last rotated */
  rotatedAtMs?: number;
  /** Timestamp when the token expires (if rotation is enabled) */
  expiresAtMs?: number;
  /** Previous token (kept during rotation grace period) */
  previousToken?: string;
  /** When the previous token expires */
  previousTokenExpiresAtMs?: number;
};

export type SecureSessionEntry = {
  token: string;
  metadata: SecureSessionMetadata;
};

export type SecureSessionMappingFile = {
  version: 1;
  /** Map from secure token to metadata */
  tokenToMetadata: Record<string, SecureSessionMetadata>;
  /** Map from legacy key to secure token (for migration/lookup) */
  legacyKeyToToken: Record<string, string>;
  /** Configuration for rotation */
  rotationConfig?: {
    enabled: boolean;
    intervalMs: number;
    graceMs: number;
  };
};

export type SecureSessionConfig = {
  /** Enable secure session keys (default: false for backwards compatibility) */
  enabled: boolean;
  /** Token length in bytes (default: 32) */
  tokenBytes?: number;
  /** Session TTL in milliseconds (default: 24 hours, 0 = no expiry) */
  ttlMs?: number;
  /** Enable automatic rotation (default: false) */
  rotationEnabled?: boolean;
  /** Rotation interval in milliseconds (default: 24 hours) */
  rotationIntervalMs?: number;
  /** Grace period for old tokens after rotation (default: 5 minutes) */
  rotationGraceMs?: number;
};

const DEFAULT_CONFIG: Required<SecureSessionConfig> = {
  enabled: false,
  tokenBytes: SESSION_TOKEN_BYTES,
  ttlMs: DEFAULT_SESSION_TTL_MS,
  rotationEnabled: false,
  rotationIntervalMs: DEFAULT_ROTATION_INTERVAL_MS,
  rotationGraceMs: 5 * 60 * 1000, // 5 minutes
};

/**
 * Generates a cryptographically secure session token.
 * Uses Node.js crypto.randomBytes which is backed by OS-level CSPRNG.
 */
export function generateSecureToken(bytes: number = SESSION_TOKEN_BYTES): string {
  return crypto.randomBytes(bytes).toString("hex");
}

/**
 * Validates that a string is a properly formatted secure session token.
 */
export function isValidSecureToken(token: string | undefined | null): boolean {
  if (!token || typeof token !== "string") {
    return false;
  }
  return SECURE_TOKEN_RE.test(token);
}

/**
 * Timing-safe comparison of two session tokens.
 * Prevents timing attacks by ensuring constant-time comparison.
 */
export function compareTokens(a: string | undefined | null, b: string | undefined | null): boolean {
  if (!a || !b) {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
  } catch {
    return false;
  }
}

/**
 * Hash a token for logging purposes (never log raw tokens).
 */
export function hashTokenForLog(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex").slice(0, 12);
}

// In-memory cache for session mappings
let mappingCache: SecureSessionMappingFile | null = null;
let mappingCacheLoadedAt = 0;
const MAPPING_CACHE_TTL_MS = 30_000; // 30 seconds

function resolveMappingPath(baseDir?: string): string {
  const root = baseDir ?? resolveStateDir();
  return path.join(root, "sessions", "secure-mapping.json");
}

function isMappingCacheValid(): boolean {
  return mappingCache !== null && Date.now() - mappingCacheLoadedAt < MAPPING_CACHE_TTL_MS;
}

/**
 * Load the secure session mapping file.
 */
export function loadSecureSessionMapping(baseDir?: string): SecureSessionMappingFile {
  if (isMappingCacheValid() && mappingCache) {
    return structuredClone(mappingCache);
  }

  const filePath = resolveMappingPath(baseDir);
  let mapping: SecureSessionMappingFile = {
    version: 1,
    tokenToMetadata: {},
    legacyKeyToToken: {},
  };

  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw) as SecureSessionMappingFile;
    if (parsed?.version === 1) {
      mapping = parsed;
    }
  } catch {
    // File doesn't exist or is invalid - use empty mapping
  }

  mappingCache = structuredClone(mapping);
  mappingCacheLoadedAt = Date.now();
  return mapping;
}

/**
 * Save the secure session mapping file with atomic write.
 */
export async function saveSecureSessionMapping(
  mapping: SecureSessionMappingFile,
  baseDir?: string,
): Promise<void> {
  const filePath = resolveMappingPath(baseDir);
  const dir = path.dirname(filePath);

  await fs.promises.mkdir(dir, { recursive: true });

  const tmp = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const json = JSON.stringify(mapping, null, 2);

  try {
    await fs.promises.writeFile(tmp, json, { mode: 0o600, encoding: "utf-8" });
    await fs.promises.rename(tmp, filePath);
    await fs.promises.chmod(filePath, 0o600);
  } catch (err) {
    // Best-effort cleanup
    await fs.promises.rm(tmp, { force: true }).catch(() => undefined);
    throw err;
  }

  // Invalidate cache
  mappingCache = null;
}

/**
 * Create a new secure session entry.
 */
export function createSecureSession(params: {
  agentId: string;
  legacyKey?: string;
  channel?: string;
  scope?: string;
  peerId?: string;
  accountId?: string;
  config?: Partial<SecureSessionConfig>;
}): SecureSessionEntry {
  const config = { ...DEFAULT_CONFIG, ...params.config };
  const now = Date.now();

  const token = generateSecureToken(config.tokenBytes);
  const metadata: SecureSessionMetadata = {
    agentId: params.agentId,
    legacyKey: params.legacyKey,
    channel: params.channel,
    scope: params.scope,
    peerId: params.peerId,
    accountId: params.accountId,
    createdAtMs: now,
    expiresAtMs: config.ttlMs > 0 ? now + config.ttlMs : undefined,
  };

  return { token, metadata };
}

/**
 * Register a secure session in the mapping file.
 */
export async function registerSecureSession(
  entry: SecureSessionEntry,
  baseDir?: string,
): Promise<void> {
  const mapping = loadSecureSessionMapping(baseDir);

  mapping.tokenToMetadata[entry.token] = entry.metadata;
  if (entry.metadata.legacyKey) {
    mapping.legacyKeyToToken[entry.metadata.legacyKey] = entry.token;
  }

  await saveSecureSessionMapping(mapping, baseDir);
}

/**
 * Validate and resolve a secure session token.
 * Returns the metadata if valid, null if invalid or expired.
 */
export function validateSecureSession(
  token: string,
  baseDir?: string,
): SecureSessionMetadata | null {
  if (!isValidSecureToken(token)) {
    return null;
  }

  const mapping = loadSecureSessionMapping(baseDir);
  const metadata = mapping.tokenToMetadata[token];

  if (!metadata) {
    // Check if this is a previous token during rotation grace period
    for (const [currentToken, meta] of Object.entries(mapping.tokenToMetadata)) {
      if (
        meta.previousToken &&
        compareTokens(token, meta.previousToken) &&
        meta.previousTokenExpiresAtMs &&
        Date.now() < meta.previousTokenExpiresAtMs
      ) {
        // Return current token's metadata but flag it as rotated
        return { ...meta, rotatedAtMs: meta.rotatedAtMs ?? Date.now() };
      }
    }
    return null;
  }

  // Check expiration
  if (metadata.expiresAtMs && Date.now() > metadata.expiresAtMs) {
    return null;
  }

  return metadata;
}

/**
 * Lookup secure token by legacy key.
 */
export function lookupTokenByLegacyKey(legacyKey: string, baseDir?: string): string | null {
  const mapping = loadSecureSessionMapping(baseDir);
  return mapping.legacyKeyToToken[legacyKey] ?? null;
}

/**
 * Lookup metadata by legacy key.
 */
export function lookupMetadataByLegacyKey(
  legacyKey: string,
  baseDir?: string,
): SecureSessionMetadata | null {
  const token = lookupTokenByLegacyKey(legacyKey, baseDir);
  if (!token) {
    return null;
  }
  return validateSecureSession(token, baseDir);
}

/**
 * Rotate a secure session token.
 * Creates a new token and keeps the old one valid for a grace period.
 */
export async function rotateSecureSession(
  currentToken: string,
  config?: Partial<SecureSessionConfig>,
  baseDir?: string,
): Promise<SecureSessionEntry | null> {
  const resolvedConfig = { ...DEFAULT_CONFIG, ...config };
  const mapping = loadSecureSessionMapping(baseDir);
  const metadata = mapping.tokenToMetadata[currentToken];

  if (!metadata) {
    return null;
  }

  const now = Date.now();
  const newToken = generateSecureToken(resolvedConfig.tokenBytes);

  // Update metadata with rotation info
  const newMetadata: SecureSessionMetadata = {
    ...metadata,
    rotatedAtMs: now,
    expiresAtMs: resolvedConfig.ttlMs > 0 ? now + resolvedConfig.ttlMs : undefined,
    previousToken: currentToken,
    previousTokenExpiresAtMs: now + resolvedConfig.rotationGraceMs,
  };

  // Remove old token and add new one
  delete mapping.tokenToMetadata[currentToken];
  mapping.tokenToMetadata[newToken] = newMetadata;

  // Update legacy key mapping
  if (metadata.legacyKey) {
    mapping.legacyKeyToToken[metadata.legacyKey] = newToken;
  }

  await saveSecureSessionMapping(mapping, baseDir);

  return { token: newToken, metadata: newMetadata };
}

/**
 * Revoke a secure session token.
 */
export async function revokeSecureSession(token: string, baseDir?: string): Promise<boolean> {
  const mapping = loadSecureSessionMapping(baseDir);
  const metadata = mapping.tokenToMetadata[token];

  if (!metadata) {
    return false;
  }

  // Remove token
  delete mapping.tokenToMetadata[token];

  // Remove legacy key mapping if present
  if (metadata.legacyKey) {
    delete mapping.legacyKeyToToken[metadata.legacyKey];
  }

  await saveSecureSessionMapping(mapping, baseDir);
  return true;
}

/**
 * Prune expired sessions from the mapping.
 */
export async function pruneExpiredSessions(baseDir?: string): Promise<number> {
  const mapping = loadSecureSessionMapping(baseDir);
  const now = Date.now();
  let pruned = 0;

  for (const [token, metadata] of Object.entries(mapping.tokenToMetadata)) {
    if (metadata.expiresAtMs && now > metadata.expiresAtMs) {
      delete mapping.tokenToMetadata[token];
      if (metadata.legacyKey) {
        delete mapping.legacyKeyToToken[metadata.legacyKey];
      }
      pruned++;
    }
  }

  if (pruned > 0) {
    await saveSecureSessionMapping(mapping, baseDir);
  }

  return pruned;
}

/**
 * Get all sessions that need rotation (based on rotation interval).
 */
export function getSessionsNeedingRotation(
  config?: Partial<SecureSessionConfig>,
  baseDir?: string,
): SecureSessionEntry[] {
  const resolvedConfig = { ...DEFAULT_CONFIG, ...config };
  if (!resolvedConfig.rotationEnabled) {
    return [];
  }

  const mapping = loadSecureSessionMapping(baseDir);
  const now = Date.now();
  const needsRotation: SecureSessionEntry[] = [];

  for (const [token, metadata] of Object.entries(mapping.tokenToMetadata)) {
    const lastRotation = metadata.rotatedAtMs ?? metadata.createdAtMs;
    if (now - lastRotation >= resolvedConfig.rotationIntervalMs) {
      needsRotation.push({ token, metadata });
    }
  }

  return needsRotation;
}

/**
 * Clear the in-memory cache (for testing).
 */
export function clearSecureSessionCache(): void {
  mappingCache = null;
  mappingCacheLoadedAt = 0;
}

export { DEFAULT_CONFIG as DEFAULT_SECURE_SESSION_CONFIG };
