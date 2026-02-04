/**
 * Session context signing with Ed25519 signatures.
 *
 * This module provides cryptographic signing and verification for session context
 * transitions to prevent unauthorized escalation from sandbox to main session.
 *
 * Uses Node.js built-in crypto module for Ed25519 operations (same pattern as
 * device-identity.ts).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import { emitDiagnosticEvent, isDiagnosticsEnabled } from "../infra/diagnostic-events.js";
import type { OpenClawConfig } from "../config/config.js";
import { hashTokenForLog } from "./secure-session-key.js";

// Session context types
export type SessionContextType = "main" | "sandbox" | "subagent" | "elevated";

export type SessionContext = {
  /** Unique session identifier */
  sessionId: string;
  /** Context type (main, sandbox, subagent, elevated) */
  contextType: SessionContextType;
  /** Agent ID this session belongs to */
  agentId: string;
  /** Timestamp when context was created (ms since epoch) */
  createdAtMs: number;
  /** Optional parent session ID for spawned sessions */
  parentSessionId?: string;
  /** Optional parent context type */
  parentContextType?: SessionContextType;
  /** Expiration timestamp (ms since epoch) */
  expiresAtMs?: number;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
};

export type SignedSessionContext = {
  context: SessionContext;
  /** Ed25519 signature of the canonical context JSON */
  signature: string;
  /** Public key fingerprint (SHA256 of raw public key bytes) */
  signerKeyId: string;
};

export type SessionContextKeyPair = {
  keyId: string;
  publicKeyPem: string;
  privateKeyPem: string;
  createdAtMs: number;
};

export type SessionContextTransition = {
  from: SessionContextType;
  to: SessionContextType;
  sessionId: string;
  timestamp: number;
  signedContext?: SignedSessionContext;
};

// Allowed context transitions (from -> to[])
const ALLOWED_TRANSITIONS: Record<SessionContextType, SessionContextType[]> = {
  main: ["sandbox", "subagent", "elevated"],
  sandbox: [], // Cannot transition from sandbox to anything
  subagent: [], // Cannot transition from subagent
  elevated: ["main"], // Can de-escalate from elevated to main
};

// Context validity duration
const DEFAULT_CONTEXT_TTL_MS = 5 * 60 * 1000; // 5 minutes
const CONTEXT_SIGNATURE_VERSION = 1;

// Ed25519 SPKI prefix for raw key extraction
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Base64URL encoding (same as device-identity.ts)
 */
function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

/**
 * Base64URL decoding
 */
function base64UrlDecode(input: string): Buffer {
  const normalized = input.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

/**
 * Extract raw public key bytes from PEM
 */
function derivePublicKeyRaw(publicKeyPem: string): Buffer {
  const key = crypto.createPublicKey(publicKeyPem);
  const spki = key.export({ type: "spki", format: "der" }) as Buffer;
  if (
    spki.length === ED25519_SPKI_PREFIX.length + 32 &&
    spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    return spki.subarray(ED25519_SPKI_PREFIX.length);
  }
  return spki;
}

/**
 * Compute key ID (SHA256 fingerprint of raw public key)
 */
function computeKeyId(publicKeyPem: string): string {
  const raw = derivePublicKeyRaw(publicKeyPem);
  return crypto.createHash("sha256").update(raw).digest("hex");
}

/**
 * Generate a new Ed25519 key pair for session context signing.
 */
export function generateContextKeyPair(): SessionContextKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const keyId = computeKeyId(publicKeyPem);

  return {
    keyId,
    publicKeyPem,
    privateKeyPem,
    createdAtMs: Date.now(),
  };
}

/**
 * Canonicalize a session context for signing.
 * Produces deterministic JSON with sorted keys.
 */
export function canonicalizeContext(context: SessionContext): string {
  const ordered = {
    v: CONTEXT_SIGNATURE_VERSION,
    sessionId: context.sessionId,
    contextType: context.contextType,
    agentId: context.agentId,
    createdAtMs: context.createdAtMs,
    parentSessionId: context.parentSessionId,
    parentContextType: context.parentContextType,
    expiresAtMs: context.expiresAtMs,
  };
  return JSON.stringify(ordered);
}

/**
 * Sign a session context with Ed25519.
 */
export function signSessionContext(
  context: SessionContext,
  privateKeyPem: string,
  publicKeyPem: string,
): SignedSessionContext {
  const canonical = canonicalizeContext(context);
  const key = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(null, Buffer.from(canonical, "utf8"), key);

  return {
    context,
    signature: base64UrlEncode(signature),
    signerKeyId: computeKeyId(publicKeyPem),
  };
}

/**
 * Verify a signed session context.
 */
export function verifySignedContext(
  signed: SignedSessionContext,
  publicKeyPem: string,
): { valid: boolean; reason?: string } {
  try {
    // Verify key ID matches
    const expectedKeyId = computeKeyId(publicKeyPem);
    if (signed.signerKeyId !== expectedKeyId) {
      return { valid: false, reason: "Key ID mismatch" };
    }

    // Verify signature
    const canonical = canonicalizeContext(signed.context);
    const key = crypto.createPublicKey(publicKeyPem);
    const signature = base64UrlDecode(signed.signature);
    const isValid = crypto.verify(null, Buffer.from(canonical, "utf8"), key, signature);

    if (!isValid) {
      return { valid: false, reason: "Invalid signature" };
    }

    // Check expiration
    if (signed.context.expiresAtMs && Date.now() > signed.context.expiresAtMs) {
      return { valid: false, reason: "Context expired" };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, reason: `Verification error: ${err}` };
  }
}

/**
 * Check if a context transition is allowed.
 */
export function isTransitionAllowed(from: SessionContextType, to: SessionContextType): boolean {
  const allowed = ALLOWED_TRANSITIONS[from];
  return allowed?.includes(to) ?? false;
}

/**
 * Validate a context transition with cryptographic verification.
 */
export function validateContextTransition(
  transition: SessionContextTransition,
  trustedPublicKeys: Map<string, string>,
  config?: OpenClawConfig,
): { valid: boolean; reason?: string } {
  // Check if transition type is allowed
  if (!isTransitionAllowed(transition.from, transition.to)) {
    if (isDiagnosticsEnabled(config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validation.failed",
        sessionKey: transition.sessionId,
        reason: `Disallowed transition: ${transition.from} -> ${transition.to}`,
      });
    }
    return {
      valid: false,
      reason: `Transition from ${transition.from} to ${transition.to} is not allowed`,
    };
  }

  // For transitions TO more privileged contexts, require signed context
  const requiresSignature = transition.to === "main" || transition.to === "elevated";
  if (requiresSignature && !transition.signedContext) {
    if (isDiagnosticsEnabled(config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validation.failed",
        sessionKey: transition.sessionId,
        reason: `Missing signature for transition to ${transition.to}`,
      });
    }
    return {
      valid: false,
      reason: `Signed context required for transition to ${transition.to}`,
    };
  }

  // Verify signature if present
  if (transition.signedContext) {
    const publicKey = trustedPublicKeys.get(transition.signedContext.signerKeyId);
    if (!publicKey) {
      if (isDiagnosticsEnabled(config)) {
        emitDiagnosticEvent({
          type: "session.security",
          action: "token.validation.failed",
          sessionKey: transition.sessionId,
          reason: `Unknown signer key: ${transition.signedContext.signerKeyId.slice(0, 12)}...`,
        });
      }
      return { valid: false, reason: "Unknown signer key" };
    }

    const verification = verifySignedContext(transition.signedContext, publicKey);
    if (!verification.valid) {
      if (isDiagnosticsEnabled(config)) {
        emitDiagnosticEvent({
          type: "session.security",
          action: "token.validation.failed",
          sessionKey: transition.sessionId,
          reason: verification.reason,
        });
      }
      return verification;
    }

    // Verify context matches transition
    if (transition.signedContext.context.sessionId !== transition.sessionId) {
      return { valid: false, reason: "Session ID mismatch in signed context" };
    }
    if (transition.signedContext.context.contextType !== transition.to) {
      return { valid: false, reason: "Context type mismatch in signed context" };
    }
  }

  // Valid transition
  if (isDiagnosticsEnabled(config)) {
    emitDiagnosticEvent({
      type: "session.security",
      action: "token.validated",
      sessionKey: transition.sessionId,
      metadata: {
        transitionFrom: transition.from,
        transitionTo: transition.to,
      },
    });
  }

  return { valid: true };
}

// Key storage
type ContextKeyStore = {
  version: 1;
  keys: Record<string, SessionContextKeyPair>;
  activeKeyId?: string;
};

function resolveKeyStorePath(baseDir?: string): string {
  const root = baseDir ?? resolveStateDir();
  return path.join(root, "sessions", "context-keys.json");
}

/**
 * Load or create the context signing key store.
 */
export function loadContextKeyStore(baseDir?: string): ContextKeyStore {
  const filePath = resolveKeyStorePath(baseDir);

  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, "utf8");
      const parsed = JSON.parse(raw) as ContextKeyStore;
      if (parsed?.version === 1 && parsed.keys) {
        return parsed;
      }
    }
  } catch {
    // Fall through to create new store
  }

  return { version: 1, keys: {} };
}

/**
 * Save the context signing key store.
 */
export async function saveContextKeyStore(store: ContextKeyStore, baseDir?: string): Promise<void> {
  const filePath = resolveKeyStorePath(baseDir);
  const dir = path.dirname(filePath);

  await fs.promises.mkdir(dir, { recursive: true });

  const tmp = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const json = JSON.stringify(store, null, 2);

  try {
    await fs.promises.writeFile(tmp, json, { mode: 0o600, encoding: "utf-8" });
    await fs.promises.rename(tmp, filePath);
    await fs.promises.chmod(filePath, 0o600);
  } catch (err) {
    await fs.promises.rm(tmp, { force: true }).catch(() => undefined);
    throw err;
  }
}

/**
 * Get or create an active signing key pair.
 */
export async function getOrCreateActiveKeyPair(baseDir?: string): Promise<SessionContextKeyPair> {
  const store = loadContextKeyStore(baseDir);

  // Return existing active key if available
  if (store.activeKeyId && store.keys[store.activeKeyId]) {
    return store.keys[store.activeKeyId];
  }

  // Generate new key pair
  const keyPair = generateContextKeyPair();
  store.keys[keyPair.keyId] = keyPair;
  store.activeKeyId = keyPair.keyId;

  await saveContextKeyStore(store, baseDir);
  return keyPair;
}

/**
 * Get all trusted public keys for verification.
 */
export function getTrustedPublicKeys(baseDir?: string): Map<string, string> {
  const store = loadContextKeyStore(baseDir);
  const keys = new Map<string, string>();

  for (const [keyId, keyPair] of Object.entries(store.keys)) {
    keys.set(keyId, keyPair.publicKeyPem);
  }

  return keys;
}

/**
 * Create a signed session context for a transition.
 */
export async function createSignedContextForTransition(params: {
  sessionId: string;
  contextType: SessionContextType;
  agentId: string;
  parentSessionId?: string;
  parentContextType?: SessionContextType;
  ttlMs?: number;
  baseDir?: string;
}): Promise<SignedSessionContext> {
  const keyPair = await getOrCreateActiveKeyPair(params.baseDir);
  const now = Date.now();

  const context: SessionContext = {
    sessionId: params.sessionId,
    contextType: params.contextType,
    agentId: params.agentId,
    createdAtMs: now,
    parentSessionId: params.parentSessionId,
    parentContextType: params.parentContextType,
    expiresAtMs: now + (params.ttlMs ?? DEFAULT_CONTEXT_TTL_MS),
  };

  return signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);
}

/**
 * Validate a context transition request.
 */
export function validateTransitionRequest(params: {
  fromContext: SessionContextType;
  toContext: SessionContextType;
  sessionId: string;
  signedContext?: SignedSessionContext;
  config?: OpenClawConfig;
  baseDir?: string;
}): { valid: boolean; reason?: string } {
  const trustedKeys = getTrustedPublicKeys(params.baseDir);

  const transition: SessionContextTransition = {
    from: params.fromContext,
    to: params.toContext,
    sessionId: params.sessionId,
    timestamp: Date.now(),
    signedContext: params.signedContext,
  };

  return validateContextTransition(transition, trustedKeys, params.config);
}

/**
 * Create a context token string for transport.
 * Format: base64url(JSON.stringify(signedContext))
 */
export function encodeSignedContext(signed: SignedSessionContext): string {
  return base64UrlEncode(Buffer.from(JSON.stringify(signed), "utf8"));
}

/**
 * Decode a context token string.
 */
export function decodeSignedContext(encoded: string): SignedSessionContext | null {
  try {
    const json = base64UrlDecode(encoded).toString("utf8");
    const parsed = JSON.parse(json) as SignedSessionContext;
    if (
      parsed?.context?.sessionId &&
      parsed?.context?.contextType &&
      parsed?.signature &&
      parsed?.signerKeyId
    ) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

export {
  ALLOWED_TRANSITIONS,
  DEFAULT_CONTEXT_TTL_MS,
  CONTEXT_SIGNATURE_VERSION,
  computeKeyId,
};
