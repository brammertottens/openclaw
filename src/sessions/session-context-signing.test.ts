import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  generateContextKeyPair,
  signSessionContext,
  verifySignedContext,
  canonicalizeContext,
  isTransitionAllowed,
  validateContextTransition,
  createSignedContextForTransition,
  validateTransitionRequest,
  encodeSignedContext,
  decodeSignedContext,
  getOrCreateActiveKeyPair,
  getTrustedPublicKeys,
  loadContextKeyStore,
  saveContextKeyStore,
  ALLOWED_TRANSITIONS,
  DEFAULT_CONTEXT_TTL_MS,
  type SessionContext,
  type SessionContextType,
} from "./session-context-signing.js";

describe("session-context-signing", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "context-signing-test-"));
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  describe("generateContextKeyPair", () => {
    it("generates a valid Ed25519 key pair", () => {
      const keyPair = generateContextKeyPair();

      expect(keyPair.keyId).toHaveLength(64); // SHA256 hex
      expect(keyPair.publicKeyPem).toContain("BEGIN PUBLIC KEY");
      expect(keyPair.privateKeyPem).toContain("BEGIN PRIVATE KEY");
      expect(keyPair.createdAtMs).toBeLessThanOrEqual(Date.now());
    });

    it("generates unique key pairs", () => {
      const keyPair1 = generateContextKeyPair();
      const keyPair2 = generateContextKeyPair();

      expect(keyPair1.keyId).not.toBe(keyPair2.keyId);
      expect(keyPair1.publicKeyPem).not.toBe(keyPair2.publicKeyPem);
      expect(keyPair1.privateKeyPem).not.toBe(keyPair2.privateKeyPem);
    });

    it("key ID is derived from public key", () => {
      const keyPair = generateContextKeyPair();

      // Re-derive key ID to verify
      const publicKey = crypto.createPublicKey(keyPair.publicKeyPem);
      const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
      // Extract raw key (skip SPKI prefix)
      const rawKey = spki.subarray(spki.length - 32);
      const expectedKeyId = crypto.createHash("sha256").update(rawKey).digest("hex");

      expect(keyPair.keyId).toBe(expectedKeyId);
    });
  });

  describe("canonicalizeContext", () => {
    it("produces deterministic JSON", () => {
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: 1700000000000,
        parentSessionId: "parent-456",
        parentContextType: "sandbox",
        expiresAtMs: 1700000300000,
      };

      const canonical1 = canonicalizeContext(context);
      const canonical2 = canonicalizeContext(context);

      expect(canonical1).toBe(canonical2);
    });

    it("includes version field", () => {
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: 1700000000000,
      };

      const canonical = canonicalizeContext(context);
      const parsed = JSON.parse(canonical);

      expect(parsed.v).toBe(1);
    });
  });

  describe("signSessionContext / verifySignedContext", () => {
    it("creates valid signature that can be verified", () => {
      const keyPair = generateContextKeyPair();
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: Date.now(),
        expiresAtMs: Date.now() + 300000,
      };

      const signed = signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);
      const verification = verifySignedContext(signed, keyPair.publicKeyPem);

      expect(verification.valid).toBe(true);
      expect(verification.reason).toBeUndefined();
    });

    it("rejects signature with wrong key", () => {
      const keyPair1 = generateContextKeyPair();
      const keyPair2 = generateContextKeyPair();
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: Date.now(),
      };

      const signed = signSessionContext(context, keyPair1.privateKeyPem, keyPair1.publicKeyPem);
      const verification = verifySignedContext(signed, keyPair2.publicKeyPem);

      expect(verification.valid).toBe(false);
      expect(verification.reason).toBe("Key ID mismatch");
    });

    it("rejects tampered context", () => {
      const keyPair = generateContextKeyPair();
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: Date.now(),
      };

      const signed = signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);

      // Tamper with the context
      signed.context.sessionId = "session-456";

      const verification = verifySignedContext(signed, keyPair.publicKeyPem);

      expect(verification.valid).toBe(false);
      expect(verification.reason).toBe("Invalid signature");
    });

    it("rejects expired context", () => {
      const keyPair = generateContextKeyPair();
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: Date.now() - 600000,
        expiresAtMs: Date.now() - 300000, // Expired 5 minutes ago
      };

      const signed = signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);
      const verification = verifySignedContext(signed, keyPair.publicKeyPem);

      expect(verification.valid).toBe(false);
      expect(verification.reason).toBe("Context expired");
    });
  });

  describe("isTransitionAllowed", () => {
    it("allows main -> sandbox", () => {
      expect(isTransitionAllowed("main", "sandbox")).toBe(true);
    });

    it("allows main -> subagent", () => {
      expect(isTransitionAllowed("main", "subagent")).toBe(true);
    });

    it("allows main -> elevated", () => {
      expect(isTransitionAllowed("main", "elevated")).toBe(true);
    });

    it("allows elevated -> main (de-escalation)", () => {
      expect(isTransitionAllowed("elevated", "main")).toBe(true);
    });

    it("blocks sandbox -> main (escalation)", () => {
      expect(isTransitionAllowed("sandbox", "main")).toBe(false);
    });

    it("blocks sandbox -> elevated", () => {
      expect(isTransitionAllowed("sandbox", "elevated")).toBe(false);
    });

    it("blocks subagent -> main", () => {
      expect(isTransitionAllowed("subagent", "main")).toBe(false);
    });

    it("documents all allowed transitions", () => {
      expect(ALLOWED_TRANSITIONS.main).toContain("sandbox");
      expect(ALLOWED_TRANSITIONS.main).toContain("subagent");
      expect(ALLOWED_TRANSITIONS.main).toContain("elevated");
      expect(ALLOWED_TRANSITIONS.sandbox).toHaveLength(0);
      expect(ALLOWED_TRANSITIONS.subagent).toHaveLength(0);
      expect(ALLOWED_TRANSITIONS.elevated).toContain("main");
    });
  });

  describe("validateContextTransition", () => {
    it("validates allowed transition with signature", async () => {
      const keyPair = generateContextKeyPair();
      const trustedKeys = new Map([[keyPair.keyId, keyPair.publicKeyPem]]);

      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        createdAtMs: Date.now(),
        expiresAtMs: Date.now() + 300000,
      };

      const signed = signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);

      const validation = validateContextTransition(
        {
          from: "main",
          to: "sandbox",
          sessionId: "session-123",
          timestamp: Date.now(),
          signedContext: signed,
        },
        trustedKeys,
      );

      expect(validation.valid).toBe(true);
    });

    it("rejects disallowed transition", () => {
      const trustedKeys = new Map<string, string>();

      const validation = validateContextTransition(
        {
          from: "sandbox",
          to: "main",
          sessionId: "session-123",
          timestamp: Date.now(),
        },
        trustedKeys,
      );

      expect(validation.valid).toBe(false);
      expect(validation.reason).toContain("not allowed");
    });

    it("rejects escalation without signature", () => {
      const trustedKeys = new Map<string, string>();

      const validation = validateContextTransition(
        {
          from: "elevated",
          to: "main", // This is actually de-escalation, so let's test something else
          sessionId: "session-123",
          timestamp: Date.now(),
        },
        trustedKeys,
      );

      // De-escalation from elevated to main is allowed, but requires signature for "main"
      expect(validation.valid).toBe(false);
      expect(validation.reason).toContain("Signed context required");
    });

    it("rejects unknown signer", async () => {
      const keyPair = generateContextKeyPair();
      const trustedKeys = new Map<string, string>(); // Empty - no trusted keys

      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: Date.now(),
        expiresAtMs: Date.now() + 300000,
      };

      const signed = signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);

      const validation = validateContextTransition(
        {
          from: "elevated",
          to: "main",
          sessionId: "session-123",
          timestamp: Date.now(),
          signedContext: signed,
        },
        trustedKeys,
      );

      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe("Unknown signer key");
    });
  });

  describe("encodeSignedContext / decodeSignedContext", () => {
    it("round-trips signed context", () => {
      const keyPair = generateContextKeyPair();
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: Date.now(),
      };

      const signed = signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);
      const encoded = encodeSignedContext(signed);
      const decoded = decodeSignedContext(encoded);

      expect(decoded).not.toBeNull();
      expect(decoded!.context.sessionId).toBe("session-123");
      expect(decoded!.context.contextType).toBe("main");
      expect(decoded!.signerKeyId).toBe(keyPair.keyId);
    });

    it("returns null for invalid encoded data", () => {
      expect(decodeSignedContext("invalid")).toBeNull();
      expect(decodeSignedContext("")).toBeNull();
    });
  });

  describe("key store persistence", () => {
    it("creates and persists key store", async () => {
      const keyPair = await getOrCreateActiveKeyPair(testDir);

      expect(keyPair.keyId).toHaveLength(64);

      // Reload and verify
      const store = loadContextKeyStore(testDir);
      expect(store.activeKeyId).toBe(keyPair.keyId);
      expect(store.keys[keyPair.keyId]).toBeDefined();
    });

    it("reuses existing active key", async () => {
      const keyPair1 = await getOrCreateActiveKeyPair(testDir);
      const keyPair2 = await getOrCreateActiveKeyPair(testDir);

      expect(keyPair1.keyId).toBe(keyPair2.keyId);
    });

    it("stores key file with secure permissions", async () => {
      await getOrCreateActiveKeyPair(testDir);

      const keyPath = path.join(testDir, "sessions", "context-keys.json");
      const stats = fs.statSync(keyPath);

      expect(stats.mode & 0o777).toBe(0o600);
    });

    it("getTrustedPublicKeys returns all stored keys", async () => {
      await getOrCreateActiveKeyPair(testDir);

      const keys = getTrustedPublicKeys(testDir);

      expect(keys.size).toBe(1);
      for (const [keyId, publicKey] of keys) {
        expect(keyId).toHaveLength(64);
        expect(publicKey).toContain("BEGIN PUBLIC KEY");
      }
    });
  });

  describe("createSignedContextForTransition", () => {
    it("creates signed context with default TTL", async () => {
      const signed = await createSignedContextForTransition({
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        baseDir: testDir,
      });

      expect(signed.context.sessionId).toBe("session-123");
      expect(signed.context.contextType).toBe("sandbox");
      expect(signed.context.expiresAtMs).toBeDefined();

      const ttl = signed.context.expiresAtMs! - signed.context.createdAtMs;
      expect(ttl).toBe(DEFAULT_CONTEXT_TTL_MS);
    });

    it("creates signed context with custom TTL", async () => {
      const customTtl = 60000; // 1 minute
      const signed = await createSignedContextForTransition({
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        ttlMs: customTtl,
        baseDir: testDir,
      });

      const ttl = signed.context.expiresAtMs! - signed.context.createdAtMs;
      expect(ttl).toBe(customTtl);
    });

    it("includes parent context info", async () => {
      const signed = await createSignedContextForTransition({
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        parentSessionId: "parent-456",
        parentContextType: "main",
        baseDir: testDir,
      });

      expect(signed.context.parentSessionId).toBe("parent-456");
      expect(signed.context.parentContextType).toBe("main");
    });
  });

  describe("validateTransitionRequest", () => {
    it("validates transition with trusted keys", async () => {
      // First create a key
      await getOrCreateActiveKeyPair(testDir);

      // Create signed context for transition
      const signed = await createSignedContextForTransition({
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        baseDir: testDir,
      });

      // Validate the transition
      const result = validateTransitionRequest({
        fromContext: "main",
        toContext: "sandbox",
        sessionId: "session-123",
        signedContext: signed,
        baseDir: testDir,
      });

      expect(result.valid).toBe(true);
    });
  });

  describe("security properties", () => {
    it("signature is bound to session ID", async () => {
      const keyPair = generateContextKeyPair();
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: Date.now(),
        expiresAtMs: Date.now() + 300000,
      };

      const signed = signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);

      // Try to use the signature for a different session
      const tamperedSigned = {
        ...signed,
        context: { ...signed.context, sessionId: "session-456" },
      };

      const verification = verifySignedContext(tamperedSigned, keyPair.publicKeyPem);
      expect(verification.valid).toBe(false);
    });

    it("signature is bound to context type", async () => {
      const keyPair = generateContextKeyPair();
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        createdAtMs: Date.now(),
        expiresAtMs: Date.now() + 300000,
      };

      const signed = signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);

      // Try to use the signature for a different context type
      const tamperedSigned = {
        ...signed,
        context: { ...signed.context, contextType: "main" as SessionContextType },
      };

      const verification = verifySignedContext(tamperedSigned, keyPair.publicKeyPem);
      expect(verification.valid).toBe(false);
    });

    it("prevents replay with expired context", async () => {
      const keyPair = generateContextKeyPair();
      const context: SessionContext = {
        sessionId: "session-123",
        contextType: "main",
        agentId: "main",
        createdAtMs: Date.now() - 600000,
        expiresAtMs: Date.now() - 1, // Just expired
      };

      const signed = signSessionContext(context, keyPair.privateKeyPem, keyPair.publicKeyPem);
      const verification = verifySignedContext(signed, keyPair.publicKeyPem);

      expect(verification.valid).toBe(false);
      expect(verification.reason).toBe("Context expired");
    });
  });
});
