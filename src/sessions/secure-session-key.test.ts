import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
  loadSecureSessionMapping,
  saveSecureSessionMapping,
  clearSecureSessionCache,
  type SecureSessionMappingFile,
} from "./secure-session-key.js";

describe("secure-session-key", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "secure-session-test-"));
    clearSecureSessionCache();
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    clearSecureSessionCache();
  });

  describe("generateSecureToken", () => {
    it("generates a 64-character hex string by default", () => {
      const token = generateSecureToken();
      expect(token).toHaveLength(64);
      expect(token).toMatch(/^[a-f0-9]+$/);
    });

    it("generates tokens of correct length for different byte sizes", () => {
      expect(generateSecureToken(16)).toHaveLength(32);
      expect(generateSecureToken(24)).toHaveLength(48);
      expect(generateSecureToken(32)).toHaveLength(64);
      expect(generateSecureToken(64)).toHaveLength(128);
    });

    it("generates unique tokens", () => {
      const tokens = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        tokens.add(generateSecureToken());
      }
      expect(tokens.size).toBe(1000);
    });

    it("generates cryptographically random tokens", () => {
      // Statistical test: check byte distribution
      const samples = 1000;
      const byteCounts = new Array(256).fill(0);

      for (let i = 0; i < samples; i++) {
        const token = generateSecureToken(32);
        const bytes = Buffer.from(token, "hex");
        for (const byte of bytes) {
          byteCounts[byte]++;
        }
      }

      // Each byte value should appear roughly equally
      const expected = (samples * 32) / 256;
      const tolerance = expected * 0.5; // Allow 50% deviation

      for (const count of byteCounts) {
        // With 1000 samples * 32 bytes = 32000 bytes total
        // Expected per byte value: 32000/256 = 125
        // This test verifies reasonable distribution
        expect(count).toBeGreaterThan(expected - tolerance);
        expect(count).toBeLessThan(expected + tolerance);
      }
    });
  });

  describe("isValidSecureToken", () => {
    it("accepts valid 64-char hex tokens", () => {
      expect(isValidSecureToken(generateSecureToken())).toBe(true);
      expect(isValidSecureToken("a".repeat(64))).toBe(true);
      expect(isValidSecureToken("0123456789abcdef".repeat(4))).toBe(true);
    });

    it("rejects invalid tokens", () => {
      expect(isValidSecureToken(null)).toBe(false);
      expect(isValidSecureToken(undefined)).toBe(false);
      expect(isValidSecureToken("")).toBe(false);
      expect(isValidSecureToken("a".repeat(63))).toBe(false); // Too short
      expect(isValidSecureToken("a".repeat(65))).toBe(false); // Too long
      expect(isValidSecureToken("g".repeat(64))).toBe(false); // Invalid hex
      expect(isValidSecureToken("agent:main:main")).toBe(false); // Legacy format
    });
  });

  describe("compareTokens", () => {
    it("returns true for identical tokens", () => {
      const token = generateSecureToken();
      expect(compareTokens(token, token)).toBe(true);
    });

    it("returns false for different tokens", () => {
      const token1 = generateSecureToken();
      const token2 = generateSecureToken();
      expect(compareTokens(token1, token2)).toBe(false);
    });

    it("returns false for null/undefined", () => {
      const token = generateSecureToken();
      expect(compareTokens(token, null)).toBe(false);
      expect(compareTokens(null, token)).toBe(false);
      expect(compareTokens(null, null)).toBe(false);
      expect(compareTokens(undefined, undefined)).toBe(false);
    });

    it("returns false for different lengths", () => {
      expect(compareTokens("abc", "abcd")).toBe(false);
    });

    it("is timing-safe", () => {
      // This is a basic sanity check - true timing safety requires statistical analysis
      const token = generateSecureToken();
      const almostSame = token.slice(0, -1) + (token[63] === "a" ? "b" : "a");

      // Both should return false but take similar time
      expect(compareTokens(token, almostSame)).toBe(false);
      expect(compareTokens(token, generateSecureToken())).toBe(false);
    });
  });

  describe("hashTokenForLog", () => {
    it("returns a 12-character prefix of SHA256 hash", () => {
      const token = generateSecureToken();
      const hash = hashTokenForLog(token);
      expect(hash).toHaveLength(12);
      expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it("returns consistent hashes for same token", () => {
      const token = generateSecureToken();
      expect(hashTokenForLog(token)).toBe(hashTokenForLog(token));
    });

    it("returns different hashes for different tokens", () => {
      const token1 = generateSecureToken();
      const token2 = generateSecureToken();
      expect(hashTokenForLog(token1)).not.toBe(hashTokenForLog(token2));
    });
  });

  describe("createSecureSession", () => {
    it("creates a session with token and metadata", () => {
      const entry = createSecureSession({
        agentId: "main",
        legacyKey: "agent:main:main",
        channel: "telegram",
      });

      expect(isValidSecureToken(entry.token)).toBe(true);
      expect(entry.metadata.agentId).toBe("main");
      expect(entry.metadata.legacyKey).toBe("agent:main:main");
      expect(entry.metadata.channel).toBe("telegram");
      expect(entry.metadata.createdAtMs).toBeLessThanOrEqual(Date.now());
    });

    it("sets expiration based on TTL", () => {
      const entry = createSecureSession({
        agentId: "main",
        config: { enabled: true, ttlMs: 3600000 }, // 1 hour
      });

      expect(entry.metadata.expiresAtMs).toBeDefined();
      const expectedExpiry = entry.metadata.createdAtMs + 3600000;
      expect(entry.metadata.expiresAtMs).toBe(expectedExpiry);
    });

    it("does not set expiration when TTL is 0", () => {
      const entry = createSecureSession({
        agentId: "main",
        config: { enabled: true, ttlMs: 0 },
      });

      expect(entry.metadata.expiresAtMs).toBeUndefined();
    });
  });

  describe("session persistence", () => {
    it("registers and validates a session", async () => {
      const entry = createSecureSession({
        agentId: "main",
        legacyKey: "agent:main:test",
      });

      await registerSecureSession(entry, testDir);

      const metadata = validateSecureSession(entry.token, testDir);
      expect(metadata).not.toBeNull();
      expect(metadata?.agentId).toBe("main");
      expect(metadata?.legacyKey).toBe("agent:main:test");
    });

    it("looks up token by legacy key", async () => {
      const entry = createSecureSession({
        agentId: "main",
        legacyKey: "agent:main:legacy-lookup",
      });

      await registerSecureSession(entry, testDir);

      const token = lookupTokenByLegacyKey("agent:main:legacy-lookup", testDir);
      expect(token).toBe(entry.token);
    });

    it("returns null for unknown tokens", () => {
      const metadata = validateSecureSession(generateSecureToken(), testDir);
      expect(metadata).toBeNull();
    });

    it("returns null for unknown legacy keys", () => {
      const token = lookupTokenByLegacyKey("agent:main:nonexistent", testDir);
      expect(token).toBeNull();
    });
  });

  describe("session expiration", () => {
    it("rejects expired sessions", async () => {
      const entry = createSecureSession({
        agentId: "main",
        config: { enabled: true, ttlMs: 1 }, // Expire immediately
      });

      await registerSecureSession(entry, testDir);

      // Wait for expiration
      await new Promise((r) => setTimeout(r, 10));

      const metadata = validateSecureSession(entry.token, testDir);
      expect(metadata).toBeNull();
    });

    it("prunes expired sessions", async () => {
      // Create expired session
      const mapping: SecureSessionMappingFile = {
        version: 1,
        tokenToMetadata: {
          [generateSecureToken()]: {
            agentId: "main",
            legacyKey: "agent:main:expired",
            createdAtMs: Date.now() - 100000,
            expiresAtMs: Date.now() - 1000, // Expired
          },
          [generateSecureToken()]: {
            agentId: "main",
            legacyKey: "agent:main:valid",
            createdAtMs: Date.now(),
            expiresAtMs: Date.now() + 100000, // Not expired
          },
        },
        legacyKeyToToken: {},
      };

      await saveSecureSessionMapping(mapping, testDir);
      clearSecureSessionCache();

      const pruned = await pruneExpiredSessions(testDir);
      expect(pruned).toBe(1);

      const reloaded = loadSecureSessionMapping(testDir);
      expect(Object.keys(reloaded.tokenToMetadata)).toHaveLength(1);
    });
  });

  describe("session rotation", () => {
    it("rotates a session token", async () => {
      const entry = createSecureSession({
        agentId: "main",
        legacyKey: "agent:main:rotate",
      });

      await registerSecureSession(entry, testDir);

      const rotated = await rotateSecureSession(entry.token, {}, testDir);

      expect(rotated).not.toBeNull();
      expect(rotated!.token).not.toBe(entry.token);
      expect(rotated!.metadata.agentId).toBe("main");
      expect(rotated!.metadata.previousToken).toBe(entry.token);
      expect(rotated!.metadata.rotatedAtMs).toBeDefined();
    });

    it("keeps old token valid during grace period", async () => {
      const entry = createSecureSession({
        agentId: "main",
        legacyKey: "agent:main:grace",
      });

      await registerSecureSession(entry, testDir);

      const rotated = await rotateSecureSession(
        entry.token,
        { rotationGraceMs: 60000 }, // 1 minute grace
        testDir,
      );

      expect(rotated).not.toBeNull();

      // Old token should still work during grace period
      clearSecureSessionCache();
      const oldMetadata = validateSecureSession(entry.token, testDir);
      expect(oldMetadata).not.toBeNull();
    });

    it("updates legacy key mapping on rotation", async () => {
      const entry = createSecureSession({
        agentId: "main",
        legacyKey: "agent:main:legacy-rotate",
      });

      await registerSecureSession(entry, testDir);

      const rotated = await rotateSecureSession(entry.token, {}, testDir);

      clearSecureSessionCache();
      const token = lookupTokenByLegacyKey("agent:main:legacy-rotate", testDir);
      expect(token).toBe(rotated!.token);
    });

    it("returns null for unknown token rotation", async () => {
      const result = await rotateSecureSession(generateSecureToken(), {}, testDir);
      expect(result).toBeNull();
    });

    it("identifies sessions needing rotation", async () => {
      const oldToken = generateSecureToken();
      const newToken = generateSecureToken();

      const mapping: SecureSessionMappingFile = {
        version: 1,
        tokenToMetadata: {
          [oldToken]: {
            agentId: "main",
            legacyKey: "agent:main:old",
            createdAtMs: Date.now() - 100000, // Created long ago
          },
          [newToken]: {
            agentId: "main",
            legacyKey: "agent:main:new",
            createdAtMs: Date.now(), // Just created
          },
        },
        legacyKeyToToken: {},
      };

      await saveSecureSessionMapping(mapping, testDir);
      clearSecureSessionCache();

      const needsRotation = getSessionsNeedingRotation(
        { rotationEnabled: true, rotationIntervalMs: 1000 },
        testDir,
      );

      expect(needsRotation).toHaveLength(1);
      expect(needsRotation[0].token).toBe(oldToken);
    });
  });

  describe("session revocation", () => {
    it("revokes a session", async () => {
      const entry = createSecureSession({
        agentId: "main",
        legacyKey: "agent:main:revoke",
      });

      await registerSecureSession(entry, testDir);

      const revoked = await revokeSecureSession(entry.token, testDir);
      expect(revoked).toBe(true);

      const metadata = validateSecureSession(entry.token, testDir);
      expect(metadata).toBeNull();

      const token = lookupTokenByLegacyKey("agent:main:revoke", testDir);
      expect(token).toBeNull();
    });

    it("returns false for unknown token revocation", async () => {
      const result = await revokeSecureSession(generateSecureToken(), testDir);
      expect(result).toBe(false);
    });
  });

  describe("file permissions", () => {
    it("creates mapping file with 0600 permissions", async () => {
      const entry = createSecureSession({ agentId: "main" });
      await registerSecureSession(entry, testDir);

      const mappingPath = path.join(testDir, "sessions", "secure-mapping.json");
      const stats = fs.statSync(mappingPath);

      // Check owner-only read/write (0600 = 33216 in decimal with file type bits)
      expect(stats.mode & 0o777).toBe(0o600);
    });
  });

  describe("concurrent access", () => {
    it("handles concurrent session creation", async () => {
      const promises = Array.from({ length: 10 }, (_, i) =>
        registerSecureSession(
          createSecureSession({
            agentId: "main",
            legacyKey: `agent:main:concurrent-${i}`,
          }),
          testDir,
        ),
      );

      await Promise.all(promises);

      clearSecureSessionCache();
      const mapping = loadSecureSessionMapping(testDir);
      expect(Object.keys(mapping.tokenToMetadata)).toHaveLength(10);
    });
  });
});
