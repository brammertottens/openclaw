import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearSecureSessionCache } from "./secure-session-key.js";
import {
  createSecureSessionWithSecurity,
  validateSessionToken,
  rotateSessionToken,
  revokeSessionToken,
  getOrCreateSecureToken,
  runSessionSecurityMaintenance,
  isSessionRateLimited,
  clearRateLimitForTest,
  getSessionSecurityConfig,
} from "./session-security.js";
import type { OpenClawConfig } from "../config/config.js";

describe("session-security", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "session-security-test-"));
    clearSecureSessionCache();
    clearRateLimitForTest();
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    clearSecureSessionCache();
    clearRateLimitForTest();
  });

  const makeConfig = (
    security: Partial<NonNullable<NonNullable<OpenClawConfig["session"]>["security"]>> = {},
  ): OpenClawConfig =>
    ({
      session: {
        security: {
          enabled: true,
          ...security,
        },
      },
    }) as OpenClawConfig;

  describe("getSessionSecurityConfig", () => {
    it("returns defaults when no config provided", () => {
      const config = getSessionSecurityConfig();
      expect(config.enabled).toBe(false);
      expect(config.tokenBytes).toBe(32);
      expect(config.ttlMs).toBe(24 * 60 * 60 * 1000);
    });

    it("respects config values", () => {
      const config = getSessionSecurityConfig(
        makeConfig({
          tokenBytes: 48,
          ttlMs: 3600000,
          rotationEnabled: true,
        }),
      );

      expect(config.enabled).toBe(true);
      expect(config.tokenBytes).toBe(48);
      expect(config.ttlMs).toBe(3600000);
      expect(config.rotationEnabled).toBe(true);
    });
  });

  describe("createSecureSessionWithSecurity", () => {
    it("creates a secure session", async () => {
      const entry = await createSecureSessionWithSecurity({
        agentId: "main",
        legacyKey: "agent:main:test",
        channel: "telegram",
        config: makeConfig(),
        baseDir: testDir,
      });

      expect(entry).not.toBeNull();
      expect(entry!.token).toHaveLength(64);
      expect(entry!.metadata.agentId).toBe("main");
      expect(entry!.metadata.legacyKey).toBe("agent:main:test");
    });

    it("respects rate limiting", async () => {
      const config = makeConfig({ rateLimitPerMinute: 3 });

      // Create 3 sessions (should succeed)
      for (let i = 0; i < 3; i++) {
        const entry = await createSecureSessionWithSecurity({
          agentId: "main",
          legacyKey: `agent:main:test-${i}`,
          channel: "telegram",
          config,
          baseDir: testDir,
        });
        expect(entry).not.toBeNull();
      }

      // 4th session should be rate limited
      const entry = await createSecureSessionWithSecurity({
        agentId: "main",
        legacyKey: "agent:main:test-limited",
        channel: "telegram",
        config,
        baseDir: testDir,
      });
      expect(entry).toBeNull();
    });

    it("rate limits by agent and channel combination", async () => {
      const config = makeConfig({ rateLimitPerMinute: 2 });

      // Fill rate limit for main:telegram
      await createSecureSessionWithSecurity({
        agentId: "main",
        channel: "telegram",
        config,
        baseDir: testDir,
      });
      await createSecureSessionWithSecurity({
        agentId: "main",
        channel: "telegram",
        config,
        baseDir: testDir,
      });

      // main:telegram is rate limited
      const limited = await createSecureSessionWithSecurity({
        agentId: "main",
        channel: "telegram",
        config,
        baseDir: testDir,
      });
      expect(limited).toBeNull();

      // But main:discord should work
      const entry = await createSecureSessionWithSecurity({
        agentId: "main",
        channel: "discord",
        config,
        baseDir: testDir,
      });
      expect(entry).not.toBeNull();
    });
  });

  describe("validateSessionToken", () => {
    it("validates a registered token", async () => {
      const entry = await createSecureSessionWithSecurity({
        agentId: "main",
        legacyKey: "agent:main:validate",
        config: makeConfig(),
        baseDir: testDir,
      });

      const metadata = validateSessionToken(entry!.token, makeConfig(), testDir);
      expect(metadata).not.toBeNull();
      expect(metadata!.agentId).toBe("main");
    });

    it("returns null for unknown tokens", () => {
      const metadata = validateSessionToken("a".repeat(64), makeConfig(), testDir);
      expect(metadata).toBeNull();
    });
  });

  describe("rotateSessionToken", () => {
    it("rotates a session token", async () => {
      const entry = await createSecureSessionWithSecurity({
        agentId: "main",
        legacyKey: "agent:main:rotate",
        config: makeConfig(),
        baseDir: testDir,
      });

      const rotated = await rotateSessionToken(entry!.token, makeConfig(), testDir);

      expect(rotated).not.toBeNull();
      expect(rotated!.token).not.toBe(entry!.token);
      expect(rotated!.metadata.previousToken).toBe(entry!.token);
    });
  });

  describe("revokeSessionToken", () => {
    it("revokes a session token", async () => {
      const entry = await createSecureSessionWithSecurity({
        agentId: "main",
        legacyKey: "agent:main:revoke",
        config: makeConfig(),
        baseDir: testDir,
      });

      const revoked = await revokeSessionToken(entry!.token, makeConfig(), testDir);
      expect(revoked).toBe(true);

      const metadata = validateSessionToken(entry!.token, makeConfig(), testDir);
      expect(metadata).toBeNull();
    });
  });

  describe("getOrCreateSecureToken", () => {
    it("creates token when none exists", async () => {
      const token = await getOrCreateSecureToken({
        agentId: "main",
        legacyKey: "agent:main:create",
        config: makeConfig(),
        baseDir: testDir,
      });

      expect(token).not.toBeNull();
      expect(token).toHaveLength(64);
    });

    it("returns existing token for same legacy key", async () => {
      const token1 = await getOrCreateSecureToken({
        agentId: "main",
        legacyKey: "agent:main:existing",
        config: makeConfig(),
        baseDir: testDir,
      });

      clearSecureSessionCache();

      const token2 = await getOrCreateSecureToken({
        agentId: "main",
        legacyKey: "agent:main:existing",
        config: makeConfig(),
        baseDir: testDir,
      });

      expect(token1).toBe(token2);
    });

    it("returns null when security is disabled", async () => {
      const token = await getOrCreateSecureToken({
        agentId: "main",
        legacyKey: "agent:main:disabled",
        config: makeConfig({ enabled: false }),
        baseDir: testDir,
      });

      expect(token).toBeNull();
    });
  });

  describe("runSessionSecurityMaintenance", () => {
    it("prunes expired sessions", async () => {
      const config = makeConfig({ ttlMs: 1 }); // Expire immediately

      await createSecureSessionWithSecurity({
        agentId: "main",
        legacyKey: "agent:main:expire",
        config,
        baseDir: testDir,
      });

      // Wait for expiration
      await new Promise((r) => setTimeout(r, 10));

      const result = await runSessionSecurityMaintenance(config, testDir);
      expect(result.pruned).toBe(1);
    });

    it("rotates sessions when rotation is enabled", async () => {
      const config = makeConfig({
        rotationEnabled: true,
        rotationIntervalMs: 1, // Rotate immediately
      });

      const entry = await createSecureSessionWithSecurity({
        agentId: "main",
        legacyKey: "agent:main:auto-rotate",
        config,
        baseDir: testDir,
      });

      // Wait a bit
      await new Promise((r) => setTimeout(r, 10));

      const result = await runSessionSecurityMaintenance(config, testDir);
      expect(result.rotated).toBeGreaterThanOrEqual(1);
    });
  });

  describe("isSessionRateLimited", () => {
    it("returns not limited when no sessions created", () => {
      const result = isSessionRateLimited("test:key", makeConfig({ rateLimitPerMinute: 10 }));
      expect(result.limited).toBe(false);
      expect(result.count).toBe(0);
    });

    it("returns not limited when rate limit is disabled", () => {
      const result = isSessionRateLimited("test:key", makeConfig({ rateLimitPerMinute: 0 }));
      expect(result.limited).toBe(false);
    });
  });
});
