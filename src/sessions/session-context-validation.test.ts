import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  inferContextType,
  isEscalation,
  isDeescalation,
  requestContextTransition,
  validateContextToken,
  canPerformAction,
  getAllowedTransitionsFrom,
  type SessionContextState,
} from "./session-context-validation.js";
import {
  createSignedContextForTransition,
  encodeSignedContext,
  getOrCreateActiveKeyPair,
} from "./session-context-signing.js";

describe("session-context-validation", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), "context-validation-test-"));
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  describe("inferContextType", () => {
    it("infers sandbox from execHost", () => {
      expect(inferContextType({ execHost: "sandbox" })).toBe("sandbox");
    });

    it("infers subagent from spawnedBy", () => {
      expect(inferContextType({ spawnedBy: "parent-session" })).toBe("subagent");
    });

    it("infers elevated from elevatedLevel", () => {
      expect(inferContextType({ elevatedLevel: "full" })).toBe("elevated");
    });

    it("returns main for normal sessions", () => {
      expect(inferContextType({})).toBe("main");
      expect(inferContextType({ elevatedLevel: "none" })).toBe("main");
    });

    it("prioritizes sandbox over other flags", () => {
      expect(
        inferContextType({
          execHost: "sandbox",
          spawnedBy: "parent",
          elevatedLevel: "full",
        }),
      ).toBe("sandbox");
    });
  });

  describe("isEscalation / isDeescalation", () => {
    it("identifies escalation from sandbox to main", () => {
      expect(isEscalation("sandbox", "main")).toBe(true);
      expect(isDeescalation("sandbox", "main")).toBe(false);
    });

    it("identifies de-escalation from elevated to main", () => {
      expect(isDeescalation("elevated", "main")).toBe(true);
      expect(isEscalation("elevated", "main")).toBe(false);
    });

    it("identifies escalation from main to elevated", () => {
      expect(isEscalation("main", "elevated")).toBe(true);
      expect(isDeescalation("main", "elevated")).toBe(false);
    });

    it("same context is neither escalation nor de-escalation", () => {
      expect(isEscalation("main", "main")).toBe(false);
      expect(isDeescalation("main", "main")).toBe(false);
    });
  });

  describe("requestContextTransition", () => {
    const makeState = (contextType: "main" | "sandbox" | "subagent" | "elevated"): SessionContextState => ({
      sessionId: "session-123",
      sessionKey: "agent:main:test",
      contextType,
      agentId: "main",
    });

    it("allows transition to same context", async () => {
      const result = await requestContextTransition({
        currentState: makeState("main"),
        targetContext: "main",
        baseDir: testDir,
      });

      expect(result.allowed).toBe(true);
      expect(result.reason).toBe("No transition needed");
    });

    it("allows de-escalation without signature by default", async () => {
      const result = await requestContextTransition({
        currentState: makeState("elevated"),
        targetContext: "main",
        baseDir: testDir,
        validationConfig: { allowUnsignedDeescalation: true, requireSignatures: true, contextTtlMs: 300000 },
      });

      // Note: elevated -> main is de-escalation but still structurally disallowed
      // because ALLOWED_TRANSITIONS[elevated] only contains "main"
      // Let's check the actual behavior
      expect(result.allowed).toBe(true);
    });

    it("blocks disallowed transitions", async () => {
      const result = await requestContextTransition({
        currentState: makeState("sandbox"),
        targetContext: "main",
        baseDir: testDir,
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("not allowed");
    });

    it("creates signed context for allowed transitions", async () => {
      const result = await requestContextTransition({
        currentState: makeState("main"),
        targetContext: "sandbox",
        baseDir: testDir,
        validationConfig: { requireSignatures: true, contextTtlMs: 300000, allowUnsignedDeescalation: true },
      });

      expect(result.allowed).toBe(true);
      expect(result.contextToken).toBeDefined();
      expect(result.newState?.contextType).toBe("sandbox");
      expect(result.newState?.signedContext).toBeDefined();
    });

    it("tracks parent context info", async () => {
      const result = await requestContextTransition({
        currentState: makeState("main"),
        targetContext: "sandbox",
        baseDir: testDir,
        validationConfig: { requireSignatures: true, contextTtlMs: 300000, allowUnsignedDeescalation: true },
      });

      expect(result.allowed).toBe(true);
      expect(result.newState?.parentContextType).toBe("main");
    });
  });

  describe("validateContextToken", () => {
    it("validates a valid context token", async () => {
      // Create a key first
      await getOrCreateActiveKeyPair(testDir);

      // Create signed context
      const signed = await createSignedContextForTransition({
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        baseDir: testDir,
      });

      const token = encodeSignedContext(signed);

      const result = validateContextToken({
        contextToken: token,
        expectedSessionId: "session-123",
        expectedContextType: "sandbox",
        baseDir: testDir,
      });

      expect(result.valid).toBe(true);
      expect(result.context).toBeDefined();
    });

    it("rejects invalid token format", () => {
      const result = validateContextToken({
        contextToken: "not-a-valid-token",
        expectedSessionId: "session-123",
        baseDir: testDir,
      });

      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Invalid context token format");
    });

    it("rejects session ID mismatch", async () => {
      await getOrCreateActiveKeyPair(testDir);

      const signed = await createSignedContextForTransition({
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        baseDir: testDir,
      });

      const token = encodeSignedContext(signed);

      const result = validateContextToken({
        contextToken: token,
        expectedSessionId: "different-session",
        baseDir: testDir,
      });

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Session ID mismatch");
    });

    it("rejects context type mismatch", async () => {
      await getOrCreateActiveKeyPair(testDir);

      const signed = await createSignedContextForTransition({
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        baseDir: testDir,
      });

      const token = encodeSignedContext(signed);

      const result = validateContextToken({
        contextToken: token,
        expectedSessionId: "session-123",
        expectedContextType: "main",
        baseDir: testDir,
      });

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Context type mismatch");
    });

    it("rejects expired token", async () => {
      await getOrCreateActiveKeyPair(testDir);

      // Create context that expires immediately
      const signed = await createSignedContextForTransition({
        sessionId: "session-123",
        contextType: "sandbox",
        agentId: "main",
        ttlMs: 1, // 1ms TTL
        baseDir: testDir,
      });

      const token = encodeSignedContext(signed);

      // Wait for expiration
      await new Promise((r) => setTimeout(r, 10));

      const result = validateContextToken({
        contextToken: token,
        expectedSessionId: "session-123",
        baseDir: testDir,
      });

      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Context token expired");
    });
  });

  describe("canPerformAction", () => {
    it("sandbox can only read", () => {
      expect(canPerformAction({ contextType: "sandbox", action: "read" })).toBe(true);
      expect(canPerformAction({ contextType: "sandbox", action: "write" })).toBe(false);
      expect(canPerformAction({ contextType: "sandbox", action: "execute" })).toBe(false);
      expect(canPerformAction({ contextType: "sandbox", action: "send" })).toBe(false);
      expect(canPerformAction({ contextType: "sandbox", action: "admin" })).toBe(false);
    });

    it("subagent can read and write", () => {
      expect(canPerformAction({ contextType: "subagent", action: "read" })).toBe(true);
      expect(canPerformAction({ contextType: "subagent", action: "write" })).toBe(true);
      expect(canPerformAction({ contextType: "subagent", action: "execute" })).toBe(false);
      expect(canPerformAction({ contextType: "subagent", action: "send" })).toBe(false);
    });

    it("main can read, write, execute, and send", () => {
      expect(canPerformAction({ contextType: "main", action: "read" })).toBe(true);
      expect(canPerformAction({ contextType: "main", action: "write" })).toBe(true);
      expect(canPerformAction({ contextType: "main", action: "execute" })).toBe(true);
      expect(canPerformAction({ contextType: "main", action: "send" })).toBe(true);
      expect(canPerformAction({ contextType: "main", action: "admin" })).toBe(false);
    });

    it("elevated can do everything including admin", () => {
      expect(canPerformAction({ contextType: "elevated", action: "read" })).toBe(true);
      expect(canPerformAction({ contextType: "elevated", action: "write" })).toBe(true);
      expect(canPerformAction({ contextType: "elevated", action: "execute" })).toBe(true);
      expect(canPerformAction({ contextType: "elevated", action: "send" })).toBe(true);
      expect(canPerformAction({ contextType: "elevated", action: "admin" })).toBe(true);
    });
  });

  describe("getAllowedTransitionsFrom", () => {
    it("returns allowed transitions for main", () => {
      const transitions = getAllowedTransitionsFrom("main");
      expect(transitions).toContain("sandbox");
      expect(transitions).toContain("subagent");
      expect(transitions).toContain("elevated");
    });

    it("returns empty array for sandbox", () => {
      const transitions = getAllowedTransitionsFrom("sandbox");
      expect(transitions).toHaveLength(0);
    });

    it("returns empty array for subagent", () => {
      const transitions = getAllowedTransitionsFrom("subagent");
      expect(transitions).toHaveLength(0);
    });

    it("returns main for elevated", () => {
      const transitions = getAllowedTransitionsFrom("elevated");
      expect(transitions).toContain("main");
    });
  });

  describe("security scenarios", () => {
    it("prevents sandbox session from escalating to main", async () => {
      const result = await requestContextTransition({
        currentState: {
          sessionId: "sandbox-session",
          sessionKey: "agent:main:sandbox",
          contextType: "sandbox",
          agentId: "main",
        },
        targetContext: "main",
        baseDir: testDir,
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("not allowed");
    });

    it("prevents sandbox session from escalating to elevated", async () => {
      const result = await requestContextTransition({
        currentState: {
          sessionId: "sandbox-session",
          sessionKey: "agent:main:sandbox",
          contextType: "sandbox",
          agentId: "main",
        },
        targetContext: "elevated",
        baseDir: testDir,
      });

      expect(result.allowed).toBe(false);
    });

    it("prevents subagent from escalating to main", async () => {
      const result = await requestContextTransition({
        currentState: {
          sessionId: "subagent-session",
          sessionKey: "agent:main:subagent:task",
          contextType: "subagent",
          agentId: "main",
        },
        targetContext: "main",
        baseDir: testDir,
      });

      expect(result.allowed).toBe(false);
    });

    it("allows main to create sandbox sessions", async () => {
      const result = await requestContextTransition({
        currentState: {
          sessionId: "main-session",
          sessionKey: "agent:main:main",
          contextType: "main",
          agentId: "main",
        },
        targetContext: "sandbox",
        baseDir: testDir,
      });

      expect(result.allowed).toBe(true);
      expect(result.newState?.contextType).toBe("sandbox");
    });
  });
});
