import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { ChannelPlugin } from "../channels/plugins/types.js";
import { resolveOAuthDir } from "../config/paths.js";
import { setActivePluginRegistry } from "../plugins/runtime.js";
import { createTestRegistry } from "../test-utils/channel-plugins.js";
import {
  buildGateContext,
  checkAllowlistAndSnapshot,
  isAllowlistVersionStale,
} from "./allowlist-gate.js";

async function withTempStateDir<T>(fn: (stateDir: string) => Promise<T>) {
  const previous = process.env.OPENCLAW_STATE_DIR;
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-gate-"));
  process.env.OPENCLAW_STATE_DIR = dir;
  try {
    return await fn(dir);
  } finally {
    if (previous === undefined) {
      delete process.env.OPENCLAW_STATE_DIR;
    } else {
      process.env.OPENCLAW_STATE_DIR = previous;
    }
    await fs.rm(dir, { recursive: true, force: true });
  }
}

function makeTelegramPlugin(): ChannelPlugin {
  return {
    id: "telegram",
    meta: {
      id: "telegram",
      label: "Telegram",
      selectionLabel: "Telegram",
      docsPath: "/channels/telegram",
      blurb: "test",
    },
    capabilities: { chatTypes: ["direct"] },
    config: {
      listAccountIds: () => [],
      resolveAccount: () => ({}),
    },
    pairing: {
      idLabel: "telegramUserId",
      normalizeAllowEntry: (entry: string) => {
        let next = entry.trim();
        if (next.startsWith("telegram:")) {
          next = next.slice("telegram:".length);
        }
        if (next.startsWith("tg:")) {
          next = next.slice("tg:".length);
        }
        return next.toLowerCase();
      },
    },
  };
}

function installRegistry() {
  setActivePluginRegistry(
    createTestRegistry([{ pluginId: "telegram", plugin: makeTelegramPlugin(), source: "test" }]),
  );
}

async function writeAllowlist(stateDir: string, channel: string, entries: string[]) {
  const oauthDir = resolveOAuthDir(process.env, stateDir);
  await fs.mkdir(oauthDir, { recursive: true });
  const filePath = path.join(oauthDir, `${channel}-allowFrom.json`);
  await fs.writeFile(filePath, JSON.stringify({ version: 1, allowFrom: entries }), "utf8");
  return filePath;
}

describe("checkAllowlistAndSnapshot", () => {
  it("admits a sender whose normalized id is in the store snapshot", async () => {
    installRegistry();
    await withTempStateDir(async (stateDir) => {
      await writeAllowlist(stateDir, "telegram", ["telegram:12345"]);
      const result = await checkAllowlistAndSnapshot({
        channel: "telegram",
        rawSenderId: "tg:12345",
      });
      expect(result.allowed).toBe(true);
      expect(result.normalizedSenderId).toBe("12345");
      expect([...result.snapshot.entries]).toEqual(["12345"]);
      expect(result.version).toBeGreaterThan(0);
    });
  });

  it("rejects a sender that is not on the allowlist", async () => {
    installRegistry();
    await withTempStateDir(async (stateDir) => {
      await writeAllowlist(stateDir, "telegram", ["1"]);
      const result = await checkAllowlistAndSnapshot({
        channel: "telegram",
        rawSenderId: "telegram:2",
      });
      expect(result.allowed).toBe(false);
      expect(result.normalizedSenderId).toBe("2");
    });
  });

  it("admits via override allowFrom even when the store is empty", async () => {
    installRegistry();
    await withTempStateDir(async () => {
      const result = await checkAllowlistAndSnapshot({
        channel: "telegram",
        rawSenderId: "9",
        overrideAllowFrom: ["tg:9"],
      });
      expect(result.allowed).toBe(true);
      expect(result.snapshot.entries).toEqual([]);
      expect(result.version).toBe(0);
    });
  });

  it("returns a frozen result and snapshot", async () => {
    installRegistry();
    await withTempStateDir(async (stateDir) => {
      await writeAllowlist(stateDir, "telegram", ["1"]);
      const result = await checkAllowlistAndSnapshot({
        channel: "telegram",
        rawSenderId: "1",
      });
      expect(Object.isFrozen(result)).toBe(true);
      expect(Object.isFrozen(result.snapshot)).toBe(true);
      expect(Object.isFrozen(result.snapshot.entries)).toBe(true);
      expect(Object.isFrozen(result.identity)).toBe(true);
    });
  });

  it("does not match an empty normalized sender id", async () => {
    installRegistry();
    await withTempStateDir(async (stateDir) => {
      // The wildcard "*" normalizes to empty string in the store; an empty
      // sender must not be considered a match against any wildcard residue.
      await writeAllowlist(stateDir, "telegram", ["*"]);
      const result = await checkAllowlistAndSnapshot({
        channel: "telegram",
        rawSenderId: "",
      });
      expect(result.allowed).toBe(false);
      expect(result.normalizedSenderId).toBe("");
    });
  });
});

describe("buildGateContext", () => {
  it("produces a frozen context with snapshot and ids", async () => {
    installRegistry();
    await withTempStateDir(async (stateDir) => {
      await writeAllowlist(stateDir, "telegram", ["7"]);
      const result = await checkAllowlistAndSnapshot({
        channel: "telegram",
        rawSenderId: "telegram:7",
      });
      const ctx = buildGateContext(result);
      expect(ctx.channel).toBe("telegram");
      expect(ctx.normalizedSenderId).toBe("7");
      expect(ctx.rawSenderId).toBe("telegram:7");
      expect([...ctx.allowlistSnapshot.entries]).toEqual(["7"]);
      expect(Object.isFrozen(ctx)).toBe(true);
    });
  });
});

describe("isAllowlistVersionStale", () => {
  it("flags mismatched versions as stale", () => {
    expect(isAllowlistVersionStale(100, 100)).toBe(false);
    expect(isAllowlistVersionStale(100, 200)).toBe(true);
    expect(isAllowlistVersionStale(0, 100)).toBe(true);
  });
});
