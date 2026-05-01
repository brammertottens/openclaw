import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ChannelPlugin } from "../channels/plugins/types.js";
import { resolveOAuthDir } from "../config/paths.js";
import { setActivePluginRegistry } from "../plugins/runtime.js";
import { createTestRegistry } from "../test-utils/channel-plugins.js";
import {
  normalizeAndImmutalizeSenderId,
  readChannelAllowFromStore,
  readChannelAllowFromStoreWithVersion,
} from "./pairing-store.js";

async function withTempStateDir<T>(fn: (stateDir: string) => Promise<T>) {
  const previous = process.env.OPENCLAW_STATE_DIR;
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-allowlist-"));
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

function makeChannelPlugin(
  id: ChannelPlugin["id"],
  normalizeAllowEntry?: (entry: string) => string,
): ChannelPlugin {
  return {
    id,
    meta: {
      id,
      label: String(id),
      selectionLabel: String(id),
      docsPath: `/channels/${id}`,
      blurb: "test",
    },
    capabilities: { chatTypes: ["direct"] },
    config: {
      listAccountIds: () => [],
      resolveAccount: () => ({}),
    },
    pairing: {
      idLabel: `${id}UserId`,
      normalizeAllowEntry,
    },
  };
}

function installPluginsWithPairing() {
  // Telegram-style normalizer: strip `telegram:` / `tg:` prefixes, lowercase.
  const telegram: ChannelPlugin = makeChannelPlugin("telegram", (entry) => {
    let next = entry.trim();
    if (next.startsWith("telegram:")) {
      next = next.slice("telegram:".length);
    }
    if (next.startsWith("tg:")) {
      next = next.slice("tg:".length);
    }
    return next.toLowerCase();
  });
  // Discord-style normalizer: strip `<@123>`, `discord:`, `user:` prefixes.
  const discord: ChannelPlugin = makeChannelPlugin("discord", (entry) => {
    let next = entry.trim();
    const mention = /^<@!?(\d+)>$/.exec(next);
    if (mention?.[1]) {
      return mention[1];
    }
    if (next.startsWith("discord:")) {
      next = next.slice("discord:".length);
    }
    if (next.startsWith("user:")) {
      next = next.slice("user:".length);
    }
    return next;
  });
  // No-op channel: no normalizeAllowEntry adapter — falls back to trim.
  const signal: ChannelPlugin = makeChannelPlugin("signal");

  setActivePluginRegistry(
    createTestRegistry([
      { pluginId: "telegram", plugin: telegram, source: "test" },
      { pluginId: "discord", plugin: discord, source: "test" },
      { pluginId: "signal", plugin: signal, source: "test" },
    ]),
  );
}

afterEach(() => {
  // The global setup beforeEach reinstalls the default registry on the next test.
});

describe("normalizeAndImmutalizeSenderId", () => {
  it("normalizes telegram ids consistently across prefix variants", () => {
    installPluginsWithPairing();
    const a = normalizeAndImmutalizeSenderId("telegram", "telegram:12345");
    const b = normalizeAndImmutalizeSenderId("telegram", "tg:12345");
    const c = normalizeAndImmutalizeSenderId("telegram", "12345");
    expect(a.normalizedSenderId).toBe("12345");
    expect(b.normalizedSenderId).toBe("12345");
    expect(c.normalizedSenderId).toBe("12345");
  });

  it("normalizes discord mentions, prefixes, and bare ids to the same id", () => {
    installPluginsWithPairing();
    const a = normalizeAndImmutalizeSenderId("discord", "<@123456>");
    const b = normalizeAndImmutalizeSenderId("discord", "<@!123456>");
    const c = normalizeAndImmutalizeSenderId("discord", "discord:123456");
    const d = normalizeAndImmutalizeSenderId("discord", "user:123456");
    const e = normalizeAndImmutalizeSenderId("discord", "123456");
    expect(a.normalizedSenderId).toBe("123456");
    expect(b.normalizedSenderId).toBe("123456");
    expect(c.normalizedSenderId).toBe("123456");
    expect(d.normalizedSenderId).toBe("123456");
    expect(e.normalizedSenderId).toBe("123456");
  });

  it("falls back to trimming when channel lacks a normalizer", () => {
    installPluginsWithPairing();
    const id = normalizeAndImmutalizeSenderId("signal", "  +15550001111  ");
    expect(id.normalizedSenderId).toBe("+15550001111");
  });

  it("returns a frozen identity object", () => {
    installPluginsWithPairing();
    const id = normalizeAndImmutalizeSenderId("telegram", "12345");
    expect(Object.isFrozen(id)).toBe(true);
    expect(() => {
      // @ts-expect-error - readonly
      id.normalizedSenderId = "tampered";
    }).toThrow();
  });

  it("preserves the raw sender id alongside the normalized form", () => {
    installPluginsWithPairing();
    const id = normalizeAndImmutalizeSenderId("telegram", "telegram:7");
    expect(id.rawSenderId).toBe("telegram:7");
    expect(id.normalizedSenderId).toBe("7");
  });
});

describe("readChannelAllowFromStoreWithVersion", () => {
  it("returns empty entries and version=0 when no file exists", async () => {
    installPluginsWithPairing();
    await withTempStateDir(async () => {
      const snapshot = await readChannelAllowFromStoreWithVersion("telegram");
      expect(snapshot.entries).toEqual([]);
      expect(snapshot.version).toBe(0);
      expect(Object.isFrozen(snapshot)).toBe(true);
      expect(Object.isFrozen(snapshot.entries)).toBe(true);
    });
  });

  it("returns normalized entries and a non-zero version when file exists", async () => {
    installPluginsWithPairing();
    await withTempStateDir(async (stateDir) => {
      const oauthDir = resolveOAuthDir(process.env, stateDir);
      await fs.mkdir(oauthDir, { recursive: true });
      const filePath = path.join(oauthDir, "telegram-allowFrom.json");
      await fs.writeFile(
        filePath,
        JSON.stringify({ version: 1, allowFrom: ["telegram:42", "tg:99", "100"] }),
        "utf8",
      );
      const snapshot = await readChannelAllowFromStoreWithVersion("telegram");
      expect([...snapshot.entries].toSorted()).toEqual(["100", "42", "99"]);
      expect(snapshot.version).toBeGreaterThan(0);
    });
  });

  it("bumps the version when the allowlist file is rewritten", async () => {
    installPluginsWithPairing();
    await withTempStateDir(async (stateDir) => {
      const oauthDir = resolveOAuthDir(process.env, stateDir);
      await fs.mkdir(oauthDir, { recursive: true });
      const filePath = path.join(oauthDir, "telegram-allowFrom.json");
      await fs.writeFile(filePath, JSON.stringify({ version: 1, allowFrom: ["1"] }), "utf8");
      const first = await readChannelAllowFromStoreWithVersion("telegram");
      // Force a measurable mtime change.
      await new Promise((resolve) => setTimeout(resolve, 20));
      await fs.writeFile(filePath, JSON.stringify({ version: 1, allowFrom: ["1", "2"] }), "utf8");
      const second = await readChannelAllowFromStoreWithVersion("telegram");
      expect(second.version).not.toBe(first.version);
      expect([...second.entries].toSorted()).toEqual(["1", "2"]);
    });
  });

  it("matches the unversioned read shape for the same file", async () => {
    installPluginsWithPairing();
    await withTempStateDir(async (stateDir) => {
      const oauthDir = resolveOAuthDir(process.env, stateDir);
      await fs.mkdir(oauthDir, { recursive: true });
      const filePath = path.join(oauthDir, "telegram-allowFrom.json");
      await fs.writeFile(
        filePath,
        JSON.stringify({ version: 1, allowFrom: ["tg:55", " 55 "] }),
        "utf8",
      );
      const versioned = await readChannelAllowFromStoreWithVersion("telegram");
      const flat = await readChannelAllowFromStore("telegram");
      expect([...versioned.entries].toSorted()).toEqual([...flat].toSorted());
    });
  });
});
