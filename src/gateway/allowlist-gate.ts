/**
 * Centralized inbound allowlist gate.
 *
 * Background (MT-009): each channel plugin used to perform its own allowlist
 * read + normalization at preflight time. That meant divergent normalization
 * rules and a TOCTOU window between the gate decision and any later access
 * checks (the on-disk allowlist could be edited between the two reads). This
 * module centralizes both concerns:
 *
 *   1. Sender id normalization happens exactly once via the per-channel
 *      pairing adapter, immediately on ingestion.
 *   2. The allowlist is read once into a frozen snapshot which is propagated
 *      through the inbound message context. Downstream code must consult the
 *      snapshot — it must not call `readChannelAllowFromStore()` again.
 */

import {
  type ChannelAllowFromSnapshot,
  type ImmutableSenderIdentity,
  type PairingChannel,
  normalizeAndImmutalizeSenderId,
  readChannelAllowFromStoreWithVersion,
} from "../pairing/pairing-store.js";

export type AllowlistGateInput = Readonly<{
  channel: PairingChannel;
  /** Raw id from the inbound payload; gate normalizes via the channel adapter. */
  rawSenderId: string | number;
  /** Caller-supplied entries (e.g. config-resolved allowFrom) merged with store. */
  overrideAllowFrom?: readonly string[];
  env?: NodeJS.ProcessEnv;
}>;

export type AllowlistGateResult = Readonly<{
  allowed: boolean;
  identity: ImmutableSenderIdentity;
  snapshot: ChannelAllowFromSnapshot;
  /** Convenience copies for callers that don't want to destructure twice. */
  normalizedSenderId: string;
  version: number;
}>;

function normalizeOverrideEntries(
  channel: PairingChannel,
  override: readonly string[] | undefined,
): readonly string[] {
  if (!override || override.length === 0) {
    return [];
  }
  // Re-use the same normalization pipeline as the store so override entries are
  // compared apples-to-apples with stored ones.
  return override
    .map((value) => {
      const id = normalizeAndImmutalizeSenderId(channel, value);
      return id.normalizedSenderId;
    })
    .filter(Boolean);
}

/**
 * Read the allowlist snapshot, normalize the sender, and decide admission.
 *
 * Channels with richer matching semantics (Discord id/name/tag, Slack mentions)
 * should still call this gate to obtain the snapshot, then run their channel
 * matcher against `snapshot.entries` instead of re-reading the store. The
 * `allowed` flag here is the simple-equality decision and is exactly what the
 * majority of channels (Telegram, LINE, WhatsApp, Signal, iMessage) need.
 */
export async function checkAllowlistAndSnapshot(
  input: AllowlistGateInput,
): Promise<AllowlistGateResult> {
  const identity = normalizeAndImmutalizeSenderId(input.channel, input.rawSenderId);
  const snapshot = await readChannelAllowFromStoreWithVersion(input.channel, input.env);
  const overrideEntries = normalizeOverrideEntries(input.channel, input.overrideAllowFrom);

  const candidate = identity.normalizedSenderId;
  const matchInStore = Boolean(candidate) && snapshot.entries.some((entry) => entry === candidate);
  const matchInOverride =
    Boolean(candidate) && overrideEntries.some((entry) => entry === candidate);

  return Object.freeze({
    allowed: matchInStore || matchInOverride,
    identity,
    snapshot,
    normalizedSenderId: identity.normalizedSenderId,
    version: snapshot.version,
  });
}

/**
 * Inbound message context shape. Channel preflights populate the gate fields
 * once at the top of processing and downstream consumers must read from this
 * object — not from the store directly. Carrying the snapshot prevents TOCTOU
 * exploitation where the on-disk allowlist changes mid-flight.
 */
export type InboundMessageGateContext = Readonly<{
  channel: PairingChannel;
  normalizedSenderId: string;
  rawSenderId: string;
  allowlistSnapshot: ChannelAllowFromSnapshot;
}>;

export function buildGateContext(result: AllowlistGateResult): InboundMessageGateContext {
  return Object.freeze({
    channel: result.identity.channel,
    normalizedSenderId: result.identity.normalizedSenderId,
    rawSenderId: result.identity.rawSenderId,
    allowlistSnapshot: result.snapshot,
  });
}

/**
 * Detects allowlist reloads between two snapshots. Channel code may compare a
 * stored gate context's version against a freshly-read store; a mismatch means
 * the file changed since admission. Default behavior is to log and proceed
 * with the original snapshot (the message was admitted under those rules);
 * `strict` mode rejects so callers can opt into refusing stale decisions.
 */
export function isAllowlistVersionStale(contextVersion: number, liveVersion: number): boolean {
  return contextVersion !== liveVersion;
}
