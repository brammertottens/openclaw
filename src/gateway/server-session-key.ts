import { loadConfig } from "../config/config.js";
import { loadSessionStore, resolveStorePath } from "../config/sessions.js";
import { getAgentRunContext, registerAgentRunContext } from "../infra/agent-events.js";
import { toAgentRequestSessionKey } from "../routing/session-key.js";
import {
  inferContextType,
  validateContextToken,
  type SessionContextType,
  type SessionContextState,
} from "../sessions/session-context-validation.js";

export function resolveSessionKeyForRun(runId: string) {
  const cached = getAgentRunContext(runId)?.sessionKey;
  if (cached) {
    return cached;
  }
  const cfg = loadConfig();
  const storePath = resolveStorePath(cfg.session?.store);
  const store = loadSessionStore(storePath);
  const found = Object.entries(store).find(([, entry]) => entry?.sessionId === runId);
  const storeKey = found?.[0];
  if (storeKey) {
    const sessionKey = toAgentRequestSessionKey(storeKey) ?? storeKey;
    registerAgentRunContext(runId, { sessionKey });
    return sessionKey;
  }
  return undefined;
}

/**
 * Resolve the session context type for a run.
 * Uses session entry metadata to determine if this is a sandbox, subagent, or main session.
 */
export function resolveSessionContextForRun(runId: string): SessionContextType | undefined {
  const cfg = loadConfig();
  const storePath = resolveStorePath(cfg.session?.store);
  const store = loadSessionStore(storePath);
  const found = Object.entries(store).find(([, entry]) => entry?.sessionId === runId);
  const entry = found?.[1];

  if (!entry) {
    return undefined;
  }

  return inferContextType({
    execHost: entry.execHost,
    spawnedBy: entry.spawnedBy,
    elevatedLevel: entry.elevatedLevel,
  });
}

/**
 * Validate a session context token for secure context transitions.
 * Returns the validated context state or null if invalid.
 */
export function validateSessionContextToken(params: {
  runId: string;
  contextToken: string;
  expectedContextType?: SessionContextType;
}): SessionContextState | null {
  const { runId, contextToken, expectedContextType } = params;
  const cfg = loadConfig();

  const validation = validateContextToken({
    contextToken,
    expectedSessionId: runId,
    expectedContextType,
    config: cfg,
  });

  if (!validation.valid || !validation.context) {
    return null;
  }

  const sessionKey = resolveSessionKeyForRun(runId);
  if (!sessionKey) {
    return null;
  }

  return {
    sessionId: runId,
    sessionKey,
    contextType: validation.context.context.contextType,
    agentId: validation.context.context.agentId,
    parentSessionId: validation.context.context.parentSessionId,
    parentContextType: validation.context.context.parentContextType,
    signedContext: validation.context,
    contextToken,
  };
}

/**
 * Check if a session can transition from its current context to a new context.
 * This is the main entry point for context transition validation.
 */
export function canSessionTransition(params: {
  runId: string;
  targetContext: SessionContextType;
  contextToken?: string;
}): { allowed: boolean; reason?: string } {
  const { runId, targetContext, contextToken } = params;
  const cfg = loadConfig();

  // Get current context
  const currentContext = resolveSessionContextForRun(runId);
  if (!currentContext) {
    return { allowed: false, reason: "Session not found" };
  }

  // Same context - always allowed
  if (currentContext === targetContext) {
    return { allowed: true };
  }

  // If transitioning to a more privileged context, require a valid context token
  const privilegeLevel: Record<SessionContextType, number> = {
    sandbox: 0,
    subagent: 1,
    main: 2,
    elevated: 3,
  };

  const isEscalation = privilegeLevel[targetContext] > privilegeLevel[currentContext];

  if (isEscalation) {
    // Escalation from sandbox is never allowed
    if (currentContext === "sandbox") {
      return {
        allowed: false,
        reason: "Escalation from sandbox context is not allowed",
      };
    }

    // Other escalations require a valid signed context token
    if (!contextToken) {
      return {
        allowed: false,
        reason: `Signed context token required for escalation to ${targetContext}`,
      };
    }

    const validated = validateSessionContextToken({
      runId,
      contextToken,
      expectedContextType: targetContext,
    });

    if (!validated) {
      return { allowed: false, reason: "Invalid context token" };
    }

    return { allowed: true };
  }

  // De-escalation is generally allowed
  return { allowed: true };
}
