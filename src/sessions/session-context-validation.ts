/**
 * Session context validation service.
 *
 * Integrates Ed25519 signed context validation with the existing session
 * management system to prevent unauthorized privilege escalation.
 */

import type { OpenClawConfig } from "../config/config.js";
import { emitDiagnosticEvent, isDiagnosticsEnabled } from "../infra/diagnostic-events.js";
import {
  type SessionContextType,
  type SignedSessionContext,
  type SessionContextTransition,
  createSignedContextForTransition,
  validateTransitionRequest,
  decodeSignedContext,
  encodeSignedContext,
  isTransitionAllowed,
  getTrustedPublicKeys,
  ALLOWED_TRANSITIONS,
} from "./session-context-signing.js";

export type SessionContextState = {
  sessionId: string;
  sessionKey: string;
  contextType: SessionContextType;
  agentId: string;
  parentSessionId?: string;
  parentContextType?: SessionContextType;
  signedContext?: SignedSessionContext;
  contextToken?: string;
};

export type ContextTransitionResult = {
  allowed: boolean;
  newState?: SessionContextState;
  reason?: string;
  contextToken?: string;
};

export type ContextValidationConfig = {
  /** Require signed context for all transitions (default: true) */
  requireSignatures: boolean;
  /** Context token TTL in milliseconds (default: 5 minutes) */
  contextTtlMs: number;
  /** Allow de-escalation without signature (default: true) */
  allowUnsignedDeescalation: boolean;
};

const DEFAULT_VALIDATION_CONFIG: ContextValidationConfig = {
  requireSignatures: true,
  contextTtlMs: 5 * 60 * 1000,
  allowUnsignedDeescalation: true,
};

/**
 * Determine context type from session metadata.
 */
export function inferContextType(params: {
  execHost?: string;
  spawnedBy?: string;
  elevatedLevel?: string;
}): SessionContextType {
  // Sandbox sessions
  if (params.execHost === "sandbox") {
    return "sandbox";
  }

  // Subagent sessions (spawned by another session)
  if (params.spawnedBy) {
    return "subagent";
  }

  // Elevated sessions
  if (params.elevatedLevel && params.elevatedLevel !== "none") {
    return "elevated";
  }

  // Default to main
  return "main";
}

/**
 * Check if a context type has higher privileges than another.
 */
export function isEscalation(from: SessionContextType, to: SessionContextType): boolean {
  const privilegeLevel: Record<SessionContextType, number> = {
    sandbox: 0,
    subagent: 1,
    main: 2,
    elevated: 3,
  };

  return privilegeLevel[to] > privilegeLevel[from];
}

/**
 * Check if a context type has lower privileges than another.
 */
export function isDeescalation(from: SessionContextType, to: SessionContextType): boolean {
  const privilegeLevel: Record<SessionContextType, number> = {
    sandbox: 0,
    subagent: 1,
    main: 2,
    elevated: 3,
  };

  return privilegeLevel[to] < privilegeLevel[from];
}

/**
 * Request a context transition with cryptographic validation.
 */
export async function requestContextTransition(params: {
  currentState: SessionContextState;
  targetContext: SessionContextType;
  config?: OpenClawConfig;
  validationConfig?: Partial<ContextValidationConfig>;
  baseDir?: string;
}): Promise<ContextTransitionResult> {
  const validationConfig = { ...DEFAULT_VALIDATION_CONFIG, ...params.validationConfig };
  const { currentState, targetContext, config, baseDir } = params;

  // Same context - no transition needed
  if (currentState.contextType === targetContext) {
    return {
      allowed: true,
      newState: currentState,
      reason: "No transition needed",
    };
  }

  // Check if transition is structurally allowed
  if (!isTransitionAllowed(currentState.contextType, targetContext)) {
    if (isDiagnosticsEnabled(config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validation.failed",
        sessionKey: currentState.sessionKey,
        reason: `Blocked transition: ${currentState.contextType} -> ${targetContext}`,
        metadata: {
          transitionFrom: currentState.contextType,
          transitionTo: targetContext,
        },
      });
    }
    return {
      allowed: false,
      reason: `Transition from ${currentState.contextType} to ${targetContext} is not allowed`,
    };
  }

  // For de-escalation, signature may be optional
  const isDeescalating = isDeescalation(currentState.contextType, targetContext);
  if (isDeescalating && validationConfig.allowUnsignedDeescalation) {
    const newState: SessionContextState = {
      ...currentState,
      contextType: targetContext,
      parentContextType: currentState.contextType,
    };

    if (isDiagnosticsEnabled(config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validated",
        sessionKey: currentState.sessionKey,
        reason: `De-escalation: ${currentState.contextType} -> ${targetContext}`,
      });
    }

    return {
      allowed: true,
      newState,
      reason: "De-escalation allowed without signature",
    };
  }

  // For escalation or when signatures required, create signed context
  if (validationConfig.requireSignatures) {
    try {
      const signedContext = await createSignedContextForTransition({
        sessionId: currentState.sessionId,
        contextType: targetContext,
        agentId: currentState.agentId,
        parentSessionId: currentState.parentSessionId,
        parentContextType: currentState.contextType,
        ttlMs: validationConfig.contextTtlMs,
        baseDir,
      });

      // Validate the transition with the signed context
      const validation = validateTransitionRequest({
        fromContext: currentState.contextType,
        toContext: targetContext,
        sessionId: currentState.sessionId,
        signedContext,
        config,
        baseDir,
      });

      if (!validation.valid) {
        return {
          allowed: false,
          reason: validation.reason,
        };
      }

      const contextToken = encodeSignedContext(signedContext);
      const newState: SessionContextState = {
        ...currentState,
        contextType: targetContext,
        parentSessionId: currentState.sessionId,
        parentContextType: currentState.contextType,
        signedContext,
        contextToken,
      };

      return {
        allowed: true,
        newState,
        contextToken,
        reason: "Transition validated with signature",
      };
    } catch (err) {
      if (isDiagnosticsEnabled(config)) {
        emitDiagnosticEvent({
          type: "session.security",
          action: "token.validation.failed",
          sessionKey: currentState.sessionKey,
          reason: `Failed to create signed context: ${err}`,
        });
      }
      return {
        allowed: false,
        reason: `Failed to create signed context: ${err}`,
      };
    }
  }

  // No signature required, allow transition
  const newState: SessionContextState = {
    ...currentState,
    contextType: targetContext,
    parentContextType: currentState.contextType,
  };

  return {
    allowed: true,
    newState,
    reason: "Transition allowed (signatures not required)",
  };
}

/**
 * Validate an incoming context token for session access.
 */
export function validateContextToken(params: {
  contextToken: string;
  expectedSessionId: string;
  expectedContextType?: SessionContextType;
  config?: OpenClawConfig;
  baseDir?: string;
}): { valid: boolean; context?: SignedSessionContext; reason?: string } {
  const { contextToken, expectedSessionId, expectedContextType, config, baseDir } = params;

  // Decode the token
  const signedContext = decodeSignedContext(contextToken);
  if (!signedContext) {
    if (isDiagnosticsEnabled(config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validation.failed",
        sessionKey: expectedSessionId,
        reason: "Failed to decode context token",
      });
    }
    return { valid: false, reason: "Invalid context token format" };
  }

  // Verify session ID matches
  if (signedContext.context.sessionId !== expectedSessionId) {
    if (isDiagnosticsEnabled(config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validation.failed",
        sessionKey: expectedSessionId,
        reason: "Session ID mismatch in context token",
      });
    }
    return { valid: false, reason: "Session ID mismatch" };
  }

  // Verify context type if expected
  if (expectedContextType && signedContext.context.contextType !== expectedContextType) {
    if (isDiagnosticsEnabled(config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validation.failed",
        sessionKey: expectedSessionId,
        reason: `Context type mismatch: expected ${expectedContextType}, got ${signedContext.context.contextType}`,
      });
    }
    return { valid: false, reason: "Context type mismatch" };
  }

  // Check expiration
  if (signedContext.context.expiresAtMs && Date.now() > signedContext.context.expiresAtMs) {
    if (isDiagnosticsEnabled(config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.expired",
        sessionKey: expectedSessionId,
        reason: "Context token expired",
      });
    }
    return { valid: false, reason: "Context token expired" };
  }

  // Verify signature
  const trustedKeys = getTrustedPublicKeys(baseDir);
  const publicKey = trustedKeys.get(signedContext.signerKeyId);
  if (!publicKey) {
    if (isDiagnosticsEnabled(config)) {
      emitDiagnosticEvent({
        type: "session.security",
        action: "token.validation.failed",
        sessionKey: expectedSessionId,
        reason: `Unknown signer: ${signedContext.signerKeyId.slice(0, 12)}...`,
      });
    }
    return { valid: false, reason: "Unknown signer" };
  }

  // Full validation via the signing module
  const validation = validateTransitionRequest({
    fromContext: signedContext.context.parentContextType ?? "main",
    toContext: signedContext.context.contextType,
    sessionId: expectedSessionId,
    signedContext,
    config,
    baseDir,
  });

  if (!validation.valid) {
    return { valid: false, reason: validation.reason };
  }

  if (isDiagnosticsEnabled(config)) {
    emitDiagnosticEvent({
      type: "session.security",
      action: "token.validated",
      sessionKey: expectedSessionId,
      tokenHash: signedContext.signerKeyId.slice(0, 12),
    });
  }

  return { valid: true, context: signedContext };
}

/**
 * Check if a session can perform an action based on its context.
 */
export function canPerformAction(params: {
  contextType: SessionContextType;
  action: "read" | "write" | "execute" | "send" | "admin";
}): boolean {
  const { contextType, action } = params;

  const permissions: Record<SessionContextType, Set<string>> = {
    sandbox: new Set(["read"]),
    subagent: new Set(["read", "write"]),
    main: new Set(["read", "write", "execute", "send"]),
    elevated: new Set(["read", "write", "execute", "send", "admin"]),
  };

  return permissions[contextType]?.has(action) ?? false;
}

/**
 * Get a summary of allowed transitions for a context type.
 */
export function getAllowedTransitionsFrom(contextType: SessionContextType): SessionContextType[] {
  return ALLOWED_TRANSITIONS[contextType] ?? [];
}

export { type SessionContextType, type SignedSessionContext };
