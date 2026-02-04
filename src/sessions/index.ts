/**
 * Session management module.
 *
 * This module provides:
 * - Cryptographically secure session key generation
 * - Session key validation and verification
 * - Session key rotation capabilities
 * - Session security monitoring and diagnostics
 */

// Core secure session key functionality
export {
  generateSecureToken,
  isValidSecureToken,
  compareTokens,
  hashTokenForLog,
  createSecureSession,
  registerSecureSession,
  validateSecureSession,
  lookupTokenByLegacyKey,
  lookupMetadataByLegacyKey,
  rotateSecureSession,
  revokeSecureSession,
  pruneExpiredSessions,
  getSessionsNeedingRotation,
  loadSecureSessionMapping,
  saveSecureSessionMapping,
  clearSecureSessionCache,
  DEFAULT_SECURE_SESSION_CONFIG,
  type SecureSessionConfig,
  type SecureSessionEntry,
  type SecureSessionMetadata,
  type SecureSessionMappingFile,
} from "./secure-session-key.js";

// Session security service (with rate limiting and diagnostics)
export {
  getSessionSecurityConfig,
  isSessionRateLimited,
  createSecureSessionWithSecurity,
  validateSessionToken,
  rotateSessionToken,
  revokeSessionToken,
  getOrCreateSecureToken,
  runSessionSecurityMaintenance,
  clearRateLimitForTest,
} from "./session-security.js";

// Session key utilities (existing)
export {
  parseAgentSessionKey,
  isSubagentSessionKey,
  isAcpSessionKey,
  resolveThreadParentSessionKey,
  type ParsedAgentSessionKey,
} from "./session-key-utils.js";

// Session context signing (Ed25519)
export {
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
  type SessionContextType,
  type SessionContext,
  type SignedSessionContext,
  type SessionContextKeyPair,
  type SessionContextTransition,
} from "./session-context-signing.js";

// Session context validation service
export {
  inferContextType,
  isEscalation,
  isDeescalation,
  requestContextTransition,
  validateContextToken,
  canPerformAction,
  getAllowedTransitionsFrom,
  type SessionContextState,
  type ContextTransitionResult,
  type ContextValidationConfig,
} from "./session-context-validation.js";
