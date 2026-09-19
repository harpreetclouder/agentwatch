export type { SecurityDecision, Policy, PolicyEvaluationResult } from './types.js';

export { PolicyEngine } from './engine.js';
export type { PolicyEngineOptions } from './engine.js';

export {
  defaultDecisionForSeverity,
  nextSecurityState,
  pickPrimaryDecision,
} from './enforcement.js';

export { toDecisionRecord, persistDecision } from './persist.js';
export type { PersistDecisionResult } from './persist.js';

export {
  isEnforcementFrozen,
  frozenSessionDecision,
  quarantineSession,
  resumeSession,
  operatorControlEventId,
} from './session-control.js';
export type { SessionControlResult } from './session-control.js';

export {
  createDefaultPolicies,
  secretAccessPolicy,
  securityControlTamperingPolicy,
  credentialAccessPolicy,
  sensitiveFileAccessPolicy,
  dangerousShellPolicy,
  productionAccessPolicy,
  networkEscapePolicy,
  taskScopeViolationPolicy,
  mcpToolViolationPolicy,
  authorityEscalationPolicy,
} from './policies/index.js';

export { classifySecretPath } from './classify/secrets.js';
export type { SecretMatch } from './classify/secrets.js';

export {
  extractPathCandidates,
  resolvePath,
  canonicalizePath,
  isPathInside,
  isPathAllowed,
  isPathDenied,
  matchesResourceScope,
  tokenizeCommand,
} from './paths.js';

export {
  redactSensitiveValue,
  sanitizeEvidence,
  sanitizeEventPayload,
} from './redact.js';
export type { ResourceMatchScope } from './paths.js';
