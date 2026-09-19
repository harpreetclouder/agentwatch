import type { Policy } from '../types.js';
import { secretAccessPolicy } from './secret-access.js';
import { securityControlTamperingPolicy } from './security-control-tampering.js';
import { credentialAccessPolicy } from './credential-access.js';
import { sensitiveFileAccessPolicy } from './sensitive-file-access.js';
import { dangerousShellPolicy } from './dangerous-shell.js';
import { productionAccessPolicy } from './production-access.js';
import { networkEscapePolicy } from './network-escape.js';
import { taskScopeViolationPolicy } from './task-scope-violation.js';
import { mcpToolViolationPolicy } from './mcp-tool-violation.js';
import { authorityEscalationPolicy } from './authority-escalation.js';

/** Full MVP deterministic policy set. Order: critical control-plane first. */
export function createDefaultPolicies(): Policy[] {
  return [
    securityControlTamperingPolicy,
    authorityEscalationPolicy,
    dangerousShellPolicy,
    secretAccessPolicy,
    credentialAccessPolicy,
    sensitiveFileAccessPolicy,
    productionAccessPolicy,
    networkEscapePolicy,
    mcpToolViolationPolicy,
    taskScopeViolationPolicy,
  ];
}

export {
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
};
