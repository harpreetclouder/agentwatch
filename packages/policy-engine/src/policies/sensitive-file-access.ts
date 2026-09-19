import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { canonicalizePath, extractPathCandidates, isPathDenied, resolveSafePath } from '../paths.js';
import { sanitizeEvidence } from '../redact.js';

/**
 * Enforce context.deniedPaths with canonical path matching (no substring).
 */
export const sensitiveFileAccessPolicy: Policy = {
  id: 'SENSITIVE_FILE_ACCESS',
  description: 'Detect access to configured sensitive / denied paths',
  severity: 'HIGH',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    if (!['file_read', 'file_write', 'shell', 'tool_call'].includes(event.type)) {
      return null;
    }

    const denied = context.deniedPaths ?? [];
    if (denied.length === 0) {
      return null;
    }

    const cwd = event.context?.cwd ?? context.workingDirectory;

    for (const candidate of extractPathCandidates(event)) {
      if (!isPathDenied(candidate, denied, cwd)) {
        continue;
      }
      const resolved = resolveSafePath(candidate, cwd) ?? canonicalizePath(candidate, cwd);
      return {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'SENSITIVE_FILE_ACCESS',
        reason: 'Access to a denied/sensitive path is not authorized.',
        evidence: sanitizeEvidence([
          `resource=${candidate}`,
          `resolved=${resolved}`,
          `deniedPaths=${denied.join(',')}`,
          `matchedRule=deniedPaths`,
        ]),
        eventId: event.id,
      };
    }

    return null;
  },
};
