import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import {
  canonicalizePath,
  extractPathCandidates,
  isPathAllowed,
  isPathDenied,
} from '../paths.js';
import { sanitizeEvidence } from '../redact.js';

/**
 * Detect file/path actions outside declared allowedPaths when a scope is set.
 */
export const taskScopeViolationPolicy: Policy = {
  id: 'TASK_SCOPE_VIOLATION',
  description: 'Detect actions outside declared task/resource scope',
  severity: 'MEDIUM',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    const allowed = context.allowedPaths ?? [];
    const denied = context.deniedPaths ?? [];

    if (!['file_read', 'file_write', 'shell', 'tool_call'].includes(event.type)) {
      return null;
    }

    const cwd = event.context?.cwd ?? context.workingDirectory;
    const candidates = extractPathCandidates(event);
    if (candidates.length === 0) {
      return null;
    }

    for (const candidate of candidates) {
      const resolved = canonicalizePath(candidate, cwd);

      if (denied.length > 0 && isPathDenied(candidate, denied, cwd)) {
        return {
          decision: 'BLOCK',
          severity: 'HIGH',
          ruleId: 'TASK_SCOPE_VIOLATION',
          reason: 'Action targets a path on the denied resource list.',
          evidence: sanitizeEvidence([
            `resource=${candidate}`,
            `resolved=${resolved}`,
            `deniedPaths=${denied.join(',')}`,
            `task=${context.task?.id ?? 'none'}`,
          ]),
          eventId: event.id,
        };
      }

      if (allowed.length === 0) {
        continue;
      }

      if (!isPathAllowed(candidate, allowed, cwd)) {
        return {
          decision: 'WARN',
          severity: 'MEDIUM',
          ruleId: 'TASK_SCOPE_VIOLATION',
          reason: 'Action targets a path outside the declared task resource scope.',
          evidence: sanitizeEvidence([
            `resource=${candidate}`,
            `resolved=${resolved}`,
            `allowedPaths=${allowed.join(',')}`,
            `task=${context.task?.id ?? 'none'}`,
          ]),
          eventId: event.id,
        };
      }
    }

    return null;
  },
};
