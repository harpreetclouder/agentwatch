import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { extractPathCandidates, resolvePath, isPathInside } from '../paths.js';

/**
 * Enforce context.deniedPaths and optional sensitive allow/deny boundaries.
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
      const resolved = resolvePath(candidate, cwd);
      for (const pattern of denied) {
        const deniedResolved = resolvePath(pattern, cwd);
        if (
          isPathInside(resolved, deniedResolved) ||
          resolved.toLowerCase().includes(pattern.toLowerCase())
        ) {
          return {
            decision: 'BLOCK',
            severity: 'HIGH',
            ruleId: 'SENSITIVE_FILE_ACCESS',
            reason: 'Access to a denied/sensitive path is not authorized.',
            evidence: [
              `resource=${candidate}`,
              `resolved=${resolved}`,
              `denied_pattern=${pattern}`,
            ],
            eventId: event.id,
          };
        }
      }
    }

    return null;
  },
};
