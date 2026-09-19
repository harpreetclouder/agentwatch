import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { extractPathCandidates, resolvePath } from '../paths.js';
import { classifySecretPath } from '../classify/secrets.js';

/**
 * Block credential / secret material access outside declared authority.
 * Deterministic — does not depend on LLM judgment.
 */
export const secretAccessPolicy: Policy = {
  id: 'SECRET_ACCESS',
  description: 'Detect and block access to secrets and credential stores',
  severity: 'HIGH',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    if (context.securityState === 'REVOKED' || context.securityState === 'QUARANTINED') {
      // Quarantined agents: still emit decisions on secret touches for evidence.
    }

    const relevantTypes = new Set(['file_read', 'file_write', 'shell', 'tool_call', 'mcp']);
    if (!relevantTypes.has(event.type)) {
      return null;
    }

    const cwd = event.context?.cwd ?? context.workingDirectory;
    const candidates = extractPathCandidates(event);
    if (candidates.length === 0) {
      return null;
    }

    for (const candidate of candidates) {
      const resolved = resolvePath(candidate, cwd);
      const match = classifySecretPath(resolved) ?? classifySecretPath(candidate);
      if (!match) {
        continue;
      }

      const allowed = isExplicitlyAllowed(context, resolved, candidate);
      if (allowed) {
        return null;
      }

      const evidence = [
        `resource=${candidate}`,
        `resolved=${resolved}`,
        `secret_category=${match.category}`,
        `secret_label=${match.label}`,
        `task=${context.task?.id ?? 'none'}`,
        'no_credential_authority',
      ];

      if (event.context?.taskDescription) {
        evidence.push(`task_description=${event.context.taskDescription}`);
      }

      return {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'SECRET_ACCESS',
        reason:
          'Credential or secret access is outside the declared task authority. ' +
          'A jailbreak must not become authority.',
        evidence,
        eventId: event.id,
      };
    }

    return null;
  },
};

function isExplicitlyAllowed(
  context: AgentContext,
  resolved: string,
  raw: string,
): boolean {
  const allowed = context.allowedPaths ?? [];
  if (allowed.length === 0) {
    return false;
  }

  const haystacks = [resolved, raw].map((s) => s.toLowerCase());
  return allowed.some((entry) => {
    const needle = entry.toLowerCase();
    return haystacks.some((h) => h === needle || h.endsWith(needle) || h.includes(needle));
  });
}
