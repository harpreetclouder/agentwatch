import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import {
  canonicalizePath,
  extractPathCandidates,
  isPathAllowed,
  isPathDenied,
} from '../paths.js';
import { classifySecretPath } from '../classify/secrets.js';
import { sanitizeEvidence } from '../redact.js';

/**
 * Block credential / secret material access outside declared authority.
 * Deterministic — does not depend on LLM judgment.
 */
export const secretAccessPolicy: Policy = {
  id: 'SECRET_ACCESS',
  description: 'Detect and block access to secrets and credential stores',
  severity: 'HIGH',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    const relevantTypes = new Set(['file_read', 'file_write', 'shell', 'tool_call', 'mcp']);
    if (!relevantTypes.has(event.type)) {
      return null;
    }

    const cwd = event.context?.cwd ?? context.workingDirectory;
    const candidates = extractPathCandidates(event);
    if (candidates.length === 0) {
      return null;
    }

    // Explicit deny scopes / deniedPaths win first
    for (const candidate of candidates) {
      if (isPathDenied(candidate, context.deniedPaths ?? [], cwd)) {
        const resolved = canonicalizePath(candidate, cwd);
        return {
          decision: 'BLOCK',
          severity: 'HIGH',
          ruleId: 'SECRET_ACCESS',
          reason: 'Path is on the denied resource list.',
          evidence: sanitizeEvidence([
            `resource=${candidate}`,
            `resolved=${resolved}`,
            `operation=read`,
            `matchedRule=deniedPaths`,
            `task=${context.task?.id ?? 'none'}`,
            `session=${context.sessionId}`,
          ]),
          eventId: event.id,
        };
      }
    }

    for (const candidate of candidates) {
      const resolved = canonicalizePath(candidate, cwd);
      const match = classifySecretPath(resolved) ?? classifySecretPath(candidate);
      if (!match) {
        continue;
      }

      if (isPathAllowed(candidate, context.allowedPaths ?? [], cwd)) {
        return null;
      }

      const allowedByScope = (context.resourceScopes ?? []).some(
        (s) =>
          (s.type === 'FILE' || s.type === 'DIRECTORY') &&
          s.effect === 'allow' &&
          isPathAllowed(candidate, [s.pattern], cwd),
      );
      if (allowedByScope) {
        return null;
      }

      return {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'SECRET_ACCESS',
        reason:
          'Agent does not have authority to access secret-bearing files. ' +
          'A jailbreak must not become authority.',
        evidence: sanitizeEvidence([
          `resource=${candidate}`,
          `resolved=${resolved}`,
          `operation=${event.type === 'file_write' ? 'write' : 'read'}`,
          `category=${match.category}`,
          `matchedRule=secret-file`,
          `secret_label=${match.label}`,
          `task=${context.task?.id ?? 'none'}`,
          `session=${context.sessionId}`,
          'no_credential_authority',
        ]),
        eventId: event.id,
      };
    }

    return null;
  },
};
