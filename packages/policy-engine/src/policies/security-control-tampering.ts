import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { extractPathCandidates } from '../paths.js';
import {
  classifySecurityPlanePath,
  isWriteLikeEvent,
} from '../classify/security-plane.js';

/**
 * CRITICAL: agent must never modify the security control plane that governs it.
 */
export const securityControlTamperingPolicy: Policy = {
  id: 'SECURITY_CONTROL_TAMPERING',
  description: 'Detect attempts to modify VEYRA policy, config, or security state',
  severity: 'CRITICAL',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    const relevantTypes = new Set(['file_read', 'file_write', 'shell', 'tool_call', 'mcp']);
    if (!relevantTypes.has(event.type)) {
      return null;
    }

    const cwd = event.context?.cwd ?? context.workingDirectory;
    const candidates = extractPathCandidates(event);
    if (candidates.length === 0) {
      // Also catch action names that target the control plane directly.
      const nameHit = detectNameBasedTampering(event);
      return nameHit;
    }

    const writeLike = isWriteLikeEvent(event.type, event.action.name);
    // Reads of .veyra are suspicious; writes are critical. Both are blocked at CRITICAL
    // for control-plane paths — agent must not inspect/alter enforcement config.
    for (const candidate of candidates) {
      const match = classifySecurityPlanePath(candidate, cwd);
      if (!match) {
        continue;
      }

      const evidence = [
        `resource=${candidate}`,
        `resolved=${match.resolved}`,
        `plane_kind=${match.kind}`,
        `write_like=${writeLike}`,
        `agent=${context.agentId}`,
        `session=${context.sessionId}`,
        'control_plane_is_outside_agent_authority',
      ];

      return {
        decision: 'QUARANTINE',
        severity: 'CRITICAL',
        ruleId: 'SECURITY_CONTROL_TAMPERING',
        reason:
          'Attempt to access or modify the VEYRA security control plane. ' +
          'Agents cannot alter the policies that constrain them.',
        evidence,
        eventId: event.id,
      };
    }

    return detectNameBasedTampering(event);
  },
};

function detectNameBasedTampering(event: AgentEvent): SecurityDecision | null {
  const blob = `${event.action.name} ${event.action.target ?? ''}`.toLowerCase();
  const markers = [
    'disable watchdog',
    'clear violations',
    'remove quarantine',
    'revoke quarantine',
    'modify policy',
    'delete .veyra',
    'rm .veyra',
  ];

  for (const marker of markers) {
    if (blob.includes(marker)) {
      return {
        decision: 'QUARANTINE',
        severity: 'CRITICAL',
        ruleId: 'SECURITY_CONTROL_TAMPERING',
        reason: 'Attempted security-control tampering via action intent.',
        evidence: [`marker=${marker}`, `action=${event.action.name}`],
        eventId: event.id,
      };
    }
  }

  return null;
}
