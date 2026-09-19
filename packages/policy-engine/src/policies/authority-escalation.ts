import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { extractPathCandidates, tokenizeCommand } from '../paths.js';

/**
 * Detect attempts to obtain permissions beyond current authority.
 */
export const authorityEscalationPolicy: Policy = {
  id: 'AUTHORITY_ESCALATION',
  description: 'Detect attempts to obtain permissions beyond current authority',
  severity: 'CRITICAL',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    const blob = `${event.action.name} ${event.action.target ?? ''}`.toLowerCase();

    const intentMarkers = [
      'request admin',
      'elevate privileges',
      'become root',
      'grant sudo',
      'disable sandbox',
      'expand visa',
      'expand authority',
      'setuid',
    ];

    for (const marker of intentMarkers) {
      if (blob.includes(marker)) {
        return quarantine(event, `intent=${marker}`, context);
      }
    }

    if (event.type === 'shell' || event.type === 'tool_call') {
      const command = [
        event.action.target ?? '',
        typeof event.action.arguments === 'string'
          ? event.action.arguments
          : typeof event.action.arguments === 'object' &&
              event.action.arguments &&
              'command' in event.action.arguments
            ? String((event.action.arguments as { command?: unknown }).command ?? '')
            : '',
      ]
        .join(' ')
        .trim();

      if (command) {
        const tokens = tokenizeCommand(command).map((t) => t.toLowerCase());
        if (
          tokens[0] === 'sudo' ||
          tokens[0] === 'su' ||
          tokens[0] === 'doas' ||
          tokens.includes('visudo') ||
          command.toLowerCase().includes('chmod u+s') ||
          command.toLowerCase().includes('chown root')
        ) {
          return quarantine(event, `command=${command.slice(0, 120)}`, context);
        }
      }
    }

    if (event.type === 'file_write') {
      for (const candidate of extractPathCandidates(event)) {
        const lower = candidate.toLowerCase();
        if (
          lower.includes('/etc/sudoers') ||
          lower.endsWith('/etc/passwd') ||
          lower.includes('/etc/shadow') ||
          lower.includes('authorized_keys')
        ) {
          return quarantine(event, `resource=${candidate}`, context);
        }
      }
    }

    return null;
  },
};

function quarantine(
  event: AgentEvent,
  evidenceItem: string,
  context: AgentContext,
): SecurityDecision {
  return {
    decision: 'QUARANTINE',
    severity: 'CRITICAL',
    ruleId: 'AUTHORITY_ESCALATION',
    reason: 'Attempt to escalate authority beyond the current agent Visa/context.',
    evidence: [
      evidenceItem,
      `securityState=${context.securityState}`,
      'authority_must_not_expand_via_agent_action',
    ],
    eventId: event.id,
  };
}
