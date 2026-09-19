import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import {
  basenameOf,
  canonicalizePath,
  extractPathCandidates,
  pathSegments,
  tokenizeCommand,
} from '../paths.js';
import { sanitizeEvidence } from '../redact.js';

const PRIVILEGE_PATH_BASENAMES = new Set([
  'sudoers',
  'passwd',
  'shadow',
  'authorized_keys',
]);

const PRIVILEGE_PATH_SEGMENTS = new Set(['sudoers.d']);

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
        const lower = command.toLowerCase();
        if (
          tokens[0] === 'sudo' ||
          tokens[0] === 'su' ||
          tokens[0] === 'doas' ||
          tokens.includes('visudo') ||
          (tokens[0] === 'chmod' && tokens.includes('u+s')) ||
          (tokens[0] === 'chown' && tokens.includes('root'))
        ) {
          return quarantine(event, `command=${command.slice(0, 120)}`, context);
        }
        // Keep chmod/chown compound forms that tokenize oddly
        if (lower.includes('chmod u+s') || lower.includes('chown root')) {
          return quarantine(event, `command=${command.slice(0, 120)}`, context);
        }
      }
    }

    if (event.type === 'file_write' || event.type === 'file_read' || event.type === 'shell') {
      const cwd = event.context?.cwd ?? context.workingDirectory;
      for (const candidate of extractPathCandidates(event)) {
        const resolved = canonicalizePath(candidate, cwd);
        const base = basenameOf(resolved).toLowerCase();
        const segments = pathSegments(resolved).map((s) => s.toLowerCase());
        if (
          PRIVILEGE_PATH_BASENAMES.has(base) ||
          segments.some((s) => PRIVILEGE_PATH_SEGMENTS.has(s))
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
    evidence: sanitizeEvidence([
      evidenceItem,
      `securityState=${context.securityState}`,
      'authority_must_not_expand_via_agent_action',
    ]),
    eventId: event.id,
  };
}
