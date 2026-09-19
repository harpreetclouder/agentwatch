import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { extractPathCandidates } from '../paths.js';

const PROD_HOST_MARKERS = [
  'prod.',
  'production.',
  '.prod.',
  'prd.',
  'prod-',
  'production-',
];

/**
 * Prevent unauthorized access to production resources / environments.
 */
export const productionAccessPolicy: Policy = {
  id: 'PRODUCTION_ACCESS',
  description: 'Prevent unauthorized production resource access',
  severity: 'HIGH',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    const writeLike = ['file_write', 'shell', 'network', 'tool_call', 'mcp'].includes(
      event.type,
    );

    if (context.environment === 'production' && writeLike) {
      return {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'PRODUCTION_ACCESS',
        reason: 'Mutating actions are blocked in the production environment without a Visa grant.',
        evidence: [
          `environment=production`,
          `event_type=${event.type}`,
          `action=${event.action.name}`,
        ],
        eventId: event.id,
      };
    }

    const haystack = [
      event.action.target ?? '',
      ...extractPathCandidates(event),
      typeof event.action.arguments === 'string' ? event.action.arguments : '',
    ]
      .join(' ')
      .toLowerCase();

    const hit = PROD_HOST_MARKERS.find((m) => haystack.includes(m));
    if (!hit) {
      return null;
    }

    // Allow when explicitly in local/dev and only reading docs — still block network/shell to prod hosts
    if (event.type === 'network' || event.type === 'shell' || event.type === 'file_write') {
      return {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'PRODUCTION_ACCESS',
        reason: 'Production-looking resource access is not authorized for this session.',
        evidence: [`marker=${hit}`, `event_type=${event.type}`, `target=${event.action.target ?? ''}`],
        eventId: event.id,
      };
    }

    return null;
  },
};
