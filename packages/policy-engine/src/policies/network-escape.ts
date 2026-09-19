import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { Policy, SecurityDecision } from '../types.js';

/**
 * Detect network destinations outside configured authority.
 */
export const networkEscapePolicy: Policy = {
  id: 'NETWORK_ESCAPE',
  description: 'Detect network destinations outside allowed authority',
  severity: 'HIGH',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    if (event.type !== 'network') {
      return null;
    }

    const target = (event.action.target ?? '').trim();
    if (!target) {
      return null;
    }

    const lower = target.toLowerCase();

    // Always block known exfil / evil fixtures
    if (
      lower.includes('evil.') ||
      lower.includes('exfil') ||
      lower.includes('collector.') ||
      lower.includes('/collect')
    ) {
      return {
        decision: 'QUARANTINE',
        severity: 'CRITICAL',
        ruleId: 'NETWORK_ESCAPE',
        reason: 'Suspected data-exfiltration network destination.',
        evidence: [`destination=${target}`, 'exfil_heuristic=true'],
        eventId: event.id,
      };
    }

    const allowed = context.allowedNetworks ?? [];
    if (allowed.length === 0) {
      // No authority list configured: allow local/private, warn on public hosts in non-local envs
      if (isLocalOrPrivate(lower)) {
        return null;
      }
      if (context.environment === 'local' || context.environment === 'development') {
        return null;
      }
      return {
        decision: 'WARN',
        severity: 'MEDIUM',
        ruleId: 'NETWORK_ESCAPE',
        reason: 'External network destination with no allowedNetworks configured.',
        evidence: [`destination=${target}`, `environment=${context.environment}`],
        eventId: event.id,
      };
    }

    const permitted = allowed.some((entry) => {
      const e = entry.toLowerCase();
      return lower === e || lower.includes(e) || hostnameOf(lower).endsWith(e.replace(/^\*\./, ''));
    });

    if (permitted) {
      return null;
    }

    return {
      decision: 'BLOCK',
      severity: 'HIGH',
      ruleId: 'NETWORK_ESCAPE',
      reason: 'Network destination is outside the allowed network authority.',
      evidence: [
        `destination=${target}`,
        `allowedNetworks=${allowed.join(',')}`,
      ],
      eventId: event.id,
    };
  },
};

function hostnameOf(urlOrHost: string): string {
  try {
    if (urlOrHost.includes('://')) {
      return new URL(urlOrHost).hostname.toLowerCase();
    }
  } catch {
    // fall through
  }
  return urlOrHost.split('/')[0]?.split(':')[0]?.toLowerCase() ?? urlOrHost;
}

function isLocalOrPrivate(value: string): boolean {
  const host = hostnameOf(value);
  return (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host.endsWith('.local') ||
    host.startsWith('10.') ||
    host.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(host)
  );
}
