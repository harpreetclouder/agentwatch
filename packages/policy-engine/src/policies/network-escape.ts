import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { sanitizeEvidence } from '../redact.js';

/**
 * Detect network destinations outside configured authority.
 * True network enforcement requires an external gateway; this is MVP authorization.
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

    const host = hostnameOf(target);
    const destination = formatDestination(target);

    if (isDeniedHost(host, context.deniedNetworks ?? []) || isExfilHeuristic(host, target)) {
      return {
        decision: 'QUARANTINE',
        severity: 'CRITICAL',
        ruleId: 'NETWORK_ESCAPE',
        reason: 'Network destination is explicitly denied or matches exfiltration heuristics.',
        evidence: sanitizeEvidence([
          `destination=${destination}`,
          `hostname=${host}`,
          'matchedRule=deniedNetworks_or_exfil',
        ]),
        eventId: event.id,
      };
    }

    const allowed = context.allowedNetworks ?? [];
    if (allowed.length === 0) {
      if (isLocalOrPrivate(host)) {
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
        evidence: sanitizeEvidence([
          `destination=${destination}`,
          `environment=${context.environment}`,
        ]),
        eventId: event.id,
      };
    }

    if (isAllowedHost(host, allowed)) {
      return null;
    }

    return {
      decision: 'BLOCK',
      severity: 'HIGH',
      ruleId: 'NETWORK_ESCAPE',
      reason: 'Network destination is outside the allowed network authority.',
      evidence: sanitizeEvidence([
        `destination=${destination}`,
        `hostname=${host}`,
        `allowedNetworks=${allowed.join(',')}`,
      ]),
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
  return urlOrHost.split('/')[0]?.split(':')[0]?.toLowerCase() ?? urlOrHost.toLowerCase();
}

function formatDestination(target: string): string {
  try {
    if (target.includes('://')) {
      const u = new URL(target);
      return `${u.protocol}//${u.hostname}${u.port ? `:${u.port}` : ''}`;
    }
  } catch {
    // fall through
  }
  return target;
}

function hostMatches(host: string, entry: string): boolean {
  const e = entry.toLowerCase().trim();
  if (!e) return false;
  if (e.startsWith('*.')) {
    const suffix = e.slice(1); // .example.com
    return host === e.slice(2) || host.endsWith(suffix);
  }
  return host === e || host.endsWith(`.${e}`);
}

function isAllowedHost(host: string, allowed: readonly string[]): boolean {
  return allowed.some((entry) => hostMatches(host, entry));
}

function isDeniedHost(host: string, denied: readonly string[]): boolean {
  return denied.some((entry) => hostMatches(host, entry));
}

function isExfilHeuristic(host: string, raw: string): boolean {
  const lower = `${host} ${raw}`.toLowerCase();
  // Stage 6 local attack sink (synthetic only — never external infra).
  const localCollector =
    (host === '127.0.0.1' || host === 'localhost' || host === '::1') &&
    (/:8787\b/.test(lower) || lower.includes('/collect'));
  return (
    host.startsWith('evil.') ||
    host.includes('exfil') ||
    host.startsWith('collector.') ||
    lower.includes('/collect') ||
    localCollector
  );
}

function isLocalOrPrivate(host: string): boolean {
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
