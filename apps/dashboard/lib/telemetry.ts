import { basename, isAbsolute, relative, sep } from 'node:path';
import type { AgentEvent } from '@veyra/agent-events';
import type { SecurityState } from '@veyra/shared';
import type { SecurityDecisionRecord } from '@veyra/storage';

export type TelemetryAction = {
  name: string;
  target?: string;
};

export type TelemetryEvent = {
  eventId: string;
  sessionId: string;
  agentId: string;
  timestamp: string;
  type: string;
  action: TelemetryAction;
  decision: string | null;
  decisionId: string | null;
  policy: string | null;
  severity: string | null;
  /** Safe policy reason — never secret contents. */
  reason: string | null;
  securityState: string;
};

/**
 * Safe display target: never emit absolute paths that might include home dirs
 * with usernames; for known secret filenames, emit basename only.
 */
export function sanitizeActionTarget(target: string | undefined): string | undefined {
  if (!target) return undefined;
  const normalized = target.replace(/\\/g, '/');
  const base = basename(normalized);
  if (
    base === '.env' ||
    base.startsWith('.env.') ||
    base === 'credentials' ||
    base === 'id_rsa' ||
    base === 'id_ed25519' ||
    /\.pem$/i.test(base) ||
    /\.key$/i.test(base)
  ) {
    return base;
  }
  if (isAbsolute(target)) {
    // Prefer last 2 path segments for readability without full home path
    const parts = normalized.split('/').filter(Boolean);
    return parts.slice(-2).join('/') || base;
  }
  // Keep relative paths but strip any `..` traversal noise
  const rel = relative('.', target);
  if (rel.startsWith('..')) {
    return base;
  }
  return rel.split(sep).join('/');
}

export function toTelemetryEvent(input: {
  event: AgentEvent;
  decision: SecurityDecisionRecord | null;
  securityState: SecurityState | string;
}): TelemetryEvent {
  const { event, decision, securityState } = input;
  const target = sanitizeActionTarget(event.action.target);
  return {
    eventId: event.id,
    sessionId: event.sessionId,
    agentId: event.agentId,
    timestamp: event.timestamp,
    type: event.type,
    action: {
      name: event.action.name,
      ...(target ? { target } : {}),
    },
    decision: decision?.decision ?? null,
    decisionId: decision?.id ?? null,
    policy: decision?.ruleId ?? null,
    severity: decision?.severity ?? null,
    reason: decision?.reason ? sanitizeReason(decision.reason) : null,
    securityState: String(securityState),
  };
}

/** Drop anything that looks like secret material from reason strings. */
export function sanitizeReason(reason: string): string {
  return reason
    .replace(/\b\w*(key|token|password|secret)\w*\s*[:=]\s*\S+/gi, '[REDACTED]')
    .replace(/veyra_fake_[a-z0-9_]+/gi, '[REDACTED]')
    .slice(0, 280);
}

export function listTelemetryAfter(
  events: AgentEvent[],
  decisions: SecurityDecisionRecord[],
  securityState: string,
  afterEventId: string | null,
): TelemetryEvent[] {
  const byEvent = new Map(decisions.map((d) => [d.eventId, d]));

  // If cursor is unknown in this session (wiped DB / session switch), replay from start.
  let started = afterEventId === null;
  if (afterEventId !== null && !events.some((e) => e.id === afterEventId)) {
    started = true;
  }

  const out: TelemetryEvent[] = [];
  for (const event of events) {
    if (!started) {
      if (event.id === afterEventId) {
        started = true;
      }
      continue;
    }
    out.push(
      toTelemetryEvent({
        event,
        decision: byEvent.get(event.id) ?? null,
        securityState,
      }),
    );
  }
  return out;
}
