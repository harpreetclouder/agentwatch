import type { SecurityState } from '@jev/shared';
import { createId } from '@jev/shared';
import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { JevStore, SessionRecord } from '@jev/storage';
import type { SecurityDecision } from './types.js';

/** Sessions in these states must not execute agent tool actions. */
export function isEnforcementFrozen(state: SecurityState): boolean {
  return state === 'QUARANTINED' || state === 'REVOKED';
}

/**
 * Synthetic decision when a frozen session attempts further action.
 * Operator must `jev resume` — agents cannot self-clear quarantine.
 */
export function frozenSessionDecision(
  event: AgentEvent,
  context: AgentContext,
): SecurityDecision {
  return {
    decision: 'QUARANTINE',
    severity: 'CRITICAL',
    ruleId: 'SESSION_QUARANTINED',
    reason:
      context.securityState === 'REVOKED'
        ? 'Session authority is REVOKED. Operator intervention required.'
        : 'Session is QUARANTINED. Operator must run `jev resume` before actions proceed.',
    evidence: [
      `session=${context.sessionId}`,
      `state=${context.securityState}`,
      `event_type=${event.type}`,
      `action=${event.action.name}`,
      'operator_only_resume',
    ],
    eventId: event.id,
  };
}

export type SessionControlResult = {
  session: SessionRecord;
  previousState: SecurityState;
  securityState: SecurityState;
  reason: string;
};

async function resolveTargetSession(
  store: JevStore,
  sessionId?: string,
): Promise<SessionRecord | null> {
  if (sessionId) {
    return store.sessions.findById(sessionId);
  }
  return (
    (await store.sessions.findLatestActive()) ?? (await store.sessions.findLatest())
  );
}

/**
 * Operator control: force-quarantine a session.
 * Agents must never call this — CLI / control plane only.
 */
export async function quarantineSession(
  store: JevStore,
  options: { sessionId?: string; reason?: string } = {},
): Promise<SessionControlResult> {
  const session = await resolveTargetSession(store, options.sessionId);
  if (!session) {
    throw new Error('No session found to quarantine. Run `jev watch` or `jev attack` first.');
  }

  const previous =
    (await store.securityState.get(session.id))?.state ?? session.securityState;
  const reason = options.reason ?? 'Operator quarantine via jev quarantine';

  await store.securityState.set(session.id, 'QUARANTINED', reason);
  const updated: SessionRecord = {
    ...session,
    securityState: 'QUARANTINED',
    status: 'QUARANTINED',
  };
  await store.sessions.update(updated);

  return {
    session: updated,
    previousState: previous,
    securityState: 'QUARANTINED',
    reason,
  };
}

/**
 * Operator control: resume a quarantined (or restricted) session to NORMAL.
 * Never callable by the agent under observation.
 */
export async function resumeSession(
  store: JevStore,
  options: { sessionId?: string; reason?: string } = {},
): Promise<SessionControlResult> {
  const session = await resolveTargetSession(store, options.sessionId);
  if (!session) {
    throw new Error('No session found to resume.');
  }

  const previous =
    (await store.securityState.get(session.id))?.state ?? session.securityState;

  if (previous === 'REVOKED') {
    throw new Error(
      'Session is REVOKED and cannot be resumed. Create a new session with `jev watch`.',
    );
  }

  if (previous !== 'QUARANTINED' && previous !== 'RESTRICTED' && session.status !== 'QUARANTINED') {
    throw new Error(
      `Session is ${previous} — resume only applies to QUARANTINED or RESTRICTED sessions.`,
    );
  }

  const reason = options.reason ?? 'Operator resume via jev resume';
  await store.securityState.set(session.id, 'NORMAL', reason);

  const updated: SessionRecord = {
    ...session,
    securityState: 'NORMAL',
    status: session.status === 'ENDED' ? 'ENDED' : 'ACTIVE',
    endedAt: session.status === 'ENDED' ? session.endedAt : null,
  };
  await store.sessions.update(updated);

  return {
    session: updated,
    previousState: previous,
    securityState: 'NORMAL',
    reason,
  };
}

/** Stable id helper for operator audit events (optional callers). */
export function operatorControlEventId(): string {
  return createId('op');
}
