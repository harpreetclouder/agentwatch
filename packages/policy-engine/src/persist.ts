import { createId } from '@jev/shared';
import type { JevStore, SecurityDecisionRecord, ViolationRecord } from '@jev/storage';
import type { SecurityDecision } from './types.js';
import { nextSecurityState } from './enforcement.js';
import type { AgentContext } from '@jev/agent-events';

export function toDecisionRecord(
  decision: SecurityDecision,
  sessionId: string,
  id: string = createId('dec'),
  createdAt: string = new Date().toISOString(),
): SecurityDecisionRecord {
  return {
    id,
    sessionId,
    eventId: decision.eventId,
    decision: decision.decision,
    severity: decision.severity,
    ruleId: decision.ruleId,
    reason: decision.reason,
    evidence: decision.evidence,
    createdAt,
  };
}

export type PersistDecisionResult = {
  decisionRecord: SecurityDecisionRecord;
  violation: ViolationRecord | null;
  securityState: AgentContext['securityState'];
};

/**
 * Persist a security decision and apply progressive enforcement state.
 */
export async function persistDecision(
  store: JevStore,
  decision: SecurityDecision,
  context: AgentContext,
): Promise<PersistDecisionResult> {
  const decisionRecord = toDecisionRecord(decision, context.sessionId);
  await store.decisions.append(decisionRecord);

  let violation: ViolationRecord | null = null;
  if (decision.decision !== 'ALLOW') {
    violation = {
      id: createId('viol'),
      sessionId: context.sessionId,
      decisionId: decisionRecord.id,
      eventId: decision.eventId,
      ruleId: decision.ruleId,
      severity: decision.severity,
      summary: decision.reason,
      createdAt: decisionRecord.createdAt,
    };
    await store.violations.append(violation);
  }

  const securityState = nextSecurityState(context.securityState, decision);
  await store.securityState.set(context.sessionId, securityState, decision.reason);

  const session = await store.sessions.findById(context.sessionId);
  if (session) {
    await store.sessions.update({
      ...session,
      securityState,
      status: securityState === 'QUARANTINED' ? 'QUARANTINED' : session.status,
    });
  }

  return { decisionRecord, violation, securityState };
}
