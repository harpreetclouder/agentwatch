import { createId } from '@veyra/shared';
import type { VeyraStore, SecurityDecisionRecord, ViolationRecord } from '@veyra/storage';
import type { SecurityDecision } from './types.js';
import { nextSecurityState } from './enforcement.js';
import type { AgentContext } from '@veyra/agent-events';
import { sanitizeEvidence } from './redact.js';

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
    reason: redactReason(decision.reason),
    evidence: sanitizeEvidence(decision.evidence),
    createdAt,
  };
}

function redactReason(reason: string): string {
  return sanitizeEvidence([reason])[0] ?? reason;
}

export type PersistDecisionResult = {
  decisionRecord: SecurityDecisionRecord;
  violation: ViolationRecord | null;
  securityState: AgentContext['securityState'];
};

/**
 * Persist a security decision and apply progressive enforcement state.
 * Evidence and reasons are redacted before storage.
 */
export async function persistDecision(
  store: VeyraStore,
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
      summary: decisionRecord.reason,
      createdAt: decisionRecord.createdAt,
    };
    await store.violations.append(violation);
  }

  const securityState = nextSecurityState(context.securityState, decision);
  await store.securityState.set(context.sessionId, securityState, decisionRecord.reason);

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
