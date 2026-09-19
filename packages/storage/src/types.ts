import type { Environment, SecurityState, Severity } from '@veyra/shared';

/** Persisted agent identity row (Passport precursor). */
export interface AgentRecord {
  id: string;
  name: string;
  runtime: string;
  model: string | null;
  createdAt: string;
  updatedAt: string;
}

export type SessionStatus = 'ACTIVE' | 'IDLE' | 'ENDED' | 'QUARANTINED';

/** Active observation / enforcement session. */
export interface SessionRecord {
  id: string;
  agentId: string;
  taskId: string | null;
  taskDescription: string | null;
  workingDirectory: string;
  environment: Environment;
  status: SessionStatus;
  securityState: SecurityState;
  startedAt: string;
  endedAt: string | null;
}

export type DecisionOutcome = 'ALLOW' | 'WARN' | 'BLOCK' | 'QUARANTINE';

/**
 * Evidence-backed security decision.
 * Matches the policy-engine contract; storage adds a stable id.
 */
export interface SecurityDecisionRecord {
  id: string;
  sessionId: string;
  eventId: string;
  decision: DecisionOutcome;
  severity: Severity;
  ruleId: string;
  reason: string;
  evidence: string[];
  createdAt: string;
}

export interface ViolationRecord {
  id: string;
  sessionId: string;
  decisionId: string;
  eventId: string;
  ruleId: string;
  severity: Severity;
  summary: string;
  createdAt: string;
}

export interface SecurityStateRecord {
  sessionId: string;
  state: SecurityState;
  reason: string | null;
  updatedAt: string;
}

export interface SessionStats {
  sessionId: string;
  events: number;
  warnings: number;
  blocks: number;
  critical: number;
}
