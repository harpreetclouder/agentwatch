import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Severity } from '@veyra/shared';
import type { DecisionOutcome } from '@veyra/storage';

/**
 * Evidence-backed security decision produced by a policy.
 * Persistence adds a stable id via @veyra/storage.
 */
export interface SecurityDecision {
  decision: DecisionOutcome;
  severity: Severity;
  ruleId: string;
  reason: string;
  evidence: string[];
  eventId: string;
}

export interface Policy {
  id: string;
  description: string;
  severity: Severity;
  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null;
}

export type PolicyEvaluationResult = {
  decisions: SecurityDecision[];
  /** Highest-severity non-ALLOW decision, if any. */
  primary: SecurityDecision | null;
};
