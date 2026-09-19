import type { AgentEvent, AgentContext } from '@veyra/agent-events';
import type { SecurityDecision } from '@veyra/policy-engine';
import type { Severity } from '@veyra/shared';

/**
 * Correlated behavior signal across multiple events.
 * Individual actions may look benign; the sequence is the threat.
 */
export interface BehaviorSignal {
  type: string;
  severity: Severity;
  confidence?: number;
  evidence: string[];
  relatedEventIds: string[];
}

export interface TrajectoryRule {
  id: string;
  description: string;
  evaluate(history: AgentEvent[], context: AgentContext): BehaviorSignal | null;
}

export type SemanticRisk = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SemanticAssessment {
  risk: SemanticRisk;
  category?: string;
  explanation: string;
  evidence: string[];
}

/**
 * Advisory only — must never bypass deterministic controls.
 */
export interface SemanticAnalyzer {
  analyze(events: AgentEvent[], context: AgentContext): Promise<SemanticAssessment>;
}

export interface WatchdogObservation {
  event: AgentEvent;
  policyDecisions: SecurityDecision[];
  primaryPolicy: SecurityDecision | null;
  signals: BehaviorSignal[];
  semantic: SemanticAssessment | null;
  blocked: boolean;
}

export interface WatchdogSessionSnapshot {
  sessionId: string;
  agentId: string;
  eventCount: number;
  signalCount: number;
  securityState: AgentContext['securityState'];
  recentSignals: BehaviorSignal[];
}
