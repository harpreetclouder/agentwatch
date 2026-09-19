import type { AgentEvent, AgentContext } from '@veyra/agent-events';
import type { SecurityDecision } from '@veyra/policy-engine';
import type { SecurityState, Severity } from '@veyra/shared';
import type { VeyraStore } from '@veyra/storage';
import type { BehaviorSignal, Watchdog } from '@veyra/watchdog';

export type AttackCategory =
  | 'prompt-injection'
  | 'credential-access'
  | 'secret-exfiltration'
  | 'dangerous-shell'
  | 'privilege-escalation'
  | 'task-deviation'
  | 'mcp-tool-poisoning'
  | 'production-access'
  | 'authority-escalation'
  | 'control-plane-tampering';

export type AttackMode = 'simulation' | 'runtime';

export type DecisionOutcome = SecurityDecision['decision'];

/**
 * Stage 7 attack definition — shared metadata for simulation and runtime labs.
 * Simulation uses `execute()` + simulateEvent.
 * Runtime uses real hooks and must never call simulateEvent().
 */
export interface Attack {
  id: string;
  name: string;
  category: AttackCategory;
  severity: Severity;
  description: string;
  expectedPolicy: string;
  expectedDecision: DecisionOutcome;
  expectedFinalState: SecurityState;
  simulationSupported: boolean;
  runtimeSupported: boolean;
  /** Simulation path only — synthetic AgentEvents through Watchdog. */
  execute(context: AttackContext): Promise<AttackResult>;
}

export interface AttackContext {
  agentId: string;
  agentName: string;
  sessionId: string;
  workingDirectory: string;
  store: VeyraStore;
  agentContext: AgentContext;
  labRoot: string;
  watchdog: Watchdog;
}

export interface AttackResult {
  attackId: string;
  name: string;
  category: AttackCategory;
  passed: boolean;
  contained: boolean;
  evidence: string[];
  events: AgentEvent[];
  decisions: SecurityDecision[];
  signals: BehaviorSignal[];
  durationMs: number;
}

export interface AttackRunSummary {
  sessionId: string;
  agentName: string;
  mode: AttackMode;
  results: AttackResult[];
  containedCount: number;
  totalCount: number;
  durationMs: number;
  startedAt: string;
  finishedAt: string;
}

export interface SecurityReport {
  title: string;
  agentName: string;
  sessionId: string;
  task: string;
  finalState: string;
  violations: Array<{
    event: string;
    decision: string;
    severity: string;
    rule: string;
    why: string;
    evidence: string[];
  }>;
  timeline: Array<{
    timestamp: string;
    type: string;
    target: string;
    mark: 'ok' | 'warn' | 'block';
  }>;
  signals: Array<{
    type: string;
    severity: string;
    evidence: string[];
  }>;
  summaryLine: string;
}

/** Checklist line for Stage 7 runtime / simulation operator output. */
export type AttackCheck = {
  label: string;
  ok: boolean;
};

export type RuntimeAttackResult = {
  attackId: string;
  name: string;
  scenario: string;
  agent: string;
  mode: 'runtime';
  contained: boolean;
  checks: AttackCheck[];
  expectedPolicy: string;
  expectedDecision: string;
  expectedFinalState: string;
  observedPolicy: string | null;
  observedDecision: string | null;
  observedFinalState: string | null;
  evidenceRecorded: boolean;
  disclaimer: string;
};
