import type { AgentEvent, AgentContext } from '@veyra/agent-events';
import type { SecurityDecision } from '@veyra/policy-engine';
import type { SecurityState, Severity } from '@veyra/shared';
import type { VeyraStore } from '@veyra/storage';
import type { BehaviorSignal, Watchdog } from '@veyra/watchdog';
import type {
  RuntimeAttackProof,
  RuntimeOutcome,
  RuntimeTimelineStep,
} from './runtime-proof.js';

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

export type AttackMode = 'simulation' | 'hook' | 'runtime';

export type DecisionOutcome = SecurityDecision['decision'];

/**
 * Attack definition — shared metadata for simulation, hook, and runtime labs.
 * Simulation uses `execute()` + simulateEvent.
 * Hook uses real PreToolUse wire format via `veyra hook` (never simulateEvent).
 * Runtime uses live Claude Code (never fakes success; never simulateEvent).
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
  /** Real PreToolUse hook path and/or live Claude runtime. */
  runtimeSupported: boolean;
  /** Canonical live-agent user task (injection-free). */
  task?: string;
  /** Fixture workspace hint (e.g. real-agent-demo). */
  fixture?: string;
  /** Expected blocked tool name (e.g. Read). */
  expectedTool?: string;
  /** Expected blocked resource (e.g. .env). */
  expectedResource?: string;
  /** High-level expected trajectory labels. */
  expectedTrajectory?: string[];
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

/** Honest operator label — never upgrades mode (P8 shareable reports). */
export type RuntimeHonesty = 'LIVE' | 'HOOK' | 'SIMULATION' | 'UNAVAILABLE';

export type ReportTestResult = {
  id: string;
  name: string;
  category: string;
  contained: boolean;
};

export type ReportCategoryTally = {
  category: string;
  contained: number;
  total: number;
};

export type ReportTopFinding = {
  name: string;
  category: string;
  rule: string;
  decision: string;
  outcome: 'contained' | 'not-contained';
};

export interface SecurityReport {
  title: string;
  agentName: string;
  sessionId: string;
  task: string;
  finalState: string;
  /** Concrete containment counts — never percentage "security scores". */
  containedCount: number;
  escapedCount: number;
  totalCount: number;
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
  /** Attack lab mode that produced this report — never upgraded. */
  mode?: AttackMode;
  /** LIVE | HOOK | SIMULATION | UNAVAILABLE — shareable honesty banner. */
  runtimeHonesty?: RuntimeHonesty;
  /** Set when LIVE runtime was requested but not executed. */
  unavailableReason?: string | null;
  /** Per-test contained/not-contained rows. */
  tests?: ReportTestResult[];
  /** Category-level N/M contained tallies. */
  categoryTallies?: ReportCategoryTally[];
  /** Headline finding for viral shareable artifact. */
  topFinding?: ReportTopFinding | null;
  /** True when unauthorized tool was denied before execution. */
  blockedBeforeExecution?: boolean | null;
  /** Secret exposure status — never includes secret values. */
  secretExposure?: string;
  unauthorizedExecution?: string;
  criticalEscapes?: number;
  /** P4 RuntimeAttackProof gates when mode=runtime (null for hook/sim). */
  runtimeProof?: RuntimeAttackProof | null;
  /** User-space hooks disclaimer — do not claim complete security. */
  disclaimer?: string;
}

/** Checklist line for hook / runtime operator output. */
export type AttackCheck = {
  label: string;
  ok: boolean;
};

export type RuntimeAttackResult = {
  attackId: string;
  name: string;
  scenario: string;
  agent: string;
  /** Distinct from simulation: hook = PreToolUse wire; runtime = live Claude. */
  mode: 'hook' | 'runtime';
  contained: boolean;
  checks: AttackCheck[];
  /**
   * Strict 12-gate Level-3 proof. Present only for runtime mode when evaluated.
   * Hook mode must leave this null — never claim full RuntimeAttackProof.
   */
  proof?: RuntimeAttackProof | null;
  /** Distinct honest outcome for runtime (and optional for hook). */
  outcome?: RuntimeOutcome;
  /** Timeline from stored events — runtime only; never synthesized. */
  timeline?: RuntimeTimelineStep[];
  /** Secret exposure status — never includes secret values. */
  secretExposure?: 'NONE' | 'LEAKED' | 'UNKNOWN';
  /** Correlation ids when available. */
  correlation?: {
    sessionId: string | null;
    eventId: string | null;
    decisionId: string | null;
    toolRequestId: string | null;
  };
  expectedPolicy: string;
  expectedDecision: string;
  expectedFinalState: string;
  observedPolicy: string | null;
  observedDecision: string | null;
  observedFinalState: string | null;
  evidenceRecorded: boolean;
  disclaimer: string;
  /** Set when live Claude path was not executed. */
  unavailableReason?: string | null;
};
