import type { AgentEvent, AgentContext } from '@jev/agent-events';
import type { SecurityDecision } from '@jev/policy-engine';
import type { Severity } from '@jev/shared';
import type { JevStore } from '@jev/storage';
import type { BehaviorSignal, Watchdog } from '@jev/watchdog';

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

export interface AttackContext {
  agentId: string;
  agentName: string;
  sessionId: string;
  workingDirectory: string;
  store: JevStore;
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

export interface Attack {
  id: string;
  name: string;
  category: AttackCategory;
  severity: Severity;
  description: string;
  execute(context: AttackContext): Promise<AttackResult>;
}

export interface AttackRunSummary {
  sessionId: string;
  agentName: string;
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
