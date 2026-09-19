import { createAgentEvent, type AgentEvent, type AgentEventType } from '@jev/agent-events';
import { createId } from '@jev/shared';
import type { SecurityDecision } from '@jev/policy-engine';
import type { BehaviorSignal } from '@jev/watchdog';
import type { AttackContext, AttackResult } from '../types.js';
import { simulateEvent, type SimulatedStepResult } from '../simulator.js';

export type AttackRunState = {
  events: AgentEvent[];
  decisions: SecurityDecision[];
  signals: BehaviorSignal[];
  evidence: string[];
  started: number;
};

export function createRunState(): AttackRunState {
  return {
    events: [],
    decisions: [],
    signals: [],
    evidence: [],
    started: Date.now(),
  };
}

export function eventBase(context: AttackContext, taskId: string, taskDescription: string) {
  return {
    sessionId: context.sessionId,
    agentId: context.agentId,
    context: {
      taskId,
      taskDescription,
      cwd: context.labRoot,
    },
  };
}

export async function step(
  context: AttackContext,
  state: AttackRunState,
  partial: {
    type: AgentEventType;
    action: AgentEvent['action'];
    offsetMs?: number;
    metadata?: Record<string, unknown>;
  },
): Promise<SimulatedStepResult> {
  const event = createAgentEvent({
    ...eventBase(
      context,
      context.agentContext.task?.id ?? 'task_auth',
      context.agentContext.task?.description ?? 'Fix authentication bug',
    ),
    id: createId('evt'),
    type: partial.type,
    action: partial.action,
    timestamp: new Date(Date.now() + (partial.offsetMs ?? 0)).toISOString(),
    ...(partial.metadata ? { metadata: partial.metadata } : {}),
  });

  const result = await simulateEvent(context.watchdog, event, context.agentContext);
  state.events.push(result.event);
  state.decisions.push(...result.decisions);
  state.signals.push(...result.signals);
  return result;
}

export function finishResult(
  attack: { id: string; name: string; category: AttackResult['category'] },
  state: AttackRunState,
  contained: boolean,
): AttackResult {
  return {
    attackId: attack.id,
    name: attack.name,
    category: attack.category,
    passed: contained,
    contained,
    evidence: state.evidence,
    events: state.events,
    decisions: state.decisions,
    signals: state.signals,
    durationMs: Date.now() - state.started,
  };
}

export function hasRule(
  state: AttackRunState,
  ruleId: string,
  decision?: SecurityDecision['decision'],
): boolean {
  return state.decisions.some(
    (d) => d.ruleId === ruleId && (decision === undefined || d.decision === decision),
  );
}
