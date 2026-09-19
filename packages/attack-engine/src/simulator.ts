import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { SecurityDecision } from '@jev/policy-engine';
import type { BehaviorSignal, Watchdog } from '@jev/watchdog';

export type SimulatedStepResult = {
  event: AgentEvent;
  decisions: SecurityDecision[];
  primary: SecurityDecision | null;
  signals: BehaviorSignal[];
  blocked: boolean;
};

/**
 * Run a simulated agent event through the Watchdog
 * (policies + trajectory correlation + optional advisory semantic).
 */
export async function simulateEvent(
  watchdog: Watchdog,
  event: AgentEvent,
  context: AgentContext,
): Promise<SimulatedStepResult> {
  const observation = await watchdog.observe(event, context);

  return {
    event: observation.event,
    decisions: observation.policyDecisions,
    primary: observation.primaryPolicy,
    signals: observation.signals,
    blocked: observation.blocked,
  };
}
