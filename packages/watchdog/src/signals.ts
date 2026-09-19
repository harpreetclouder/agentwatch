import type { SecurityDecision } from '@jev/policy-engine';
import type { BehaviorSignal } from './types.js';

/**
 * Convert a trajectory signal into a SecurityDecision when severity warrants enforcement.
 * Does not replace policy engine — supplements it for multi-event patterns.
 */
export function signalToDecision(
  signal: BehaviorSignal,
  eventId: string,
): SecurityDecision | null {
  if (signal.severity === 'LOW') {
    return null;
  }

  const decision =
    signal.severity === 'CRITICAL'
      ? 'QUARANTINE'
      : signal.severity === 'HIGH'
        ? 'BLOCK'
        : 'WARN';

  return {
    decision,
    severity: signal.severity,
    ruleId: `WATCHDOG_${signal.type.toUpperCase()}`,
    reason: `Trajectory signal: ${signal.type}. Correlated behavior exceeds single-event risk.`,
    evidence: signal.evidence,
    eventId,
  };
}
