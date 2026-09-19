import type { Severity } from '@veyra/shared';
import { severityRank } from '@veyra/shared';
import type { DecisionOutcome } from '@veyra/storage';
import type { SecurityState } from '@veyra/shared';
import type { SecurityDecision } from './types.js';

/**
 * Map policy severity to a default enforcement outcome.
 * Severity overrides strike counts (progressive model precursor).
 */
export function defaultDecisionForSeverity(severity: Severity): DecisionOutcome {
  switch (severity) {
    case 'LOW':
      return 'WARN';
    case 'MEDIUM':
      return 'WARN';
    case 'HIGH':
      return 'BLOCK';
    case 'CRITICAL':
      return 'QUARANTINE';
  }
}

/**
 * Progressive enforcement: escalate state from a decision.
 * CRITICAL always quarantines immediately.
 */
export function nextSecurityState(
  current: SecurityState,
  decision: SecurityDecision,
): SecurityState {
  if (decision.decision === 'QUARANTINE' || decision.severity === 'CRITICAL') {
    return 'QUARANTINED';
  }

  if (current === 'REVOKED' || current === 'QUARANTINED') {
    return current;
  }

  if (decision.decision === 'BLOCK' || decision.severity === 'HIGH') {
    return current === 'RESTRICTED' ? 'RESTRICTED' : 'RESTRICTED';
  }

  if (decision.decision === 'WARN' || decision.severity === 'MEDIUM' || decision.severity === 'LOW') {
    if (current === 'NORMAL') {
      return 'WARNING';
    }
    if (current === 'WARNING') {
      return 'RESTRICTED';
    }
    return current;
  }

  return current;
}

export function pickPrimaryDecision(
  decisions: SecurityDecision[],
): SecurityDecision | null {
  if (decisions.length === 0) {
    return null;
  }

  const rank = (d: SecurityDecision): number => {
    const severity = severityRank(d.severity) * 10;
    const outcome =
      d.decision === 'QUARANTINE'
        ? 4
        : d.decision === 'BLOCK'
          ? 3
          : d.decision === 'WARN'
            ? 2
            : 1;
    return severity + outcome;
  };

  return [...decisions].sort((a, b) => rank(b) - rank(a))[0] ?? null;
}
