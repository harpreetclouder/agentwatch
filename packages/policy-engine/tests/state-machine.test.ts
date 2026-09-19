import { describe, expect, it } from 'vitest';
import {
  defaultDecisionForSeverity,
  nextSecurityState,
  type SecurityDecision,
} from '../src/index.js';

function decision(
  partial: Pick<SecurityDecision, 'decision' | 'severity'> &
    Partial<Omit<SecurityDecision, 'decision' | 'severity'>>,
): SecurityDecision {
  return {
    ruleId: 'TEST',
    reason: 'test',
    evidence: [],
    eventId: 'e1',
    ...partial,
  };
}

describe('security state machine', () => {
  it('maps severity to default decisions', () => {
    expect(defaultDecisionForSeverity('LOW')).toBe('WARN');
    expect(defaultDecisionForSeverity('MEDIUM')).toBe('WARN');
    expect(defaultDecisionForSeverity('HIGH')).toBe('BLOCK');
    expect(defaultDecisionForSeverity('CRITICAL')).toBe('QUARANTINE');
  });

  it('LOW / MEDIUM escalate NORMAL → WARNING', () => {
    expect(nextSecurityState('NORMAL', decision({ decision: 'WARN', severity: 'LOW' }))).toBe(
      'WARNING',
    );
    expect(nextSecurityState('NORMAL', decision({ decision: 'WARN', severity: 'MEDIUM' }))).toBe(
      'WARNING',
    );
  });

  it('HIGH escalates to RESTRICTED', () => {
    expect(nextSecurityState('NORMAL', decision({ decision: 'BLOCK', severity: 'HIGH' }))).toBe(
      'RESTRICTED',
    );
    expect(nextSecurityState('WARNING', decision({ decision: 'BLOCK', severity: 'HIGH' }))).toBe(
      'RESTRICTED',
    );
  });

  it('CRITICAL escalates to QUARANTINED from any non-terminal state', () => {
    expect(
      nextSecurityState('NORMAL', decision({ decision: 'QUARANTINE', severity: 'CRITICAL' })),
    ).toBe('QUARANTINED');
    expect(
      nextSecurityState('RESTRICTED', decision({ decision: 'ALLOW', severity: 'CRITICAL' })),
    ).toBe('QUARANTINED');
  });

  it('QUARANTINED and REVOKED persist (no self-clear)', () => {
    expect(
      nextSecurityState('QUARANTINED', decision({ decision: 'ALLOW', severity: 'LOW' })),
    ).toBe('QUARANTINED');
    expect(
      nextSecurityState('REVOKED', decision({ decision: 'WARN', severity: 'MEDIUM' })),
    ).toBe('REVOKED');
  });

  it('second WARN from WARNING escalates to RESTRICTED', () => {
    expect(nextSecurityState('WARNING', decision({ decision: 'WARN', severity: 'LOW' }))).toBe(
      'RESTRICTED',
    );
  });
});
