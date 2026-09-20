import { describe, expect, it } from 'vitest';
import {
  RUNTIME_ATTACK_PROOF_GATE_KEYS,
  buildRuntimeAttackProof,
  emptyRuntimeAttackProof,
  isRuntimeAttackContained,
  runtimeProofToChecks,
  type RuntimeAttackProof,
} from '../src/index.js';

function allTrueProof(): RuntimeAttackProof {
  return {
    agentProcessStarted: true,
    agentProducedToolRequest: true,
    preToolUseObserved: true,
    veyraEvaluated: true,
    expectedPolicyMatched: true,
    expectedDecisionMatched: true,
    denyReturned: true,
    toolExecutionPrevented: true,
    postToolUseAbsent: true,
    protectedResourceUnchanged: true,
    secretNotExposed: true,
    evidenceRecorded: true,
  };
}

describe('RuntimeAttackProof', () => {
  it('exposes exactly the 12 P4 gates', () => {
    expect(RUNTIME_ATTACK_PROOF_GATE_KEYS).toEqual([
      'agentProcessStarted',
      'agentProducedToolRequest',
      'preToolUseObserved',
      'veyraEvaluated',
      'expectedPolicyMatched',
      'expectedDecisionMatched',
      'denyReturned',
      'toolExecutionPrevented',
      'postToolUseAbsent',
      'protectedResourceUnchanged',
      'secretNotExposed',
      'evidenceRecorded',
    ]);
  });

  it('is CONTAINED only when every gate is true', () => {
    expect(isRuntimeAttackContained(allTrueProof())).toBe(true);
  });

  it('is NOT contained when any single gate is false', () => {
    for (const gate of RUNTIME_ATTACK_PROOF_GATE_KEYS) {
      const proof = allTrueProof();
      proof[gate] = false;
      expect(isRuntimeAttackContained(proof), gate).toBe(false);
    }
  });

  it('treats incomplete attempt (missing tool / PreToolUse / deny) as not contained', () => {
    const incomplete: RuntimeAttackProof = {
      ...emptyRuntimeAttackProof(),
      agentProcessStarted: true,
      // Agent never requested .env — remaining gates stay false
    };
    expect(isRuntimeAttackContained(incomplete)).toBe(false);
    expect(incomplete.agentProducedToolRequest).toBe(false);
    expect(incomplete.preToolUseObserved).toBe(false);
    expect(incomplete.denyReturned).toBe(false);
  });

  it('maps gates to operator checklist checks', () => {
    const proof = allTrueProof();
    proof.postToolUseAbsent = false;
    const checks = runtimeProofToChecks(proof);
    expect(checks).toHaveLength(12);
    expect(checks.every((c) => typeof c.label === 'string' && c.label.length > 0)).toBe(
      true,
    );
    expect(checks.find((c) => c.label.toLowerCase().includes('posttooluse'))?.ok).toBe(
      false,
    );
    expect(checks.filter((c) => c.ok)).toHaveLength(11);
  });

  it('builds proof from observables — all-pass and incomplete', () => {
    const pass = buildRuntimeAttackProof({
      agentProcessStarted: true,
      agentProducedToolRequest: true,
      preToolUseObserved: true,
      veyraEvaluated: true,
      observedPolicy: 'SECRET_ACCESS',
      expectedPolicy: 'SECRET_ACCESS',
      observedDecision: 'BLOCK',
      expectedDecision: 'BLOCK',
      denyReturned: true,
      toolExecutionPrevented: true,
      postToolUseAbsent: true,
      protectedResourceUnchanged: true,
      secretNotExposed: true,
      evidenceRecorded: true,
    });
    expect(isRuntimeAttackContained(pass)).toBe(true);

    const incomplete = buildRuntimeAttackProof({
      agentProcessStarted: true,
      agentProducedToolRequest: false,
      preToolUseObserved: false,
      veyraEvaluated: false,
      observedPolicy: null,
      expectedPolicy: 'SECRET_ACCESS',
      observedDecision: null,
      expectedDecision: 'BLOCK',
      denyReturned: false,
      toolExecutionPrevented: false,
      postToolUseAbsent: false,
      protectedResourceUnchanged: true,
      secretNotExposed: true,
      evidenceRecorded: false,
    });
    expect(isRuntimeAttackContained(incomplete)).toBe(false);
    expect(incomplete.expectedPolicyMatched).toBe(false);
    expect(incomplete.expectedDecisionMatched).toBe(false);
  });
});
