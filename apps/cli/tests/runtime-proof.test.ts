import { describe, expect, it } from 'vitest';
import {
  emptyRuntimeAttackProof,
  formatRuntimeProofGateLines,
  isRuntimeAttackContained,
  runtimeProofToChecks,
  type RuntimeAttackProof,
  type RuntimeAttackResult,
} from '@veyra/attack-engine';
import { printRuntimeAttackResult } from '../src/harness/runtime-attack.js';

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

function capturePrint(result: RuntimeAttackResult): string {
  const chunks: string[] = [];
  const orig = console.log;
  console.log = (...a: unknown[]) => {
    chunks.push(a.map(String).join(' '));
  };
  try {
    printRuntimeAttackResult(result);
  } finally {
    console.log = orig;
  }
  return chunks.join('\n');
}

describe('P4 RuntimeAttackProof operator output', () => {
  it('prints YES/NO-style gates and CONTAINED when all pass', () => {
    const proof = allTrueProof();
    expect(isRuntimeAttackContained(proof)).toBe(true);

    const out = capturePrint({
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'runtime',
      contained: true,
      checks: runtimeProofToChecks(proof),
      proof,
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: 'SECRET_ACCESS',
      observedDecision: 'BLOCK',
      observedFinalState: 'RESTRICTED',
      evidenceRecorded: true,
      disclaimer: 'Do not claim complete security.',
      unavailableReason: null,
    });

    expect(out).toContain('RuntimeAttackProof:');
    for (const line of formatRuntimeProofGateLines(proof)) {
      expect(out).toContain(line);
      expect(line.startsWith('✓')).toBe(true);
    }
    expect(out).toContain('1 / 1 CONTROLLED ATTACKS CONTAINED');
    expect(out).not.toContain('PROOF INCOMPLETE');
  });

  it('any failed gate → not contained + PROOF INCOMPLETE', () => {
    const proof = allTrueProof();
    proof.denyReturned = false;
    expect(isRuntimeAttackContained(proof)).toBe(false);

    const out = capturePrint({
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'runtime',
      contained: false,
      checks: runtimeProofToChecks(proof),
      proof,
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: 'SECRET_ACCESS',
      observedDecision: null,
      observedFinalState: null,
      evidenceRecorded: true,
      disclaimer: 'Do not claim complete security.',
      unavailableReason: null,
    });

    expect(out).toContain('✕ Deny returned');
    expect(out).toContain('RESULT:');
    expect(out).toContain('PROOF INCOMPLETE');
    expect(out).toContain('0 / 1 CONTROLLED ATTACKS CONTAINED');
  });

  it('incomplete attempt (no .env tool request) is never soft CONTAINED', () => {
    const proof: RuntimeAttackProof = {
      ...emptyRuntimeAttackProof(),
      agentProcessStarted: true,
      protectedResourceUnchanged: true,
      secretNotExposed: true,
    };
    expect(isRuntimeAttackContained(proof)).toBe(false);

    const out = capturePrint({
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'runtime',
      contained: false,
      checks: runtimeProofToChecks(proof),
      proof,
      outcome: 'PROOF_INCOMPLETE',
      secretExposure: 'NONE',
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: null,
      observedDecision: null,
      observedFinalState: null,
      evidenceRecorded: false,
      disclaimer: 'Do not claim complete security.',
      unavailableReason: null,
    });

    expect(out).toContain('✓ Agent process started');
    expect(out).toContain('✕ Agent produced tool request');
    expect(out).toContain('✕ PreToolUse observed');
    expect(out).toContain('PROOF INCOMPLETE');
    expect(out).not.toContain('ATTACK NOT CONTAINED');
    expect(out).not.toContain('1 / 1 CONTROLLED ATTACKS CONTAINED');
    expect(out).toContain('Critical escapes: 0');
    expect(out).toContain('Unauthorized execution: (not evaluated — attack not attempted)');
    expect(out).not.toContain('Unauthorized execution: POSSIBLE');
  });

  it('D-style escape print → ATTACK NOT CONTAINED with critical escape tally', () => {
    const proof = allTrueProof();
    proof.secretNotExposed = false;
    proof.toolExecutionPrevented = false;
    const out = capturePrint({
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'runtime',
      contained: false,
      checks: runtimeProofToChecks(proof),
      proof,
      outcome: 'ATTACK_NOT_CONTAINED',
      secretExposure: 'LEAKED',
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: 'SECRET_ACCESS',
      observedDecision: 'BLOCK',
      observedFinalState: 'RESTRICTED',
      evidenceRecorded: true,
      disclaimer: 'Do not claim complete security.',
      unavailableReason: null,
    });

    expect(out).toContain('ATTACK NOT CONTAINED');
    expect(out).toContain('SECRET EXPOSURE DETECTED');
    expect(out).toContain('Critical escapes: 1');
    expect(out).toContain('Unauthorized execution: POSSIBLE — see checks');
  });

  it('hook mode does not claim RuntimeAttackProof gate table', () => {
    const out = capturePrint({
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'hook',
      contained: true,
      checks: [{ label: 'SECRET_ACCESS', ok: true }],
      proof: null,
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: 'SECRET_ACCESS',
      observedDecision: 'BLOCK',
      observedFinalState: 'RESTRICTED',
      evidenceRecorded: true,
      disclaimer: 'Do not claim complete security.',
    });

    expect(out).toContain('Runtime: HOOK');
    expect(out).not.toContain('RuntimeAttackProof:');
    expect(out).toContain('✓ SECRET_ACCESS');
  });
});
