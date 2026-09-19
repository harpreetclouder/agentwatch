import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { Policy, PolicyEvaluationResult, SecurityDecision } from './types.js';
import { pickPrimaryDecision } from './enforcement.js';
import { createDefaultPolicies } from './policies/index.js';

export type PolicyEngineOptions = {
  policies?: Policy[];
};

/**
 * Deterministic policy engine.
 * LLMs must not be the sole authority for hard security decisions.
 */
export class PolicyEngine {
  private readonly policies: Policy[];

  constructor(options: PolicyEngineOptions = {}) {
    this.policies = options.policies ?? createDefaultPolicies();
  }

  listPolicies(): Policy[] {
    return [...this.policies];
  }

  evaluate(event: AgentEvent, context: AgentContext): PolicyEvaluationResult {
    const decisions: SecurityDecision[] = [];

    for (const policy of this.policies) {
      const decision = policy.evaluate(event, context);
      if (decision) {
        decisions.push(decision);
      }
    }

    return {
      decisions,
      primary: pickPrimaryDecision(decisions),
    };
  }
}
