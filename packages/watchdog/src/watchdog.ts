import type { AgentContext, AgentEvent } from '@jev/agent-events';
import {
  PolicyEngine,
  persistDecision,
  pickPrimaryDecision,
  isEnforcementFrozen,
  frozenSessionDecision,
  type SecurityDecision,
} from '@jev/policy-engine';
import type { JevStore } from '@jev/storage';
import { SessionHistory } from './history.js';
import { createDefaultTrajectoryRules } from './trajectories/rules.js';
import { MockSemanticAnalyzer } from './semantic/mock.js';
import { createSemanticAnalyzer } from './semantic/factory.js';
import { signalToDecision } from './signals.js';
import type {
  BehaviorSignal,
  SemanticAnalyzer,
  TrajectoryRule,
  WatchdogObservation,
  WatchdogSessionSnapshot,
} from './types.js';

export type WatchdogOptions = {
  store?: JevStore;
  policyEngine?: PolicyEngine;
  rules?: TrajectoryRule[];
  semanticAnalyzer?: SemanticAnalyzer | null;
  /** When true (default), run mock semantic analysis after cheap checks. */
  enableSemantic?: boolean;
};

/**
 * Correlates events across a session.
 * Flow: event → deterministic policies → trajectory rules → optional advisory semantic.
 */
export class Watchdog {
  private readonly histories = new Map<string, SessionHistory>();
  private readonly signals = new Map<string, BehaviorSignal[]>();
  private readonly policyEngine: PolicyEngine;
  private readonly rules: TrajectoryRule[];
  private readonly semantic: SemanticAnalyzer | null;
  private readonly store: JevStore | undefined;

  constructor(options: WatchdogOptions = {}) {
    this.store = options.store;
    this.policyEngine = options.policyEngine ?? new PolicyEngine();
    this.rules = options.rules ?? createDefaultTrajectoryRules();
    const enableSemantic = options.enableSemantic !== false;
    if (options.semanticAnalyzer === null || !enableSemantic) {
      this.semantic = null;
    } else if (options.semanticAnalyzer !== undefined) {
      this.semantic = options.semanticAnalyzer;
    } else {
      // Env-driven: mock by default, OpenAI-compatible when JEV_SEMANTIC_API_KEY is set
      this.semantic = createSemanticAnalyzer() ?? new MockSemanticAnalyzer();
    }
  }

  getHistory(sessionId: string): SessionHistory {
    let history = this.histories.get(sessionId);
    if (!history) {
      history = new SessionHistory(sessionId);
      this.histories.set(sessionId, history);
    }
    return history;
  }

  getSignals(sessionId: string): BehaviorSignal[] {
    return [...(this.signals.get(sessionId) ?? [])];
  }

  snapshot(context: AgentContext): WatchdogSessionSnapshot {
    const history = this.getHistory(context.sessionId);
    const recentSignals = this.getSignals(context.sessionId);
    return {
      sessionId: context.sessionId,
      agentId: context.agentId,
      eventCount: history.size(),
      signalCount: recentSignals.length,
      securityState: context.securityState,
      recentSignals: recentSignals.slice(-5),
    };
  }

  /**
   * Observe one event: persist (optional), evaluate policies + trajectories.
   * Frozen sessions (QUARANTINED / REVOKED) hard-deny further tool-like actions.
   */
  async observe(event: AgentEvent, context: AgentContext): Promise<WatchdogObservation> {
    const history = this.getHistory(context.sessionId);
    history.append(event);

    if (this.store) {
      await this.store.events.append(event);
    }

    // Frozen gate — operator must resume; agent cannot self-clear
    if (isEnforcementFrozen(context.securityState)) {
      const frozen = frozenSessionDecision(event, context);
      if (this.store) {
        const persisted = await persistDecision(this.store, frozen, context);
        context.securityState = persisted.securityState;
      }
      return {
        event,
        policyDecisions: [frozen],
        primaryPolicy: frozen,
        signals: [],
        semantic: null,
        blocked: true,
      };
    }

    // 1. Cheap deterministic per-event policies
    const policyResult = this.policyEngine.evaluate(event, context);
    const policyDecisions = [...policyResult.decisions];

    // 2. Trajectory correlation on session history
    const newSignals: BehaviorSignal[] = [];
    for (const rule of this.rules) {
      const signal = rule.evaluate([...history.all()], context);
      if (signal) {
        // Deduplicate identical type for the same related set
        const existing = this.signals.get(context.sessionId) ?? [];
        const duplicate = existing.some(
          (s) =>
            s.type === signal.type &&
            s.relatedEventIds.join(',') === signal.relatedEventIds.join(','),
        );
        if (!duplicate) {
          newSignals.push(signal);
          existing.push(signal);
          this.signals.set(context.sessionId, existing);
        }
      }
    }

    // Trajectory signals may yield additional decisions (never weaken policy BLOCK)
    const trajectoryDecisions: SecurityDecision[] = [];
    for (const signal of newSignals) {
      const decision = signalToDecision(signal, event.id);
      if (decision) {
        trajectoryDecisions.push(decision);
      }
    }

    const allDecisions = [...policyDecisions, ...trajectoryDecisions];
    const primaryPolicy = pickPrimaryDecision(allDecisions);

    if (this.store) {
      for (const decision of allDecisions) {
        if (decision.decision === 'ALLOW') {
          continue;
        }
        const persisted = await persistDecision(this.store, decision, context);
        context.securityState = persisted.securityState;
      }
    } else if (primaryPolicy && primaryPolicy.decision !== 'ALLOW') {
      if (primaryPolicy.decision === 'QUARANTINE' || primaryPolicy.severity === 'CRITICAL') {
        context.securityState = 'QUARANTINED';
      } else if (primaryPolicy.decision === 'BLOCK' || primaryPolicy.severity === 'HIGH') {
        if (context.securityState === 'NORMAL' || context.securityState === 'WARNING') {
          context.securityState = 'RESTRICTED';
        }
      } else if (primaryPolicy.decision === 'WARN' && context.securityState === 'NORMAL') {
        context.securityState = 'WARNING';
      }
    }

    // 3. Advisory semantic — NEVER sets blocked; never sole authority
    let semantic = null;
    if (this.semantic && primaryPolicy?.decision !== 'QUARANTINE') {
      semantic = await this.semantic.analyze([...history.all()], context);
    }

    // Enforcement comes ONLY from deterministic policy / trajectory decisions
    const blocked =
      primaryPolicy?.decision === 'BLOCK' || primaryPolicy?.decision === 'QUARANTINE';

    return {
      event,
      policyDecisions: allDecisions,
      primaryPolicy,
      signals: newSignals,
      semantic,
      blocked,
    };
  }
}
