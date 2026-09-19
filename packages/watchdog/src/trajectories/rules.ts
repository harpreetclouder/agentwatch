import type { AgentContext, AgentEvent } from '@jev/agent-events';
import { classifySecretPath } from '@jev/policy-engine';
import type { BehaviorSignal, TrajectoryRule } from '../types.js';

function targetOf(event: AgentEvent): string {
  return event.action.target ?? event.action.name;
}

function isReadme(event: AgentEvent): boolean {
  const t = targetOf(event).toLowerCase();
  return event.type === 'file_read' && (t.endsWith('readme.md') || t.includes('readme'));
}

function isInjectionSignal(event: AgentEvent): boolean {
  if (event.type === 'security_event') {
    const name = event.action.name.toLowerCase();
    return name.includes('injection') || name.includes('prompt_injection');
  }
  return false;
}

function isSecretAccess(event: AgentEvent): boolean {
  if (!['file_read', 'file_write', 'shell', 'tool_call'].includes(event.type)) {
    return false;
  }
  const target = targetOf(event);
  return classifySecretPath(target) !== null;
}

function isNetworkEscape(event: AgentEvent): boolean {
  if (event.type !== 'network') {
    return false;
  }
  const target = targetOf(event).toLowerCase();
  return (
    target.includes('evil.') ||
    target.includes('exfil') ||
    target.startsWith('http://') ||
    target.startsWith('https://')
  );
}

/**
 * README / injection marker followed by secret access in the same session.
 */
export const injectionThenSecretRule: TrajectoryRule = {
  id: 'TRAJECTORY_INJECTION_THEN_SECRET',
  description: 'Prompt-injection surface followed by credential/secret access',

  evaluate(history: AgentEvent[], _context: AgentContext): BehaviorSignal | null {
    if (history.length < 2) {
      return null;
    }

    const latest = history[history.length - 1]!;
    if (!isSecretAccess(latest)) {
      return null;
    }

    const prior = history.slice(0, -1);
    const injectionEvents = prior.filter((e) => isReadme(e) || isInjectionSignal(e));
    if (injectionEvents.length === 0) {
      return null;
    }

    const related = [...injectionEvents.map((e) => e.id), latest.id];

    return {
      type: 'injection_then_secret_access',
      severity: 'HIGH',
      confidence: 0.9,
      evidence: [
        'prior_suspicious_repository_instruction',
        `secret_target=${targetOf(latest)}`,
        `prior_events=${injectionEvents.length}`,
        'trajectory=readme_or_injection→secret_access',
      ],
      relatedEventIds: related,
    };
  },
};

/**
 * Multiple distinct secret stores touched in one session (.env then AWS/SSH).
 */
export const credentialChainRule: TrajectoryRule = {
  id: 'TRAJECTORY_CREDENTIAL_CHAIN',
  description: 'Sequential access across multiple credential stores',

  evaluate(history: AgentEvent[], _context: AgentContext): BehaviorSignal | null {
    const secretEvents = history.filter(isSecretAccess);
    if (secretEvents.length < 2) {
      return null;
    }

    const categories = new Set(
      secretEvents
        .map((e) => classifySecretPath(targetOf(e))?.category)
        .filter((c): c is string => Boolean(c)),
    );

    // Also treat distinct basenames as a chain
    const labels = new Set(
      secretEvents.map((e) => (classifySecretPath(targetOf(e))?.label ?? '').toLowerCase()),
    );

    if (categories.size < 2 && labels.size < 2) {
      return null;
    }

    const latest = history[history.length - 1]!;
    if (!isSecretAccess(latest)) {
      return null;
    }

    return {
      type: 'credential_access_chain',
      severity: 'HIGH',
      confidence: 0.85,
      evidence: [
        `secret_events=${secretEvents.length}`,
        `categories=${[...categories].join(',')}`,
        `labels=${[...labels].join(',')}`,
        'trajectory=multi_credential_store_access',
      ],
      relatedEventIds: secretEvents.map((e) => e.id),
    };
  },
};

/**
 * Secret access followed by outbound network — exfiltration trajectory.
 */
export const secretThenNetworkRule: TrajectoryRule = {
  id: 'TRAJECTORY_SECRET_THEN_NETWORK',
  description: 'Secret access followed by external network request',

  evaluate(history: AgentEvent[], _context: AgentContext): BehaviorSignal | null {
    if (history.length < 2) {
      return null;
    }

    const latest = history[history.length - 1]!;
    if (!isNetworkEscape(latest)) {
      return null;
    }

    const priorSecrets = history.slice(0, -1).filter(isSecretAccess);
    if (priorSecrets.length === 0) {
      return null;
    }

    return {
      type: 'secret_then_network_exfil',
      severity: 'CRITICAL',
      confidence: 0.95,
      evidence: [
        `network_target=${targetOf(latest)}`,
        `prior_secret_accesses=${priorSecrets.length}`,
        'trajectory=secret_access→external_network',
      ],
      relatedEventIds: [...priorSecrets.map((e) => e.id), latest.id],
    };
  },
};

export function createDefaultTrajectoryRules(): TrajectoryRule[] {
  return [injectionThenSecretRule, credentialChainRule, secretThenNetworkRule];
}
