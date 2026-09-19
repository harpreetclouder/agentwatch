import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { SemanticAnalyzer, SemanticAssessment } from '../types.js';

/**
 * Local mock — advisory only. Hard policies work without this.
 */
export class MockSemanticAnalyzer implements SemanticAnalyzer {
  async analyze(events: AgentEvent[], context: AgentContext): Promise<SemanticAssessment> {
    const latest = events[events.length - 1];
    if (!latest) {
      return {
        risk: 'LOW',
        explanation: 'No events to analyze.',
        evidence: [],
      };
    }

    const blob = `${latest.type} ${latest.action.name} ${latest.action.target ?? ''}`.toLowerCase();

    if (blob.includes('prompt_injection') || blob.includes('injection')) {
      return {
        risk: 'MEDIUM',
        category: 'prompt_injection',
        explanation:
          'Advisory: content resembles a prompt-injection instruction surface. Deterministic policies remain authoritative.',
        evidence: [`event=${latest.id}`, `task=${context.task?.id ?? 'none'}`],
      };
    }

    if (blob.includes('.env') || blob.includes('credential')) {
      return {
        risk: 'HIGH',
        category: 'credential_access',
        explanation:
          'Advisory: event appears related to credential material. Enforce via SECRET_ACCESS, not this assessment.',
        evidence: [`event=${latest.id}`],
      };
    }

    return {
      risk: 'LOW',
      explanation: 'Advisory: no elevated semantic risk heuristics matched.',
      evidence: [`event=${latest.id}`],
    };
  }
}
