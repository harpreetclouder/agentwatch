import type { AgentEvent } from '@jev/agent-events';

/**
 * In-memory session history for trajectory correlation.
 * Persistence remains in @jev/storage; this is the hot path view.
 */
export class SessionHistory {
  private readonly events: AgentEvent[] = [];

  constructor(readonly sessionId: string) {}

  append(event: AgentEvent): void {
    if (event.sessionId !== this.sessionId) {
      throw new Error(
        `Event session ${event.sessionId} does not match history ${this.sessionId}`,
      );
    }
    this.events.push(event);
  }

  all(): readonly AgentEvent[] {
    return this.events;
  }

  size(): number {
    return this.events.length;
  }

  findByType(type: AgentEvent['type']): AgentEvent[] {
    return this.events.filter((e) => e.type === type);
  }

  clear(): void {
    this.events.length = 0;
  }
}
