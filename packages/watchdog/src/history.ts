import type { AgentEvent } from '@veyra/agent-events';

const DEFAULT_MAX_EVENTS = 500;

/**
 * In-memory session history for trajectory correlation.
 * Bounded to avoid unbounded memory growth.
 */
export class SessionHistory {
  private readonly events: AgentEvent[] = [];
  private readonly maxEvents: number;

  constructor(
    readonly sessionId: string,
    options: { maxEvents?: number } = {},
  ) {
    this.maxEvents = options.maxEvents ?? DEFAULT_MAX_EVENTS;
  }

  append(event: AgentEvent): void {
    if (event.sessionId !== this.sessionId) {
      throw new Error(
        `Event session ${event.sessionId} does not match history ${this.sessionId}`,
      );
    }
    this.events.push(event);
    while (this.events.length > this.maxEvents) {
      this.events.shift();
    }
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
