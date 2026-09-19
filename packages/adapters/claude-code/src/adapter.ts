import type { AgentEvent } from '@veyra/agent-events';
import type { AdapterOptions, AgentAdapter, AgentSession } from '@veyra/adapter-core';
import { detectClaudeCode } from './detect.js';
import { normalizeClaudeCodeEvent } from './normalize.js';

export class ClaudeCodeSession implements AgentSession {
  readonly adapterName = 'claude-code';
  private stopped = false;

  constructor(
    readonly sessionId: string,
    readonly agentId: string,
    private readonly options: AdapterOptions,
  ) {}

  async ingest(rawEvent: unknown): Promise<AgentEvent | null> {
    if (this.stopped) {
      throw new Error('Claude Code session is stopped');
    }

    const event = normalizeClaudeCodeEvent(rawEvent, this.options);
    if (!event) {
      return null;
    }

    if (this.options.onEvent) {
      await this.options.onEvent(event);
    }

    return event;
  }

  async stop(): Promise<void> {
    this.stopped = true;
  }
}

/**
 * Claude Code adapter — normalization only.
 * Policy / Watchdog logic stays outside this package.
 */
export class ClaudeCodeAdapter implements AgentAdapter {
  readonly name = 'claude-code';

  async detect(): Promise<boolean> {
    return detectClaudeCode();
  }

  async start(options: AdapterOptions): Promise<AgentSession> {
    return new ClaudeCodeSession(options.sessionId, options.agentId, options);
  }

  normalize(rawEvent: unknown, options: AdapterOptions): AgentEvent | null {
    return normalizeClaudeCodeEvent(rawEvent, options);
  }
}

export function createClaudeCodeAdapter(): ClaudeCodeAdapter {
  return new ClaudeCodeAdapter();
}
