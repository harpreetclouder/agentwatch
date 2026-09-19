import type { AgentEvent } from '@jev/agent-events';
import type { AdapterOptions, AgentAdapter, AgentSession } from '@jev/adapter-core';
import { detectCodex } from './detect.js';
import { normalizeCodexEvent } from './normalize.js';

export class CodexSession implements AgentSession {
  readonly adapterName = 'codex';
  private stopped = false;

  constructor(
    readonly sessionId: string,
    readonly agentId: string,
    private readonly options: AdapterOptions,
  ) {}

  async ingest(rawEvent: unknown): Promise<AgentEvent | null> {
    if (this.stopped) {
      throw new Error('Codex session is stopped');
    }
    const event = normalizeCodexEvent(rawEvent, this.options);
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

export class CodexAdapter implements AgentAdapter {
  readonly name = 'codex';

  async detect(): Promise<boolean> {
    return detectCodex();
  }

  async start(options: AdapterOptions): Promise<AgentSession> {
    return new CodexSession(options.sessionId, options.agentId, options);
  }

  normalize(rawEvent: unknown, options: AdapterOptions): AgentEvent | null {
    return normalizeCodexEvent(rawEvent, options);
  }
}

export function createCodexAdapter(): CodexAdapter {
  return new CodexAdapter();
}
