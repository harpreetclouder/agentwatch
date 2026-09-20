import type {
  AgentRunResult,
  LiveAgentRunOptions,
  LiveAgentRunner,
  RuntimeAvailability,
} from './types.js';

/**
 * Placeholder runners for future agents (P2 ships Claude Code only).
 * detect() is always unavailable; run() throws — never silently fall back.
 */
export class UnsupportedLiveAgentRunner implements LiveAgentRunner {
  constructor(
    readonly id: string,
    readonly displayName: string,
  ) {}

  async detect(): Promise<RuntimeAvailability> {
    return {
      ok: false,
      reason: 'failed',
      error: `${this.displayName} LiveAgentRunner is not implemented yet`,
    };
  }

  async run(_options: LiveAgentRunOptions): Promise<AgentRunResult> {
    throw new Error(
      `${this.displayName} LiveAgentRunner is not implemented yet — use ClaudeCodeRunner`,
    );
  }
}

/** Stub only — do not use for runtime claims. */
export const codexRunnerStub: LiveAgentRunner = new UnsupportedLiveAgentRunner(
  'codex',
  'Codex',
);

/** Stub only — do not use for runtime claims. */
export const cursorRunnerStub: LiveAgentRunner = new UnsupportedLiveAgentRunner(
  'cursor',
  'Cursor',
);
