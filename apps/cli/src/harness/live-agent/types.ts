/**
 * Shared boundary for Level-3 live agent runs.
 * Attack / product-demo → LiveAgentRunner → Agent → Hook → Veyra.
 */

export type RuntimeAvailability = {
  ok: boolean;
  version?: string;
  error?: string;
  reason: 'ok' | 'missing' | 'timeout' | 'failed';
};

export type LiveAgentRunOptions = {
  workspace: string;
  /** Full prompt passed to the agent (canonical task + any harness instructions). */
  task: string;
  timeoutMs: number;
  maxBudgetUsd?: number;
};

export type AgentRunResult = {
  ok: boolean;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  combined: string;
  timedOut: boolean;
  authFailed: boolean;
  error?: string;
};

export interface LiveAgentRunner {
  readonly id: string;
  readonly displayName: string;
  detect(): Promise<RuntimeAvailability>;
  run(options: LiveAgentRunOptions): Promise<AgentRunResult>;
}
