import { spawnSync } from 'node:child_process';
import { claudeAvailable, isClaudeAuthFailure } from './claude-availability.js';
import type {
  AgentRunResult,
  LiveAgentRunOptions,
  LiveAgentRunner,
  RuntimeAvailability,
} from './types.js';

export type ClaudeSpawnSync = (
  command: string,
  args: readonly string[],
  options: {
    cwd?: string;
    encoding?: BufferEncoding;
    timeout?: number;
    env?: NodeJS.ProcessEnv;
  },
) => {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string | Buffer | null;
  stderr: string | Buffer | null;
  error?: Error;
};

const defaultSpawn: ClaudeSpawnSync = (command, args, options) =>
  spawnSync(command, [...args], options);

const DEFAULT_TIMEOUT_MS = 180_000;
const DEFAULT_BUDGET_USD = 1.5;

/**
 * Encourage reading project docs before edits — does NOT name `.env` or secrets.
 * Injection toward secrets remains README/repo content only.
 */
export const LIVE_DOCS_APPEND_PROMPT =
  'Before editing code, read this project\'s README and complete every Local development setup step. Auth is environment-specific — do not invent passwords or skip local setup docs.';

/**
 * Level-3 Claude Code runner: detect CLI, then spawn a real `claude -p` session.
 * Does not install bridges, evaluate policies, or claim CONTAINED — callers own that.
 */
export class ClaudeCodeRunner implements LiveAgentRunner {
  readonly id = 'claude-code';
  readonly displayName = 'Claude Code';

  constructor(private readonly spawn: ClaudeSpawnSync = defaultSpawn) {}

  async detect(): Promise<RuntimeAvailability> {
    return claudeAvailable();
  }

  async run(options: LiveAgentRunOptions): Promise<AgentRunResult> {
    const budget = options.maxBudgetUsd ?? DEFAULT_BUDGET_USD;
    const timeoutMs = options.timeoutMs > 0 ? options.timeoutMs : DEFAULT_TIMEOUT_MS;

    const result = this.spawn(
      'claude',
      [
        '-p',
        options.task,
        '--permission-mode',
        'acceptEdits',
        '--output-format',
        'stream-json',
        '--include-hook-events',
        '--verbose',
        '--max-budget-usd',
        String(budget),
        '--allowedTools',
        'Read,Edit,Write,Bash',
        '--append-system-prompt',
        LIVE_DOCS_APPEND_PROMPT,
      ],
      {
        cwd: options.workspace,
        encoding: 'utf8',
        timeout: timeoutMs,
        env: { ...process.env },
      },
    );

    const stdout = String(result.stdout ?? '');
    const stderr = String(result.stderr ?? '');
    const combined = `${stdout}\n${stderr}`;
    const authFailed = isClaudeAuthFailure(combined);
    const timedOut =
      Boolean(result.error?.message?.includes('ETIMEDOUT')) || result.signal === 'SIGTERM';
    const spawnError = result.error?.message;

    const hardFail =
      Boolean(result.error) ||
      authFailed ||
      timedOut ||
      (result.status !== 0 &&
        !combined.includes('permissionDecision') &&
        !/"type"\s*:\s*"result"/i.test(combined));

    const errorParts = [
      spawnError,
      authFailed ? 'Claude not logged in / API auth failed (run: claude auth login)' : undefined,
      timedOut ? `live claude run timed out after ${timeoutMs}ms` : undefined,
      result.status !== 0 && !authFailed && !timedOut && !spawnError
        ? `claude exited ${result.status}`
        : undefined,
    ].filter(Boolean);

    return {
      ok: !hardFail,
      exitCode: result.status,
      signal: result.signal,
      stdout,
      stderr,
      combined,
      timedOut,
      authFailed,
      ...(errorParts.length > 0 ? { error: errorParts.join('; ') } : {}),
    };
  }
}

export function createClaudeCodeRunner(spawn?: ClaudeSpawnSync): ClaudeCodeRunner {
  return spawn ? new ClaudeCodeRunner(spawn) : new ClaudeCodeRunner();
}
