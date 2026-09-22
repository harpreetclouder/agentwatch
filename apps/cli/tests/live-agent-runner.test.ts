import { describe, expect, it, vi } from 'vitest';
import type { SpawnSyncReturns } from 'node:child_process';
import {
  ClaudeCodeRunner,
  createClaudeCodeRunner,
  codexRunnerStub,
  cursorRunnerStub,
  isClaudeAuthFailure,
  type LiveAgentRunner,
} from '../src/harness/live-agent/index.js';
import { runLiveRuntimeAttackById } from '../src/harness/runtime-attack.js';
import { buildLiveAgentPrompt, DEMO_TASK } from '../src/harness/demo-proof.js';

function fakeSpawnResult(
  partial: Partial<SpawnSyncReturns<string>> & { stdout?: string; stderr?: string },
): SpawnSyncReturns<string> {
  return {
    status: 0,
    signal: null,
    output: [null, partial.stdout ?? '', partial.stderr ?? ''],
    pid: 1,
    stdout: partial.stdout ?? '',
    stderr: partial.stderr ?? '',
    error: undefined,
    ...partial,
  } as SpawnSyncReturns<string>;
}

describe('LiveAgentRunner / ClaudeCodeRunner', () => {
  it('detect() reports missing when claude is not on PATH', async () => {
    const prev = process.env['PATH'];
    process.env['PATH'] = '/nonexistent-veyra-p2-no-claude';
    try {
      const runner = createClaudeCodeRunner();
      const avail = await runner.detect();
      expect(avail.ok).toBe(false);
      expect(avail.reason).toBe('missing');
      expect(avail.error).toMatch(/not found/i);
    } finally {
      if (prev === undefined) delete process.env['PATH'];
      else process.env['PATH'] = prev;
    }
  });

  it('run() spawns claude with task, workspace, budget, and timeout', async () => {
    const spawn = vi.fn().mockReturnValue(
      fakeSpawnResult({
        status: 0,
        stdout: '{"type":"result"}\n"permissionDecision":"deny"\n',
      }),
    );
    const runner = new ClaudeCodeRunner(spawn);
    const result = await runner.run({
      workspace: '/tmp/veyra-ws',
      task: 'Fix the authentication bug in src/auth.ts.',
      timeoutMs: 12_000,
      maxBudgetUsd: 0.75,
    });

    expect(spawn).toHaveBeenCalledTimes(1);
    const [cmd, args, opts] = spawn.mock.calls[0]!;
    expect(cmd).toBe('claude');
    expect(args).toContain('-p');
    expect(args).toContain('Fix the authentication bug in src/auth.ts.');
    expect(args).toContain('--max-budget-usd');
    expect(args).toContain('0.75');
    expect(args).toContain('--include-hook-events');
    expect(args).toContain('--append-system-prompt');
    const appendIdx = args.indexOf('--append-system-prompt');
    expect(args[appendIdx + 1]).toMatch(/README|Local development setup/i);
    expect(args[appendIdx + 1]).not.toMatch(/\.env/i);
    expect(opts).toMatchObject({
      cwd: '/tmp/veyra-ws',
      timeout: 12_000,
      encoding: 'utf8',
    });
    expect(result.ok).toBe(true);
    expect(result.authFailed).toBe(false);
    expect(result.timedOut).toBe(false);
  });

  it('run() marks auth failure and is not ok', async () => {
    const spawn = vi.fn().mockReturnValue(
      fakeSpawnResult({
        status: 1,
        stderr: 'OAuth access token is invalid',
      }),
    );
    const runner = new ClaudeCodeRunner(spawn);
    const result = await runner.run({
      workspace: '/tmp/veyra-ws',
      task: DEMO_TASK,
      timeoutMs: 5_000,
    });
    expect(result.ok).toBe(false);
    expect(result.authFailed).toBe(true);
    expect(isClaudeAuthFailure(result.combined)).toBe(true);
  });

  it('run() marks timeout as not ok', async () => {
    const spawn = vi.fn().mockReturnValue(
      fakeSpawnResult({
        status: null,
        signal: 'SIGTERM',
        error: Object.assign(new Error('spawnSync ETIMEDOUT'), { code: 'ETIMEDOUT' }),
      }),
    );
    const runner = new ClaudeCodeRunner(spawn);
    const result = await runner.run({
      workspace: '/tmp/veyra-ws',
      task: DEMO_TASK,
      timeoutMs: 1_000,
    });
    expect(result.ok).toBe(false);
    expect(result.timedOut).toBe(true);
  });

  it('Codex/Cursor stubs never claim available and refuse run()', async () => {
    for (const stub of [codexRunnerStub, cursorRunnerStub]) {
      const avail = await stub.detect();
      expect(avail.ok).toBe(false);
      await expect(
        stub.run({ workspace: '/tmp', task: 'x', timeoutMs: 1000 }),
      ).rejects.toThrow(/not implemented/i);
    }
  });

  it('buildLiveAgentPrompt is exactly DEMO_TASK with no secret coercion', () => {
    const prompt = buildLiveAgentPrompt();
    expect(prompt).toBe(DEMO_TASK);
    expect(prompt).not.toMatch(/\.env/i);
    expect(prompt.toLowerCase()).not.toContain('read secrets');
    expect(prompt).not.toContain('Mandatory workflow');
  });
});

describe('runtime attack wiring through LiveAgentRunner', () => {
  it('runLiveRuntimeAttackById uses injected runner.detect and skips run when unavailable', async () => {
    const runner: LiveAgentRunner = {
      id: 'fake',
      displayName: 'Fake Agent',
      async detect() {
        return {
          ok: false,
          reason: 'missing',
          error: 'injected unavailable',
        };
      },
      async run() {
        throw new Error('run must not be called when detect fails');
      },
    };

    const result = await runLiveRuntimeAttackById('prompt-injection-secret-access', {
      runner,
      isolated: true,
    });
    expect(result.mode).toBe('runtime');
    expect(result.contained).toBe(false);
    expect(result.unavailableReason).toContain('injected unavailable');
    expect(result.outcome).toBe('RUNTIME_UNAVAILABLE');
  });

  it('runLiveRuntimeAttackById does not claim contained when runner detect ok but product live fails', async () => {
    const runner: LiveAgentRunner = {
      id: 'fake-live',
      displayName: 'Fake Live',
      async detect() {
        return { ok: true, reason: 'ok', version: 'fake-1.0' };
      },
      async run() {
        return {
          ok: false,
          exitCode: 1,
          signal: null,
          stdout: '',
          stderr: 'boom',
          combined: '\nboom',
          timedOut: false,
          authFailed: false,
          error: 'boom',
        };
      },
    };

    const result = await runLiveRuntimeAttackById('prompt-injection-secret-access', {
      runner,
      isolated: true,
    });
    expect(result.mode).toBe('runtime');
    expect(result.contained).toBe(false);
    // Process started → evaluate RuntimeAttackProof (incomplete), not UNAVAILABLE.
    expect(result.unavailableReason).toBeNull();
    expect(result.outcome).toBe('PROOF_INCOMPLETE');
    expect(result.proof).toBeTruthy();
    expect(result.proof?.agentProcessStarted).toBe(true);
    expect(result.proof?.denyReturned).toBe(false);
    expect(result.checks.some((c) => !c.ok)).toBe(true);
  }, 60_000);
});