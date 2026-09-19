/**
 * Stage 9 Level 2 — Hook integration + fail-closed regression.
 * Spawns real `veyra hook` (dist/index.js) with Claude PreToolUse JSON.
 * Synthetic secrets only (veyra_fake_*).
 */
import { afterEach, describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { parseDenyPayload } from '../src/commands/hook.js';
import {
  createTestWorkspace,
  resolveCliEntry,
  runHookPreToolUse,
  type TestWorkspace,
} from '../src/harness/test-workspace.js';

const workspaces: TestWorkspace[] = [];
const cliEntry = resolveCliEntry();

afterEach(() => {
  while (workspaces.length > 0) {
    workspaces.pop()?.cleanup();
  }
});

function runHookRaw(cwd: string, input: string) {
  return spawnSync(process.execPath, [cliEntry, 'hook', '--adapter=claude-code'], {
    cwd,
    input,
    encoding: 'utf8',
    timeout: 20000,
  });
}

function runHookJson(cwd: string, payload: unknown) {
  return runHookRaw(cwd, JSON.stringify(payload));
}

describe('Stage 9 Level 2 — hook integration + fail-closed', () => {
  it('allows Read src/auth.ts with empty stdout (no deny)', () => {
    expect(existsSync(cliEntry)).toBe(true);
    const ws = createTestWorkspace('veyra-stage9-hook-');
    workspaces.push(ws);

    const result = runHookPreToolUse({
      cwd: ws.root,
      filePath: 'src/auth.ts',
      cliEntry,
    });

    expect(result.status).toBe(0);
    expect(result.denied).toBe(false);
    expect(parseDenyPayload(result.stdout)).toBeNull();
    expect(result.stdout.trim()).toBe('');
  });

  it('denies Read .env with permissionDecision deny + SECRET_ACCESS and no secret leak', () => {
    expect(existsSync(cliEntry)).toBe(true);
    const ws = createTestWorkspace('veyra-stage9-hook-');
    workspaces.push(ws);

    const result = runHookJson(ws.root, {
      session_id: 'sess_stage9_env',
      cwd: ws.root,
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: '.env' },
      tool_use_id: 'toolu_stage9_env',
    });

    expect(result.status).toBe(0);
    const deny = parseDenyPayload(result.stdout);
    expect(deny).not.toBeNull();
    expect(deny!.hookEventName).toBe('PreToolUse');
    expect(deny!.permissionDecision).toBe('deny');
    expect(deny!.permissionDecisionReason).toMatch(/policy=SECRET_ACCESS/);
    expect(result.stdout).not.toContain('veyra_fake_key');
    expect(result.stdout).not.toContain('veyra_fake_token_only');
    expect(result.stdout).not.toContain('fake_password');
  });

  it('fail-closes PreToolUse on malformed JSON with structured deny', () => {
    const ws = createTestWorkspace('veyra-stage9-hook-');
    workspaces.push(ws);

    const result = runHookRaw(ws.root, '{not-json');

    expect(result.status).toBe(0);
    const deny = parseDenyPayload(result.stdout);
    expect(deny?.permissionDecision).toBe('deny');
    expect(deny?.permissionDecisionReason).toMatch(/fail-closed|malformed/i);
  });

  it('treats empty stdin as no-op exit 0', () => {
    const ws = createTestWorkspace('veyra-stage9-hook-');
    workspaces.push(ws);

    const result = runHookRaw(ws.root, '');

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('');
    expect(parseDenyPayload(result.stdout)).toBeNull();
  });

  it('keeps denying tools after quarantine with SESSION_QUARANTINED', () => {
    const ws = createTestWorkspace('veyra-stage9-hook-');
    workspaces.push(ws);

    // First: dangerous shell → quarantine
    const quarantine = runHookJson(ws.root, {
      session_id: 'sess_stage9_q',
      cwd: ws.root,
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
      tool_use_id: 'toolu_stage9_q',
    });
    expect(quarantine.status).toBe(0);
    const qDeny = parseDenyPayload(quarantine.stdout);
    expect(qDeny?.permissionDecision).toBe('deny');

    // Second: benign read must still deny while quarantined
    const next = runHookPreToolUse({
      cwd: ws.root,
      filePath: 'src/auth.ts',
      cliEntry,
    });
    expect(next.status).toBe(0);
    expect(next.denied).toBe(true);
    const nextDeny = parseDenyPayload(next.stdout);
    expect(nextDeny?.permissionDecision).toBe('deny');
    expect(nextDeny?.permissionDecisionReason).toMatch(/SESSION_QUARANTINED/);
  });
});
