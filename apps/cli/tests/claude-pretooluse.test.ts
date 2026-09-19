import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { parseDenyPayload } from '../src/commands/hook.js';

const tempDirs: string[] = [];
const cliEntry = join(fileURLToPath(new URL('..', import.meta.url)), 'dist', 'index.js');

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

function tempProject(): string {
  const dir = mkdtempSync(join(tmpdir(), 'veyra-stage2-'));
  tempDirs.push(dir);
  writeFileSync(join(dir, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
  mkdirSync(join(dir, '.veyra'), { recursive: true });
  writeFileSync(join(dir, '.env'), 'DEMO_API_KEY=veyra_fake_secret_stage2\n', 'utf8');
  writeFileSync(join(dir, 'src-auth.ts'), 'export const ok = true;\n', 'utf8');
  writeFileSync(
    join(dir, '.veyra', 'config.json'),
    `${JSON.stringify(
      { schemaVersion: '0.1.0', createdAt: new Date().toISOString(), dbPath: 'veyra.sqlite' },
      null,
      2,
    )}\n`,
  );
  return dir;
}

function runHook(cwd: string, payload: unknown) {
  return spawnSync(process.execPath, [cliEntry, 'hook', '--adapter=claude-code'], {
    cwd,
    input: JSON.stringify(payload),
    encoding: 'utf8',
    timeout: 20000,
  });
}

describe('Stage 2 — Claude PreToolUse integration', () => {
  it('denies .env Read with Claude hookSpecificOutput + SECRET_ACCESS metadata', () => {
    expect(existsSync(cliEntry)).toBe(true);
    const cwd = tempProject();

    // Real Claude Code PreToolUse shape (docs: tool_name + tool_input + hook_event_name)
    const result = runHook(cwd, {
      session_id: 'sess_stage2',
      cwd,
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: join(cwd, '.env') },
      tool_use_id: 'toolu_stage2_env',
    });

    expect(result.status).toBe(0);
    const deny = parseDenyPayload(result.stdout);
    expect(deny).not.toBeNull();
    expect(deny!.hookEventName).toBe('PreToolUse');
    expect(deny!.permissionDecision).toBe('deny');
    expect(deny!.permissionDecisionReason).toMatch(/policy=SECRET_ACCESS/);
    expect(deny!.permissionDecisionReason).toMatch(/decision=BLOCK/);
    expect(deny!.permissionDecisionReason).toMatch(/severity=HIGH/);
    // Never echo secret contents into Claude's deny reason
    expect(result.stdout).not.toContain('veyra_fake_secret_stage2');
  });

  it('allows benign PreToolUse with empty stdout (no deny JSON)', () => {
    const cwd = tempProject();
    const result = runHook(cwd, {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: join(cwd, 'src-auth.ts') },
      cwd,
    });
    expect(result.status).toBe(0);
    expect(parseDenyPayload(result.stdout)).toBeNull();
    expect(result.stdout.trim()).toBe('');
  });

  it('fail-closes PreToolUse on malformed JSON with structured deny', () => {
    const cwd = tempProject();
    const result = spawnSync(process.execPath, [cliEntry, 'hook', '--adapter=claude-code'], {
      cwd,
      input: '{not-json',
      encoding: 'utf8',
      timeout: 15000,
    });
    expect(result.status).toBe(0);
    const deny = parseDenyPayload(result.stdout);
    expect(deny?.permissionDecision).toBe('deny');
    expect(deny?.permissionDecisionReason).toMatch(/fail-closed|malformed/i);
  });
});
