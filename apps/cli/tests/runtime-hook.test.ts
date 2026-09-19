import { afterEach, describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  createTestWorkspace,
  runHookPreToolUse,
  resolveCliEntry,
  type TestWorkspace,
} from '../src/harness/test-workspace.js';

const workspaces: TestWorkspace[] = [];
const cliEntry = resolveCliEntry();

afterEach(() => {
  while (workspaces.length > 0) {
    workspaces.pop()?.cleanup();
  }
});

describe('real hook protocol enforcement', () => {
  it('blocks .env PreToolUse and leaves file unread', () => {
    expect(existsSync(cliEntry)).toBe(true);
    const ws = createTestWorkspace();
    workspaces.push(ws);

    const result = runHookPreToolUse({
      cwd: ws.root,
      filePath: '.env',
      cliEntry,
    });

    expect(result.status).toBe(0);
    expect(result.denied).toBe(true);
    expect(result.stdout).toMatch(/SECRET_ACCESS|Credential|secret|authority/i);
    expect(result.envAfter).toBe(result.envBefore);
    // Deny response must not include secret values
    expect(result.stdout).not.toContain('jev_fake_secret_123');
  });

  it('allows benign source reads silently', () => {
    const ws = createTestWorkspace();
    workspaces.push(ws);
    const result = runHookPreToolUse({
      cwd: ws.root,
      filePath: 'src/auth.ts',
      cliEntry,
    });
    expect(result.status).toBe(0);
    expect(result.denied).toBe(false);
    expect(result.stdout.trim()).toBe('');
  });

  it('fail-closes on malformed PreToolUse JSON', () => {
    const ws = createTestWorkspace();
    workspaces.push(ws);
    const result = spawnSync(process.execPath, [cliEntry, 'hook', '--adapter=claude-code'], {
      cwd: ws.root,
      input: '{not-json',
      encoding: 'utf8',
      timeout: 15000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('permissionDecision');
    expect(result.stdout).toContain('deny');
    expect(result.stdout).toMatch(/fail-closed|malformed/i);
  });

  it('keeps denying after quarantine (frozen session)', () => {
    const ws = createTestWorkspace();
    workspaces.push(ws);

    // First: dangerous shell → quarantine
    const q = spawnSync(process.execPath, [cliEntry, 'hook', '--adapter=claude-code'], {
      cwd: ws.root,
      input: JSON.stringify({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'rm -rf /' },
        cwd: ws.root,
      }),
      encoding: 'utf8',
      timeout: 15000,
    });
    expect(q.stdout).toContain('deny');

    // Second: benign read must still deny while quarantined
    const next = runHookPreToolUse({
      cwd: ws.root,
      filePath: 'src/auth.ts',
      cliEntry,
    });
    expect(next.denied).toBe(true);
    expect(next.stdout).toMatch(/QUARANTINE|quarantine|SESSION/i);
  });
});
