import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

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
  const dir = mkdtempSync(join(tmpdir(), 'jev-hook-'));
  tempDirs.push(dir);
  writeFileSync(join(dir, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
  mkdirSync(join(dir, '.jev'), { recursive: true });
  writeFileSync(
    join(dir, '.jev', 'config.json'),
    `${JSON.stringify(
      { schemaVersion: '0.1.0', createdAt: new Date().toISOString(), dbPath: 'jev.sqlite' },
      null,
      2,
    )}\n`,
  );
  return dir;
}

describe('jev hook', () => {
  it('denies PreToolUse secret access with structured JSON', () => {
    expect(existsSync(cliEntry)).toBe(true);
    const cwd = tempProject();
    const payload = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: '.env' },
      cwd,
    });

    const result = spawnSync(process.execPath, [cliEntry, 'hook', '--adapter=claude-code'], {
      cwd,
      input: payload,
      encoding: 'utf8',
      timeout: 15000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('permissionDecision');
    expect(result.stdout).toContain('deny');
    expect(result.stdout).toMatch(/SECRET_ACCESS|Credential|secret/i);
  });

  it('allows benign PreToolUse silently', () => {
    expect(existsSync(cliEntry)).toBe(true);
    const cwd = tempProject();
    const payload = JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd,
    });

    const result = spawnSync(process.execPath, [cliEntry, 'hook', '--adapter=claude-code'], {
      cwd,
      input: payload,
      encoding: 'utf8',
      timeout: 15000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});
