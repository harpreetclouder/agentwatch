import { mkdtempSync, rmSync, readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { bridgeStatus, installBridge, uninstallBridge } from '../src/bridge/install.js';
import { isJevManagedCommand } from '../src/bridge/paths.js';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

function tempProject(): string {
  const dir = mkdtempSync(join(tmpdir(), 'jev-bridge-'));
  tempDirs.push(dir);
  writeFileSync(join(dir, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
  mkdirSync(join(dir, '.jev'), { recursive: true });
  writeFileSync(
    join(dir, '.jev', 'config.json'),
    `${JSON.stringify({ schemaVersion: '0.1.0', createdAt: new Date().toISOString(), dbPath: 'jev.sqlite' }, null, 2)}\n`,
  );
  return dir;
}

describe('bridge install', () => {
  it('installs Claude + Codex hooks and reports status', () => {
    const cwd = tempProject();
    const result = installBridge({
      adapters: ['claude-code', 'codex'],
      cwd,
    });

    expect(existsSync(result.claudeSettingsPath)).toBe(true);
    expect(existsSync(result.codexHooksPath)).toBe(true);

    const claude = JSON.parse(readFileSync(result.claudeSettingsPath, 'utf8')) as {
      hooks: Record<string, Array<{ hooks: Array<{ command: string }> }>>;
    };
    const pre = claude.hooks['PreToolUse'] ?? [];
    expect(pre.some((g) => g.hooks.some((h) => isJevManagedCommand(h.command)))).toBe(true);

    const status = bridgeStatus(cwd);
    expect(status.claudeInstalled).toBe(true);
    expect(status.codexInstalled).toBe(true);
  });

  it('preserves existing non-JEV hooks on install/uninstall', () => {
    const cwd = tempProject();
    mkdirSync(join(cwd, '.claude'), { recursive: true });
    writeFileSync(
      join(cwd, '.claude', 'settings.json'),
      `${JSON.stringify(
        {
          hooks: {
            PreToolUse: [
              {
                matcher: 'Bash',
                hooks: [{ type: 'command', command: 'echo custom-user-hook' }],
              },
            ],
          },
        },
        null,
        2,
      )}\n`,
    );

    installBridge({ adapters: ['claude-code'], cwd });
    const mid = JSON.parse(
      readFileSync(join(cwd, '.claude', 'settings.json'), 'utf8'),
    ) as {
      hooks: { PreToolUse: Array<{ hooks: Array<{ command: string }> }> };
    };
    const commands = mid.hooks.PreToolUse.flatMap((g) => g.hooks.map((h) => h.command));
    expect(commands.some((c) => c.includes('custom-user-hook'))).toBe(true);
    expect(commands.some((c) => isJevManagedCommand(c))).toBe(true);

    uninstallBridge(cwd);
    const after = JSON.parse(
      readFileSync(join(cwd, '.claude', 'settings.json'), 'utf8'),
    ) as {
      hooks?: { PreToolUse?: Array<{ hooks: Array<{ command: string }> }> };
    };
    const remaining = (after.hooks?.PreToolUse ?? []).flatMap((g) =>
      g.hooks.map((h) => h.command),
    );
    expect(remaining.some((c) => c.includes('custom-user-hook'))).toBe(true);
    expect(remaining.some((c) => isJevManagedCommand(c))).toBe(false);
  });

  it('writes a Claude settings patch when .claude is not writable', () => {
    const cwd = tempProject();
    writeFileSync(join(cwd, '.claude'), 'blocked');
    const result = installBridge({ adapters: ['claude-code'], cwd });
    expect(result.claudeMode).toBe('patch');
    expect(existsSync(result.claudePatchPath)).toBe(true);
    const patch = JSON.parse(readFileSync(result.claudePatchPath, 'utf8')) as {
      hooks: { PreToolUse: unknown[] };
    };
    expect(patch.hooks.PreToolUse.length).toBeGreaterThan(0);
  });
});
