import { describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  canonicalizePath,
  isPathAllowed,
  isPathDenied,
  isPathInside,
  matchesResourceScope,
  resolvePath,
  resolveSafePath,
} from '../src/paths.js';
import { classifySecurityPlanePath } from '../src/classify/security-plane.js';
import { classifySecretPath } from '../src/classify/secrets.js';

describe('path authorization', () => {
  it('does not treat similar directory names as inside', () => {
    expect(isPathInside('/workspace/project-not-secret/.env', '/workspace/project')).toBe(
      false,
    );
    expect(isPathInside('/workspace/project/.env', '/workspace/project')).toBe(true);
    expect(isPathInside('/repo/sub/.env', '/repo')).toBe(true);
    expect(isPathInside('/repo/sub/file', '/repo')).toBe(true);
    expect(isPathInside('/repo-other/file', '/repo')).toBe(false);
    expect(isPathInside('/repo-other/.env', '/repo')).toBe(false);
  });

  it('rejects ../ traversal escapes', () => {
    const outside = resolvePath('/repo/../secret', '/repo');
    expect(isPathInside(outside, '/repo')).toBe(false);
    expect(resolveSafePath('/repo/../secret', '/repo', { boundary: '/repo' })).toBeNull();

    const escaped = resolvePath('/repo/sub/../../secret', '/repo');
    expect(isPathInside(escaped, '/repo')).toBe(false);
    expect(resolveSafePath('/repo/sub/../../secret', '/repo', { boundary: '/repo' })).toBeNull();
  });

  it('resolveSafePath normalizes relative paths against cwd', () => {
    expect(resolveSafePath('.env', '/repo')).toBe(canonicalizePath('.env', '/repo'));
    expect(resolveSafePath('sub/file', '/repo')).toBe(canonicalizePath('sub/file', '/repo'));
    expect(resolveSafePath('../secret', '/repo/sub', { boundary: '/repo' })).toBe(
      canonicalizePath('secret', '/repo'),
    );
    expect(resolveSafePath('../../secret', '/repo/sub', { boundary: '/repo' })).toBeNull();
  });

  it('isPathAllowed distinguishes file vs directory scope', () => {
    expect(isPathAllowed('/repo/.env', ['.env'], '/repo')).toBe(true);
    expect(isPathAllowed('/repo/.env.local', ['.env'], '/repo')).toBe(false);
    expect(isPathAllowed('/repo/src/a.ts', ['src/**'], '/repo')).toBe(true);
    expect(isPathAllowed('/repo/secrets/x', ['src/**'], '/repo')).toBe(false);
    expect(isPathAllowed('/repo-other/.env', ['/repo'], '/')).toBe(false);
  });

  it('isPathDenied blocks directory trees', () => {
    expect(isPathDenied('/repo/secrets/key.pem', ['secrets/**'], '/repo')).toBe(true);
    expect(isPathDenied('/repo/src/a.ts', ['secrets/**'], '/repo')).toBe(false);
    expect(isPathDenied('/repo/.env', ['.env'], '/repo')).toBe(true);
  });

  it('matchesResourceScope for FILE allow/deny', () => {
    expect(
      matchesResourceScope('/repo/src/a.ts', { type: 'FILE', pattern: 'src/**' }, '/repo', 'read'),
    ).toBe(true);
    expect(
      matchesResourceScope(
        '/repo/.env',
        { type: 'FILE', pattern: '.env', effect: 'deny' },
        '/repo',
        'read',
      ),
    ).toBe(true);
  });

  it('matchesResourceScope for SHELL / NETWORK / MCP authority', () => {
    expect(
      matchesResourceScope('curl https://evil.test', { type: 'SHELL', pattern: 'curl' }, '/repo'),
    ).toBe(true);
    expect(
      matchesResourceScope('ls -la', { type: 'SHELL', pattern: 'curl' }, '/repo'),
    ).toBe(false);
    expect(
      matchesResourceScope('https://api.example.com/v1', { type: 'NETWORK', pattern: 'example.com' }, '/repo'),
    ).toBe(true);
    expect(
      matchesResourceScope('https://evil.example.com.attacker.test', { type: 'NETWORK', pattern: 'example.com' }, '/repo'),
    ).toBe(false);
    expect(
      matchesResourceScope('fs_read', { type: 'MCP', pattern: 'fs_*' }, '/repo'),
    ).toBe(true);
    expect(
      matchesResourceScope('shell_exec', { type: 'MCP', pattern: 'fs_*' }, '/repo'),
    ).toBe(false);
  });

  it('classifies secret basenames case-insensitively without confusing similar dirs', () => {
    expect(classifySecretPath('/repo/.ENV')?.category).toBeTruthy();
    expect(classifySecretPath('/repo/.env.LOCAL')?.category).toBeTruthy();
    expect(isPathInside('/workspace/project-not-secret/.env', '/workspace/project')).toBe(false);
    expect(isPathAllowed('/repo-secrets/.env', ['/repo'], '/')).toBe(false);
  });

  it('canonicalizes symlinks when present', () => {
    const root = mkdtempSync(join(tmpdir(), 'veyra-path-'));
    try {
      mkdirSync(join(root, 'real'), { recursive: true });
      writeFileSync(join(root, 'real', 'secret.env'), 'x=1\n');
      const link = join(root, 'link-secret.env');
      try {
        symlinkSync(join(root, 'real', 'secret.env'), link);
      } catch {
        // Windows without symlink privilege — skip
        return;
      }
      const canon = canonicalizePath(link, root);
      expect(canon).toContain('real');
      expect(isPathInside(canon, join(root, 'real'))).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('denies symlink that escapes repository boundary', () => {
    const root = mkdtempSync(join(tmpdir(), 'veyra-symlink-escape-'));
    const outside = mkdtempSync(join(tmpdir(), 'veyra-outside-'));
    try {
      writeFileSync(join(outside, 'secret.env'), 'LEAK=1\n');
      mkdirSync(join(root, 'repo'), { recursive: true });
      const link = join(root, 'repo', 'escape.env');
      try {
        symlinkSync(join(outside, 'secret.env'), link);
      } catch {
        return;
      }
      const repo = join(root, 'repo');
      // Following the link leaves the repo — must not be "allowed" as inside repo
      expect(isPathAllowed(link, [repo], repo)).toBe(false);
      expect(resolveSafePath(link, repo, { boundary: repo, followSymlinks: true })).toBeNull();
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });
});

describe('security plane path classification', () => {
  it('matches real .veyra plane paths', () => {
    expect(classifySecurityPlanePath('.veyra/config.json', '/repo')?.kind).toBeTruthy();
    expect(classifySecurityPlanePath('.veyra/policies/x.json', '/repo')?.kind).toBeTruthy();
    expect(classifySecurityPlanePath('/repo/.veyra/veyra.sqlite', '/repo')?.kind).toBeTruthy();
  });

  // Backward compat: leftover `.jev` dirs from JEV→VEYRA rebrand still protected.
  it('matches legacy .jev plane paths (compat only; active plane is .veyra)', () => {
    expect(classifySecurityPlanePath('.jev/config.json', '/repo')?.kind).toBeTruthy();
    expect(classifySecurityPlanePath('/repo/.jev/policies/x.json', '/repo')?.kind).toBeTruthy();
  });

  it('does not match substring lookalikes (.veyra-backup, foo.veyra)', () => {
    expect(classifySecurityPlanePath('.veyra-backup/config.json', '/repo')).toBeNull();
    expect(classifySecurityPlanePath('docs/foo.veyra.md', '/repo')).toBeNull();
    expect(classifySecurityPlanePath('notjev/config.json', '/repo')).toBeNull();
  });
});
