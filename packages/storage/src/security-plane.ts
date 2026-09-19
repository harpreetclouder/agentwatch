import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const JEV_DIR_NAME = '.jev';
export const JEV_DB_FILE = 'jev.sqlite';
export const JEV_CONFIG_FILE = 'config.json';

export type JevLocalConfig = {
  schemaVersion: string;
  createdAt: string;
  dbPath: string;
};

export type InitSecurityPlaneResult = {
  rootDir: string;
  configPath: string;
  dbPath: string;
  created: boolean;
};

/**
 * Prefer an existing .jev plane, else the workspace root (pnpm-workspace.yaml),
 * else the starting directory. Avoids creating .jev under apps/cli when run via pnpm --filter.
 */
export function resolveProjectRoot(startDir: string = process.cwd()): string {
  let dir = startDir;
  let workspaceRoot: string | null = null;

  for (;;) {
    if (existsSync(join(dir, JEV_DIR_NAME, JEV_CONFIG_FILE))) {
      return dir;
    }
    if (workspaceRoot === null && existsSync(join(dir, 'pnpm-workspace.yaml'))) {
      workspaceRoot = dir;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }

  return workspaceRoot ?? startDir;
}

/**
 * Initialize the local security-plane directory.
 * These files are security-plane resources — agents must not modify them.
 */
export function initSecurityPlane(cwd: string = process.cwd()): InitSecurityPlaneResult {
  const projectRoot = resolveProjectRoot(cwd);
  const rootDir = join(projectRoot, JEV_DIR_NAME);
  const configPath = join(rootDir, JEV_CONFIG_FILE);
  const dbPath = join(rootDir, JEV_DB_FILE);
  const created = !existsSync(rootDir);

  mkdirSync(join(rootDir, 'policies'), { recursive: true });
  mkdirSync(join(rootDir, 'sessions'), { recursive: true });
  mkdirSync(join(rootDir, 'events'), { recursive: true });

  if (!existsSync(configPath)) {
    const config: JevLocalConfig = {
      schemaVersion: '0.1.0',
      createdAt: new Date().toISOString(),
      dbPath: JEV_DB_FILE,
    };
    writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
  }

  const readmePath = join(rootDir, 'README.md');
  if (!existsSync(readmePath)) {
    writeFileSync(
      readmePath,
      `# JEV Security Plane

This directory is part of the Jev security control plane.

Agents must NOT modify:
- config.json
- policies/
- jev.sqlite
- security state
- event / decision history

Local MVP note: a process with OS privileges can still bypass user-space controls.
Production deployments should place this plane outside the agent trust boundary.
`,
      'utf8',
    );
  }

  return { rootDir, configPath, dbPath, created };
}

export function resolveJevDbPath(cwd: string = process.cwd()): string | null {
  const projectRoot = resolveProjectRoot(cwd);
  const rootDir = join(projectRoot, JEV_DIR_NAME);
  const configPath = join(rootDir, JEV_CONFIG_FILE);
  if (!existsSync(configPath)) {
    return null;
  }

  try {
    const raw = JSON.parse(readFileSync(configPath, 'utf8')) as Partial<JevLocalConfig>;
    const relative = raw.dbPath ?? JEV_DB_FILE;
    return join(rootDir, relative);
  } catch {
    return join(rootDir, JEV_DB_FILE);
  }
}
