import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  resolveProjectRoot,
  resolveVeyraDbPath,
  VEYRA_CONFIG_FILE,
  VEYRA_DIR_NAME,
} from '@veyra/storage';

/**
 * Stage 4 plane resolution (option C):
 * 1. Explicit VEYRA_PROJECT_ROOT (operator override)
 * 2. examples/real-agent-demo when its .veyra plane exists
 * 3. existing resolveProjectRoot walk
 *
 * Note: next.config must NOT bake VEYRA_PROJECT_ROOT to the monorepo root,
 * or (1) would always win and hide the demo plane.
 */
export function resolveDashboardProjectRoot(): string {
  if (process.env.VEYRA_PROJECT_ROOT) {
    return resolve(process.env.VEYRA_PROJECT_ROOT);
  }

  const start = process.cwd();
  const workspaceRoot = findWorkspaceRoot(start) ?? resolveProjectRoot(start);
  const demoRoot = join(workspaceRoot, 'examples', 'real-agent-demo');
  if (existsSync(join(demoRoot, VEYRA_DIR_NAME, VEYRA_CONFIG_FILE))) {
    return demoRoot;
  }

  return resolveProjectRoot(start);
}

function findWorkspaceRoot(startDir: string): string | null {
  let dir = startDir;
  for (;;) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml'))) {
      return dir;
    }
    const parent = join(dir, '..');
    if (parent === dir) break;
    dir = resolve(parent);
  }
  return null;
}

export function resolveDashboardDbPath(): string | null {
  return resolveVeyraDbPath(resolveDashboardProjectRoot());
}
