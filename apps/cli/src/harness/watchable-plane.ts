import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { resolveProjectRoot, VEYRA_DIR_NAME } from '@veyra/storage';
import { prepareDemoWorkspace } from './demo-proof.js';
import {
  createTestWorkspace,
  materializeDemoProject,
  type TestWorkspace,
} from './test-workspace.js';

export const LIVE_DASHBOARD_URL = 'http://localhost:3100/live';

/**
 * Canonical watchable fixture the dashboard prefers (`examples/real-agent-demo`).
 */
export function resolveWatchableDemoRoot(cwd: string = process.cwd()): string {
  return join(resolveProjectRoot(cwd), 'examples', 'real-agent-demo');
}

export type WatchableWorkspace = TestWorkspace & {
  /** True when evidence lands under the dashboard-preferred plane. */
  watchable: boolean;
};

export type OpenDemoWorkspaceOptions = {
  /** Explicit workspace root (absolute or relative to project root). */
  workspace?: string;
  /**
   * Force an isolated temp dir (tests / CI). Default false — prefer
   * `examples/real-agent-demo` so `/live` can stream real SQLite events.
   */
  isolated?: boolean;
  prefix?: string;
};

/**
 * Open a demo/attack workspace. Prefer the stable watchable plane so LIVE
 * can see events without faking dashboard telemetry.
 */
export function openDemoWorkspace(
  options: OpenDemoWorkspaceOptions = {},
): WatchableWorkspace {
  if (options.workspace) {
    const root = resolve(resolveProjectRoot(process.cwd()), options.workspace);
    const example = resolveWatchableDemoRoot();
    prepareDemoWorkspace(root, example);
    return wrapStableWorkspace(root);
  }

  if (!options.isolated) {
    const example = resolveWatchableDemoRoot();
    if (existsSync(example) || existsSync(join(resolveProjectRoot(), 'examples'))) {
      mkdirSync(example, { recursive: true });
      if (!existsSync(join(example, '.env'))) {
        materializeDemoProject(example);
      }
      prepareDemoWorkspace(example, example);
      return wrapStableWorkspace(example);
    }
  }

  const ws = createTestWorkspace(options.prefix ?? 'veyra-demo-');
  return { ...ws, watchable: false };
}

function wrapStableWorkspace(root: string): WatchableWorkspace {
  return {
    id: 'watchable-demo',
    root,
    envPath: join(root, '.env'),
    readmePath: join(root, 'README.md'),
    authPath: join(root, 'src', 'auth.ts'),
    watchable: true,
    cleanup: () => {
      // Never delete the shared fixture — only clear a stale lock if needed.
    },
  };
}

/** Reset SQLite on a shared plane so a new attack starts a clean session story. */
export function resetPlaneDb(workspaceRoot: string): void {
  const dbPath = join(workspaceRoot, VEYRA_DIR_NAME, 'veyra.sqlite');
  if (existsSync(dbPath)) {
    rmSync(dbPath, { force: true });
  }
}

/**
 * One-liner so operators can open LIVE before/during/after the run.
 * Dashboard already prefers examples/real-agent-demo/.veyra when present.
 */
export function printLiveWatchHint(
  workspaceRoot: string,
  options: { phase?: 'start' | 'end' } = {},
): void {
  const plane = join(resolve(workspaceRoot), VEYRA_DIR_NAME);
  console.log(`Watch LIVE: ${LIVE_DASHBOARD_URL}`);
  console.log(`Plane: ${plane}`);
  if (options.phase === 'end') {
    console.log(
      'Open LIVE / Show history to review this attack (latest run stays visible ~10 min).',
    );
  }
  console.log('');
}
