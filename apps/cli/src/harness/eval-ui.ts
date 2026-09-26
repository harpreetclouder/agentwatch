/**
 * UI verification for `veyra eval --ui`.
 * Starts the dashboard on a free port and runs the Playwright spec.
 * Does not run unless the eval case is included.
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { resolveProjectRoot } from '@veyra/storage';
import type { EvalCaseOutcome, EvalCaseSpec } from './eval-suite.js';
import { resolveCliEntry } from './test-workspace.js';

const UI_REQUIREMENT =
  '/live with no fresh activity shows idle waiting copy; hook attack on examples/real-agent-demo shows Read activity and .env BLOCKED (SECRET_ACCESS or the injection-then-secret trajectory); HTML report is HOOK with an outcome and disclaimer and no percent score or secret.';

function fail(detail: string): EvalCaseOutcome {
  return { status: 'FAIL', detail };
}

function pass(detail: string): EvalCaseOutcome {
  return { status: 'PASS', detail };
}

function listen(port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const address = server.address();
      const chosen = address && typeof address === 'object' ? address.port : port;
      server.close((err) => (err ? reject(err) : resolve(chosen)));
    });
  });
}

async function portAnswersHttp(port: number): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/`, {
      signal: AbortSignal.timeout(700),
      redirect: 'manual',
    });
    return res.status > 0;
  } catch {
    return false;
  }
}

/**
 * Prefer 3100 only when nothing is already serving it.
 * A bind check is not enough: an existing Next dev server can answer 127.0.0.1:3100
 * while a second IPv4 listen still succeeds. Never attach to that process.
 */
export async function chooseDashboardPort(prefer = 3100): Promise<number> {
  if (await portAnswersHttp(prefer)) return listen(0);
  try {
    return await listen(prefer);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'EADDRINUSE') throw err;
    return listen(0);
  }
}

function tail(text: string, max = 1200): string {
  const trimmed = text.replace(/\s+/g, ' ').trim();
  if (trimmed.length <= max) return trimmed;
  return trimmed.slice(-max);
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.pid === undefined || child.exitCode !== null) return;
  const pid = child.pid;
  const signal = (name: NodeJS.Signals) => {
    try {
      process.kill(-pid, name);
    } catch {
      try {
        child.kill(name);
      } catch {
        // already exited
      }
    }
  };
  signal('SIGTERM');
  await new Promise((resolve) => setTimeout(resolve, 400));
  if (child.exitCode === null) signal('SIGKILL');
}

async function waitForHttp(url: string, child: ChildProcess, timeoutMs: number): Promise<void> {
  const start = Date.now();
  let last = 'no response';
  let streak = 0;
  while (Date.now() - start < timeoutMs) {
    if (child.exitCode !== null) {
      throw new Error(`dashboard exited ${child.exitCode}: ${last}`);
    }
    try {
      const res = await fetch(url, { redirect: 'follow' });
      const body = await res.text();
      if (res.ok && body.includes('LIVE')) {
        streak += 1;
        if (streak >= 2) return;
      } else {
        streak = 0;
        last = `HTTP ${res.status}`;
      }
    } catch (err) {
      streak = 0;
      last = err instanceof Error ? err.message : String(err);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`dashboard not ready (${last})`);
}

export function uiEvalSpec(): EvalCaseSpec {
  return {
    id: 'ui-live-report',
    name: 'LIVE dashboard and HTML report',
    layer: 'hook',
    source: 'playwright apps/dashboard/e2e/live-eval.spec.ts',
    requirement: UI_REQUIREMENT,
    required: true,
    run: runUiVerification,
  };
}

async function runUiVerification(): Promise<EvalCaseOutcome> {
  const root = resolveProjectRoot();
  const dashboardDir = join(root, 'apps', 'dashboard');
  const port = await chooseDashboardPort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const logs: string[] = [];
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env['VEYRA_PROJECT_ROOT'];

  // `next dev` refuses to start while another dev server for this app is running.
  // `next start` can own a free port beside that process.
  const child = spawn(
    'pnpm',
    ['exec', 'next', 'start', '--hostname', '127.0.0.1', '--port', String(port)],
    {
      cwd: dashboardDir,
      env,
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  child.stdout?.on('data', (chunk: Buffer) => {
    logs.push(chunk.toString('utf8'));
  });
  child.stderr?.on('data', (chunk: Buffer) => {
    logs.push(chunk.toString('utf8'));
  });

  try {
    await waitForHttp(`${baseUrl}/live`, child, 120_000);
    const playwrightEnv: NodeJS.ProcessEnv = {
      ...env,
      VEYRA_DASHBOARD_URL: baseUrl,
      VEYRA_REPO_ROOT: root,
      VEYRA_CLI: resolveCliEntry(),
    };
    const result = spawnSync('pnpm', ['exec', 'playwright', 'test', '--reporter=line'], {
      cwd: dashboardDir,
      env: playwrightEnv,
      encoding: 'utf8',
      timeout: 240_000,
    });
    if (result.error) {
      return fail(tail(`playwright failed to start: ${result.error.message}`));
    }
    if (result.status !== 0) {
      return fail(
        tail(
          `playwright exit ${result.status ?? 'signal'}: ${result.stdout ?? ''}\n${result.stderr ?? ''}\n${logs.join(' ')}`,
        ),
      );
    }
    return pass(`playwright passed against ${baseUrl}/live`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return fail(tail(`${message} ${logs.join(' ')}`));
  } finally {
    await stopChild(child);
  }
}
