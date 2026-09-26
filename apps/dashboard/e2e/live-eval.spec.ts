/**
 * End-to-end LIVE + HTML report check. Uses the built `veyra` binary and the real hook path.
 * `veyra eval --ui` starts the dashboard and sets VEYRA_DASHBOARD_URL.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { expect, test } from '@playwright/test';

const SECRET = 'VEYRA_RUNTIME_FAKE_SECRET_123';
const repo =
  process.env['VEYRA_REPO_ROOT'] ?? fileURLToPath(new URL('../../..', import.meta.url));
const cli = process.env['VEYRA_CLI'] ?? join(repo, 'apps', 'cli', 'dist', 'index.js');

function scrub(text: string): string {
  return text.split(SECRET).join('[REDACTED]').replace(/veyra_fake_\S+/gi, '[REDACTED]');
}

function veyra(args: string[]): { status: number | null; output: string } {
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd: repo,
    encoding: 'utf8',
    timeout: 120_000,
    env: process.env,
  });
  const output = scrub(`${result.stdout ?? ''}\n${result.stderr ?? ''}\n${result.error?.message ?? ''}`);
  return { status: result.status, output };
}

function clearDemoPlane(): void {
  const db = join(repo, 'examples', 'real-agent-demo', '.veyra', 'veyra.sqlite');
  for (const suffix of ['', '-wal', '-shm']) {
    rmSync(`${db}${suffix}`, { force: true });
  }
}

test('live idle, hook attack on the watchable plane, and hook HTML report', async ({ page }) => {
  expect(existsSync(cli), 'CLI not built').toBe(true);
  clearDemoPlane();

  await expect(async () => {
    const response = await page.goto('/live', { waitUntil: 'domcontentloaded' });
    expect(response?.ok(), `live HTTP ${response?.status() ?? 'none'}`).toBe(true);
  }).toPass({ timeout: 30_000 });
  await expect(page.getByRole('heading', { name: 'LIVE' })).toBeVisible();
  await expect(page.getByText('Waiting for events…')).toBeVisible();
  await expect(page.getByText('Idle', { exact: true })).toBeVisible();
  await expect(page.getByText('Idle · waiting for the next session')).toBeVisible();
  await expect(page.getByText('SECRET_ACCESS')).toHaveCount(0);
  await expect(page.getByText('BLOCKED')).toHaveCount(0);
  const idleText = await page.locator('body').innerText();
  expect(idleText).not.toContain(SECRET);
  expect(idleText).not.toMatch(/veyra_fake_/i);

  const attack = veyra(['attack', '--mode=hook']);
  expect(attack.status, attack.output).toBe(0);

  await page.reload();
  await expect(page.getByText('Read README').first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText('.env BLOCKED').first()).toBeVisible();
  await expect(page.getByText('BLOCK', { exact: true }).first()).toBeVisible();
  await expect(page.locator('body')).toContainText(/SECRET_ACCESS|TRAJECTORY_INJECTION_THEN_SECRET/);

  const liveText = await page.locator('body').innerText();
  expect(liveText).toMatch(/Read (auth|README)/);
  expect(liveText).toContain('BLOCKED');
  expect(liveText).toMatch(/SECRET_ACCESS|TRAJECTORY_INJECTION_THEN_SECRET/);
  expect(liveText).not.toContain(SECRET);
  expect(liveText).not.toMatch(/veyra_fake_/i);

  const report = veyra(['report', '--html']);
  expect(report.status, report.output).toBe(0);
  const htmlPath = join(repo, '.veyra', 'reports', 'last.html');
  expect(existsSync(htmlPath), 'HTML report was not written').toBe(true);
  await page.goto(pathToFileURL(htmlPath).href);

  await expect(page.locator('.honesty')).toHaveText('HOOK');
  const modeLine = page.locator('p').filter({ hasText: /^Mode:/ });
  await expect(modeLine).toContainText('hook');
  await expect(modeLine).not.toContainText(/runtime/i);
  await expect(page.getByText('This record is not a runtime proof.')).toBeVisible();
  const outcome = page.locator('section').filter({
    has: page.getByRole('heading', { name: 'Outcome' }),
  });
  await expect(outcome).toContainText(
    /CONTAINED|PROOF INCOMPLETE|RUNTIME UNAVAILABLE|ATTACK NOT CONTAINED/,
  );
  await expect(page.locator('footer')).toContainText(
    /Controlled benchmark|Do not claim complete security|Not a universal security guarantee/i,
  );

  const reportText = await page.locator('body').innerText();
  expect(reportText).not.toMatch(/\d\s*%/);
  expect(reportText.toLowerCase()).not.toContain('percent');
  expect(reportText).not.toContain(SECRET);
  expect(reportText).not.toMatch(/veyra_fake_/i);
});
