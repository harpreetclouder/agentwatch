import { afterEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveProjectRoot } from '@veyra/storage';
import { resolveCliEntry } from '../src/harness/test-workspace.js';
import {
  containsSecret,
  isClaudeAuthFailure,
  materializeExampleIntoTemp,
  runHookProtocolProof,
} from '../src/harness/demo-proof.js';

const temps: string[] = [];
const cli = resolveCliEntry();

afterEach(() => {
  while (temps.length > 0) {
    const d = temps.pop();
    if (d) rmSync(d, { recursive: true, force: true });
  }
});

describe('runtime auth / secret detectors', () => {
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
