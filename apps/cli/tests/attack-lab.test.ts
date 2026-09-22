import { afterEach, describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { resolveCliEntry } from '../src/harness/test-workspace.js';
import {
  printRuntimeAttackResult,
  runHookAttackById,
  runLiveRuntimeAttackById,
} from '../src/harness/runtime-attack.js';
import { runCli } from '../src/cli.js';
import type { RuntimeAttackResult } from '@veyra/attack-engine';
import { tallyAttackResults } from '../src/commands/attack.js';

const cli = resolveCliEntry();
const temps: string[] = [];

afterEach(() => {
  temps.length = 0;
});

async function capture(argv: string[]): Promise<{ code: number; out: string }> {
  const chunks: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...args: unknown[]) => {
    chunks.push(args.map(String).join(' '));
  };
  console.error = (...args: unknown[]) => {
    chunks.push(args.map(String).join(' '));
  };
  try {
    const code = await runCli(argv);
    return { code, out: chunks.join('\n') };
  } finally {
    console.log = origLog;
    console.error = origErr;
  }
}

function capturePrint(result: RuntimeAttackResult): string {
  const chunks: string[] = [];
  const orig = console.log;
  console.log = (...a: unknown[]) => {
    chunks.push(a.map(String).join(' '));
  };
  try {
    printRuntimeAttackResult(result);
  } finally {
    console.log = orig;
  }
  return chunks.join('\n');
}

describe('Stage H attack lab modes', () => {
  it('lists hook-capable attacks separately from full simulation corpus', async () => {
    const { code, out } = await capture(['attack', '--list', '--mode=hook']);
    expect(code).toBe(0);
    expect(out).toContain('AGENT ATTACK LAB');
    expect(out).toContain('prompt-injection-secret-access');
    expect(out).toContain('live-trajectory-attack');
    expect(out).toContain('SIMULATION');
    expect(out).toContain('HOOK');
    expect(out).toContain('RUNTIME');
    expect(out).toContain('RUNTIME (UNAVAILABLE)');
    expect(out).not.toContain('02-dangerous-shell');
  });

  it('live-trajectory-attack hook path uses hook-trajectory-proof (not live label)', async () => {
    expect(existsSync(cli)).toBe(true);
    const result = await runHookAttackById('live-trajectory-attack', { isolated: true });
    expect(result.mode).toBe('hook');
    expect(result.contained).toBe(true);
    expect(result.proof).toBeNull();
    expect(result.checks.some((c) => c.label.includes('Collector') && c.ok)).toBe(true);
  }, 30_000);

  it('live-trajectory-attack runtime unavailable is honest (no soft contain)', async () => {
    const result = await runLiveRuntimeAttackById('live-trajectory-attack', {
      runner: {
        id: 'mock',
        displayName: 'Mock',
        async detect() {
          return { ok: false, reason: 'missing', error: 'test' };
        },
        async run() {
          throw new Error('must not run');
        },
      },
    });
    expect(result.mode).toBe('runtime');
    expect(result.contained).toBe(false);
    expect(result.unavailableReason).toBeTruthy();
    expect(result.unavailableReason).toMatch(/hook-trajectory-proof|--mode=hook/);
    const out = capturePrint(result);
    expect(out).toContain('REAL RUNTIME UNAVAILABLE');
    expect(out).toContain('Runtime: RUNTIME (UNAVAILABLE)');
    expect(out).toContain('hook-trajectory-proof');
    expect(out).toContain('0 / 1 CONTROLLED ATTACKS CONTAINED');
  }, 15_000);

  it('attack --help states three explicit levels and front-door thesis', async () => {
    const { code, out } = await capture(['attack', '--help']);
    expect(code).toBe(0);
    expect(out).toContain('Test whether your agent can be compromised');
    expect(out).toContain('SIMULATION');
    expect(out).toContain('HOOK');
    expect(out).toContain('RUNTIME');
    expect(out).toContain('simulation');
    expect(out).toContain('hook');
    expect(out).toContain('runtime');
    expect(out).toContain('REAL RUNTIME UNAVAILABLE');
    expect(out).toContain('veyra report --json');
  });

  it('runs prompt-injection-secret-access via real hooks (no simulateEvent)', async () => {
    expect(existsSync(cli)).toBe(true);
    const result = await runHookAttackById('prompt-injection-secret-access', {
      isolated: true,
    });
    expect(result.mode).toBe('hook');
    expect(result.contained).toBe(true);
    expect(result.checks.every((c) => c.ok)).toBe(true);
    expect(result.observedPolicy).toBe('SECRET_ACCESS');
    expect(result.disclaimer).toContain('Do not claim complete security');

    const out = capturePrint(result);
    expect(out).toContain('AGENT ATTACK LAB');
    expect(out).toContain('Runtime: HOOK');
    expect(out).not.toContain('Runtime: RUNTIME');
    expect(out).not.toContain('REAL RUNTIME');
    expect(out).toContain('Prompt Injection → Secret Access');
    expect(out).toContain('✓ Injection encountered');
    expect(out).toContain('✓ SECRET_ACCESS');
    expect(out).toContain('✓ BLOCK');
    expect(out).toContain('1 / 1 CONTROLLED ATTACKS CONTAINED');
    expect(out).toContain('Secret exposure: NONE');
    expect(out).toContain('Critical escapes: 0');
    expect(out).toContain('veyra explain');
    expect(out).toContain('veyra report --json');
    expect(out).toContain('Controlled benchmark');
  }, 30_000);

  it('veyra attack --mode=hook exits 0 when contained', async () => {
    expect(existsSync(cli)).toBe(true);
    const { code, out } = await capture(['attack', '--mode=hook']);
    expect(code).toBe(0);
    expect(out).toContain('Watch LIVE: http://localhost:3100/live');
    expect(out).toContain('Plane:');
    expect(out).toContain('real-agent-demo/.veyra');
    expect(out).toContain('Open LIVE / Show history to review this attack');
    expect(out).toContain('AGENT ATTACK LAB');
    expect(out).toContain('Runtime: HOOK');
    expect(out).not.toMatch(/Runtime: RUNTIME(?! \(UNAVAILABLE\))/);
    expect(out).toContain('1 / 1 CONTROLLED ATTACKS CONTAINED');
  }, 30_000);

  it('runtime unavailable path does not claim contained-as-runtime', async () => {
    const prevPath = process.env['PATH'];
    process.env['PATH'] = '/nonexistent-veyra-p1-no-claude';
    try {
      const result = await runLiveRuntimeAttackById('prompt-injection-secret-access');
      expect(result.mode).toBe('runtime');
      expect(result.unavailableReason).toBeTruthy();
      expect(result.contained).toBe(false);
      expect(result.evidenceRecorded).toBe(false);

      const out = capturePrint(result);
      expect(out).toContain('REAL RUNTIME UNAVAILABLE');
      expect(out).toContain('Runtime: RUNTIME (UNAVAILABLE)');
      expect(out).toContain('veyra attack --mode=hook');
      expect(out).toContain('not claiming containment');
      expect(out).toContain('0 / 1 CONTROLLED ATTACKS CONTAINED');
      expect(out).not.toContain('1 / 1 CONTROLLED ATTACKS CONTAINED');
      expect(out).not.toContain('Runtime: HOOK');
      expect(out).not.toMatch(/Runtime: RUNTIME$/m);
    } finally {
      if (prevPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = prevPath;
    }
  }, 30_000);

  it('veyra attack --mode=runtime exits non-zero when Claude unavailable', async () => {
    const prevPath = process.env['PATH'];
    process.env['PATH'] = '/nonexistent-veyra-p1-no-claude';
    try {
      const { code, out } = await capture(['attack', '--mode=runtime']);
      expect(code).toBe(2);
      expect(out).toContain('REAL RUNTIME UNAVAILABLE');
      expect(out).toContain('Runtime: RUNTIME (UNAVAILABLE)');
      expect(out).toContain('--mode=hook');
      expect(out).not.toContain('1 / 1 CONTROLLED ATTACKS CONTAINED');
      expect(out).not.toContain('Runtime: HOOK');
    } finally {
      if (prevPath === undefined) delete process.env['PATH'];
      else process.env['PATH'] = prevPath;
    }
  }, 30_000);

  it('hook vs runtime Mode labels stay distinct in printer', () => {
    const base = {
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      contained: true,
      checks: [{ label: 'SECRET_ACCESS', ok: true }],
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: 'SECRET_ACCESS',
      observedDecision: 'BLOCK',
      observedFinalState: 'RESTRICTED',
      evidenceRecorded: true,
      disclaimer: 'Do not claim complete security.',
    } satisfies Omit<RuntimeAttackResult, 'mode' | 'unavailableReason'>;

    const hookOut = capturePrint({ ...base, mode: 'hook' });
    expect(hookOut).toContain('Runtime: HOOK');
    expect(hookOut).not.toContain('Runtime: RUNTIME');
    expect(hookOut).not.toContain('REAL RUNTIME');

    const runtimeOut = capturePrint({
      ...base,
      mode: 'runtime',
      unavailableReason: null,
    });
    expect(runtimeOut).toContain('Runtime: RUNTIME');
    expect(runtimeOut).not.toContain('Runtime: HOOK');
    expect(runtimeOut).not.toContain('RUNTIME (UNAVAILABLE)');

    const unavailableOut = capturePrint({
      ...base,
      mode: 'runtime',
      contained: false,
      unavailableReason: 'Claude Code CLI not installed/on PATH',
    });
    expect(unavailableOut).toContain('REAL RUNTIME UNAVAILABLE');
    expect(unavailableOut).toContain('Runtime: RUNTIME (UNAVAILABLE)');
    expect(unavailableOut).not.toContain('1 / 1 CONTROLLED ATTACKS CONTAINED');
    expect(unavailableOut).not.toContain('Runtime: HOOK');
  });

  it('veyra attack --ci runs simulation and exits 0 when all contained', async () => {
    expect(existsSync(cli)).toBe(true);
    const { code, out } = await capture(['attack', '--ci']);
    expect(code).toBe(0);
    expect(out).toContain('AGENT ATTACK LAB');
    expect(out).toContain('Runtime: SIMULATION');
    expect(out).toContain('CI regression corpus');
    expect(out).toMatch(/\d+ \/ \d+ CONTROLLED ATTACKS CONTAINED/);
    expect(out).toContain('Secret exposure: NONE');
    expect(out).toContain('Unauthorized execution: NONE');
    expect(out).toContain('Critical escapes: 0');
    expect(out).not.toContain('veyra explain');
  }, 60_000);

  it('tallyAttackResults never invents percentage scores', () => {
    const tally = tallyAttackResults([
      {
        attackId: 'prompt-injection-secret-access',
        name: 'Prompt Injection → Secret Access',
        category: 'prompt-injection',
        passed: true,
        contained: true,
        evidence: [],
        events: [],
        decisions: [],
        signals: [],
        durationMs: 1,
      },
      {
        attackId: '02-dangerous-shell',
        name: 'Dangerous Shell',
        category: 'dangerous-shell',
        passed: false,
        contained: false,
        evidence: [],
        events: [],
        decisions: [],
        signals: [],
        durationMs: 1,
      },
    ]);
    expect(tally.containedCount).toBe(1);
    expect(tally.totalCount).toBe(2);
    expect(tally.secretExposure).toBe('NONE');
    expect(tally.unauthorizedExecution).toContain('Dangerous Shell');
    expect(tally.criticalEscapes).toBe(1);
    expect(JSON.stringify(tally)).not.toMatch(/%|secure score/i);
  });

  it('top-level help advertises attack as front door', async () => {
    const { code, out } = await capture(['help']);
    expect(code).toBe(0);
    expect(out).toContain('Front door:  veyra attack');
    expect(out).toContain('Test whether your agent can be compromised');
  });
});
