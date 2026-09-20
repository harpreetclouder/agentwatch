import { afterEach, describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { resolveCliEntry } from '../src/harness/test-workspace.js';
import {
  printRuntimeAttackResult,
  runHookAttackById,
} from '../src/harness/runtime-attack.js';
import { runCli } from '../src/cli.js';

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

describe('Stage H attack lab modes', () => {
  it('lists hook-capable attacks separately from full simulation corpus', async () => {
    const { code, out } = await capture(['attack', '--list', '--mode=hook']);
    expect(code).toBe(0);
    expect(out).toContain('prompt-injection-secret-access');
    expect(out).toContain('hook');
    expect(out).not.toContain('02-dangerous-shell');
  });

  it('runs prompt-injection-secret-access via real hooks (no simulateEvent)', async () => {
    expect(existsSync(cli)).toBe(true);
    const result = await runHookAttackById('prompt-injection-secret-access');
    expect(result.mode).toBe('hook');
    expect(result.contained).toBe(true);
    expect(result.checks.every((c) => c.ok)).toBe(true);
    expect(result.observedPolicy).toBe('SECRET_ACCESS');
    expect(result.disclaimer).toContain('Do not claim complete security');

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
    const out = chunks.join('\n');
    expect(out).toContain('VEYRA ATTACK LAB');
    expect(out).toContain('HOOK');
    expect(out).toContain('Prompt Injection → Secret Access');
    expect(out).toContain('✓ Injection encountered');
    expect(out).toContain('✓ SECRET_ACCESS');
    expect(out).toContain('✓ BLOCK');
    expect(out).toContain('1/1 controlled attack contained');
    expect(out).toContain('Do not claim complete security');
  }, 30_000);

  it('veyra attack --mode=hook exits 0 when contained', async () => {
    expect(existsSync(cli)).toBe(true);
    const { code, out } = await capture(['attack', '--mode=hook']);
    expect(code).toBe(0);
    expect(out).toContain('VEYRA ATTACK LAB');
    expect(out).toContain('HOOK');
    expect(out).toContain('1/1 controlled attack contained');
  }, 30_000);

  it('veyra attack --ci runs simulation and exits 0 when all contained', async () => {
    expect(existsSync(cli)).toBe(true);
    const { code, out } = await capture(['attack', '--ci']);
    expect(code).toBe(0);
    expect(out).toContain('SIMULATION');
    expect(out).toMatch(/contained:\s+\d+/);
    expect(out).toMatch(/not-contained:\s+0/);
  }, 60_000);
});
