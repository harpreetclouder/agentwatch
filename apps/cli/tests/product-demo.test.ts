import { describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { resolveCliEntry } from '../src/harness/test-workspace.js';
import { printProductDemo, runProductDemo } from '../src/harness/product-demo.js';
import { runCli } from '../src/cli.js';

const cli = resolveCliEntry();

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

describe('Stage 8 product demo', () => {
  it('runs product demo with honest labeling and containment when hooks work', async () => {
    expect(existsSync(cli)).toBe(true);
    const report = await runProductDemo({ cliEntry: cli });

    // Must never claim live runtime when Claude path did not verify
    if (!report.realRuntime) {
      expect(report.path).toBe('DETERMINISTIC_HOOK');
      expect(
        report.realRuntimeUnavailableReason || report.liveIncompleteReason,
      ).toBeTruthy();
    }

    expect(report.blocked).toBe(true);
    expect(report.policy).toBe('SECRET_ACCESS');
    expect(report.decision).toBe('BLOCK');
    expect(report.executionPrevented).toBe(true);
    expect(report.secretExposure).toBe('NONE');
    expect(report.contained).toBe(true);

    const chunks: string[] = [];
    const orig = console.log;
    console.log = (...a: unknown[]) => {
      chunks.push(a.map(String).join(' '));
    };
    try {
      printProductDemo(report);
    } finally {
      console.log = orig;
    }
    const out = chunks.join('\n');
    expect(out).toContain('VEYRA');
    expect(out).toContain('Runtime Security for AI Agents');
    expect(out).toContain('Fix authentication bug');
    expect(out).toContain('SECRET_ACCESS');
    expect(out).toContain('BLOCK');
    expect(out).toContain('NOT EXECUTED');
    expect(out).toContain('1/1 controlled attack contained');
    expect(out).toContain('not a claim of complete agent security');
    if (report.realRuntimeUnavailableReason) {
      expect(out).toContain('REAL RUNTIME UNAVAILABLE');
      expect(out).not.toMatch(/\nRUNTIME\n/);
    } else if (report.liveIncompleteReason) {
      expect(out).toContain('deterministic PreToolUse hook test');
      expect(out).not.toMatch(/\nRUNTIME\n/);
    }
  }, 200_000);

  it('veyra demo (default) exits 0 on contained product demo', async () => {
    expect(existsSync(cli)).toBe(true);
    const { code, out } = await capture(['demo']);
    expect(code).toBe(0);
    expect(out).toContain('VEYRA');
    expect(out).toContain('1/1 controlled attack contained');
    expect(out).toContain('SECRET_ACCESS');
  }, 200_000);
});
