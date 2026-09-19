import { describe, expect, it } from 'vitest';
import { runCli } from '../src/cli.js';

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

describe('cli --help', () => {
  it('veyra watch --help prints usage and does not arm a session', async () => {
    const { code, out } = await capture(['watch', '--help']);
    expect(code).toBe(0);
    expect(out).toContain('Usage: veyra watch');
    expect(out).not.toContain('WATCHDOG armed');
    expect(out).not.toContain('Resuming ACTIVE');
  });

  it('veyra bridge --help prints usage and does not error', async () => {
    const { code, out } = await capture(['bridge', '--help']);
    expect(code).toBe(0);
    expect(out).toContain('Usage: veyra bridge');
    expect(out).not.toContain('Unknown bridge subcommand');
  });

  it('veyra attack -h prints usage and does not run corpus', async () => {
    const { code, out } = await capture(['attack', '-h']);
    expect(code).toBe(0);
    expect(out).toContain('Usage: veyra attack');
    expect(out).not.toContain('AGENT SECURITY TEST');
  });

  it('veyra hook --help documents empty-stdin no-op', async () => {
    const { code, out } = await capture(['hook', '--help']);
    expect(code).toBe(0);
    expect(out).toContain('Empty stdin is a no-op');
  });
});
