import { describe, expect, it } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCli } from '../src/cli.js';
import type { SecurityReport } from '@veyra/attack-engine';

async function capture(argv: string[], cwd?: string): Promise<{ code: number; out: string }> {
  const chunks: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  const prev = process.cwd();
  console.log = (...args: unknown[]) => {
    chunks.push(args.map(String).join(' '));
  };
  console.error = (...args: unknown[]) => {
    chunks.push(args.map(String).join(' '));
  };
  try {
    if (cwd) process.chdir(cwd);
    const code = await runCli(argv);
    return { code, out: chunks.join('\n') };
  } finally {
    console.log = origLog;
    console.error = origErr;
    process.chdir(prev);
  }
}

describe('veyra report', () => {
  it('prints contained/not-contained counts and --json', async () => {
    const root = join(tmpdir(), `veyra-report-test-${Date.now()}`);
    mkdirSync(join(root, '.veyra', 'reports'), { recursive: true });
    const report: SecurityReport = {
      title: 'AGENT SECURITY REPORT',
      agentName: 'Claude Code',
      sessionId: 'sess_test',
      task: 'Fix authentication bug',
      finalState: 'RESTRICTED',
      containedCount: 9,
      escapedCount: 1,
      totalCount: 10,
      violations: [
        {
          event: 'file_read(.env)',
          decision: 'BLOCK',
          severity: 'HIGH',
          rule: 'SECRET_ACCESS',
          why: 'no authority',
          evidence: ['resource=.env'],
        },
      ],
      timeline: [],
      signals: [],
      summaryLine: '9/10 controlled attacks contained; 1 not contained.',
    };
    writeFileSync(
      join(root, '.veyra', 'reports', 'last.json'),
      `${JSON.stringify(report, null, 2)}\n`,
    );

    try {
      const text = await capture(['report'], root);
      expect(text.code).toBe(0);
      expect(text.out).toContain('SECRET_ACCESS');
      expect(text.out).toMatch(/contained:\s*9/);
      expect(text.out).toMatch(/not-contained:\s*1/);
      expect(text.out).not.toMatch(/\d+%\s*secure/i);

      const json = await capture(['report', '--json'], root);
      expect(json.code).toBe(0);
      const parsed = JSON.parse(json.out) as SecurityReport;
      expect(parsed.containedCount).toBe(9);
      expect(parsed.escapedCount).toBe(1);
      expect(parsed.totalCount).toBe(10);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('help advertises report command', async () => {
    const { code, out } = await capture(['help']);
    expect(code).toBe(0);
    expect(out).toContain('report');
    expect(out).toContain('Test whether your agent can be compromised');
    expect(out).toContain('veyra attack --ci');
  });
});
