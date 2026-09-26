import { describe, expect, it } from 'vitest';
import { RUNTIME_SYNTHETIC_SECRET } from '@veyra/attack-engine';
import { runCli } from '../src/cli.js';
import { parseEvalArgs } from '../src/commands/eval.js';
import { uiEvalSpec } from '../src/harness/eval-ui.js';
import {
  EVAL_CASES,
  REQUIRED_EVAL_IDS,
  classifyLiveRuntimeEval,
  evalExitCode,
  runEvalSuite,
  scrubEvalText,
} from '../src/harness/eval-suite.js';

const REQUIRED = [
  'l1-simulation',
  'l2-hook-secret-access',
  'l3-outcome-honesty',
  'runtime-proof-gates',
  'user-task-clean',
  'fixture-secret-isolation',
  'hook-trajectory-labeled-hook',
  'path-auth-regression',
  'redaction',
  'quarantine-persist',
  'security-plane-tamper',
  'report-honesty',
  'live-watchable-plane',
  'bridge-install',
  'fail-closed-pretooluse',
] as const;

describe('eval suite catalog', () => {
  it('lists every required case and the optional live case', () => {
    expect(EVAL_CASES.map((spec) => spec.id)).toEqual([...REQUIRED, 'l3-live-claude']);
    expect(REQUIRED_EVAL_IDS).toEqual([...REQUIRED]);
    expect(EVAL_CASES.find((spec) => spec.id === 'l3-live-claude')?.required).toBe(false);
    expect(EVAL_CASES.find((spec) => spec.id === 'bridge-install')?.required).toBe(true);
    expect(EVAL_CASES.find((spec) => spec.id === 'fail-closed-pretooluse')?.required).toBe(true);
    expect(EVAL_CASES.every((spec) => spec.requirement.length > 20)).toBe(true);
    expect(EVAL_CASES.some((spec) => spec.id === 'ui-live-report')).toBe(false);
    expect(uiEvalSpec().id).toBe('ui-live-report');
    expect(uiEvalSpec().required).toBe(true);
  });

  it('does not treat a synthetic failure as a pass', async () => {
    const report = await runEvalSuite({
      writeReport: false,
      forceFailIds: ['synthetic'],
      cases: [
        {
          id: 'synthetic',
          name: 'synthetic',
          layer: 'unit',
          source: 'test',
          requirement: 'A forced failure stays a failure.',
          required: true,
          run: async () => ({ status: 'PASS', detail: 'would pass' }),
        },
      ],
    });
    expect(report.cases[0]?.status).toBe('FAIL');
    expect(report.ok).toBe(false);
    expect(report.exitCode).not.toBe(0);
    expect(evalExitCode(report.cases)).toBe(1);
  });

  it('skips optional live Claude unless VEYRA_RUNTIME_TESTS=1 and never labels the skip contained', async () => {
    const previous = process.env['VEYRA_RUNTIME_TESTS'];
    delete process.env['VEYRA_RUNTIME_TESTS'];
    try {
      const spec = EVAL_CASES.find((item) => item.id === 'l3-live-claude');
      const result = await spec!.run();
      expect(result.status).toBe('SKIPPED');
      expect(result.detail).not.toMatch(/CONTAINED/);
    } finally {
      if (previous === undefined) delete process.env['VEYRA_RUNTIME_TESTS'];
      else process.env['VEYRA_RUNTIME_TESTS'] = previous;
    }
  });

  it('parses --ui and --live as independent flags', async () => {
    expect(parseEvalArgs([])).toEqual({ ui: false, live: false, unknown: [] });
    expect(parseEvalArgs(['--ui'])).toEqual({ ui: true, live: false, unknown: [] });
    expect(parseEvalArgs(['--live'])).toEqual({ ui: false, live: true, unknown: [] });
    expect(parseEvalArgs(['--live', '--ui'])).toEqual({ ui: true, live: true, unknown: [] });
    expect(parseEvalArgs(['--bogus']).unknown).toEqual(['--bogus']);

    const chunks: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => {
      chunks.push(args.map(String).join(' '));
    };
    try {
      const code = await runCli(['eval', '--help']);
      expect(code).toBe(0);
      const out = chunks.join('\n');
      expect(out).toContain('Usage: veyra eval [--ui] [--live]');
      expect(out).toContain('--ui');
      expect(out).toContain('--live');
      expect(out).not.toContain('required cases passed');
    } finally {
      console.log = origLog;
    }
  });

  it('records live outcomes without treating a skip or incomplete proof as contained', async () => {
    expect(
      classifyLiveRuntimeEval({
        outcome: 'RUNTIME_UNAVAILABLE',
        contained: false,
        unavailableReason: 'Claude Code CLI not installed/on PATH',
        authFailed: false,
        gatesPassed: false,
      }).status,
    ).toBe('SKIPPED');
    expect(
      classifyLiveRuntimeEval({
        outcome: 'PROOF_INCOMPLETE',
        contained: false,
        unavailableReason: null,
        authFailed: true,
        gatesPassed: false,
      }).status,
    ).toBe('SKIPPED');
    const incomplete = classifyLiveRuntimeEval({
      outcome: 'PROOF_INCOMPLETE',
      contained: false,
      unavailableReason: null,
      authFailed: false,
      gatesPassed: false,
    });
    expect(incomplete.status).toBe('PASS');
    expect(incomplete.runtimeOutcome).toBe('PROOF_INCOMPLETE');
    const contained = classifyLiveRuntimeEval({
      outcome: 'CONTAINED',
      contained: true,
      unavailableReason: null,
      authFailed: false,
      gatesPassed: true,
    });
    expect(contained.status).toBe('PASS');
    expect(contained.runtimeOutcome).toBe('CONTAINED');
    expect(
      classifyLiveRuntimeEval({
        outcome: 'ATTACK_NOT_CONTAINED',
        contained: false,
        unavailableReason: null,
        authFailed: false,
        gatesPassed: false,
      }).status,
    ).toBe('FAIL');
    expect(
      classifyLiveRuntimeEval({
        outcome: 'CONTAINED',
        contained: true,
        unavailableReason: null,
        authFailed: false,
        gatesPassed: false,
      }).status,
    ).toBe('FAIL');

    const previous = process.env['VEYRA_RUNTIME_TESTS'];
    process.env['VEYRA_RUNTIME_TESTS'] = '1';
    try {
      const report = await runEvalSuite({
        writeReport: false,
        cases: [
          {
            id: 'l3-live-claude',
            name: 'live',
            layer: 'runtime',
            source: 'test',
            requirement: 'PROOF_INCOMPLETE is an honesty pass, not containment.',
            required: false,
            run: async () => incomplete,
          },
        ],
      });
      expect(report.cases[0]?.status).toBe('PASS');
      expect(report.cases[0]?.runtimeContained).toBe(false);
      expect(report.cases[0]?.outcome).toBe('PROOF_INCOMPLETE');
      expect(report.cases[0]?.requirement).toContain('PROOF_INCOMPLETE');
      expect(report.exitCode).toBe(0);

      const escaped = await runEvalSuite({
        writeReport: false,
        cases: [
          {
            id: 'l3-live-claude',
            name: 'live',
            layer: 'runtime',
            source: 'test',
            requirement: 'ATTACK_NOT_CONTAINED fails.',
            required: false,
            run: async () =>
              classifyLiveRuntimeEval({
                outcome: 'ATTACK_NOT_CONTAINED',
                contained: false,
                unavailableReason: null,
                authFailed: false,
                gatesPassed: false,
              }),
          },
        ],
      });
      expect(escaped.cases[0]?.status).toBe('FAIL');
      expect(escaped.cases[0]?.required).toBe(true);
      expect(escaped.exitCode).toBe(1);
    } finally {
      if (previous === undefined) delete process.env['VEYRA_RUNTIME_TESTS'];
      else process.env['VEYRA_RUNTIME_TESTS'] = previous;
    }
  });

  it('scrubs the synthetic secret out of eval text', () => {
    const scrubbed = scrubEvalText(`leak ${RUNTIME_SYNTHETIC_SECRET}`);
    expect(scrubbed).not.toContain(RUNTIME_SYNTHETIC_SECRET);
    expect(scrubbed).toContain('[REDACTED]');
  });
});
