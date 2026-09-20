import { describe, expect, it } from 'vitest';
import { SqliteVeyraStore } from '@veyra/storage';
import {
  createAttackLab,
  formatExplainReport,
  listAttacks,
  runAttacks,
} from '../src/index.js';

describe('attack lab safety', () => {
  it('creates fake secrets only', () => {
    const lab = createAttackLab();
    expect(lab.root).toContain('veyra-attack-lab-');
    lab.cleanup();
  });
});

describe('attack corpus', () => {
  it('lists 11 scenarios', () => {
    expect(listAttacks()).toHaveLength(11);
  });

  it('marks prompt-injection-secret-access and live-trajectory as hook/runtime-capable', () => {
    const hook = listAttacks('hook');
    const runtime = listAttacks('runtime');
    expect(hook).toHaveLength(2);
    expect(runtime).toHaveLength(2);
    expect(hook.map((a) => a.id).sort()).toEqual([
      'live-trajectory-attack',
      'prompt-injection-secret-access',
    ]);
    expect(runtime[0]?.runtimeSupported).toBe(true);
  });

  it('contains all corpus attacks when run together', async () => {
    const store = SqliteVeyraStore.openMemory();
    const { summary, results } = await runAttacks({ store });

    expect(results).toHaveLength(11);
    expect(summary.totalCount).toBe(11);
    expect(summary.containedCount).toBe(11);
    expect(summary.mode).toBe('simulation');
    for (const result of results) {
      expect(result.contained, result.attackId).toBe(true);
    }

    store.close();
  }, 30_000);
});

describe('prompt injection → credential access', () => {
  it('contains the .env access attempt via SECRET_ACCESS', async () => {
    const store = SqliteVeyraStore.openMemory();
    const { summary, report, results } = await runAttacks({
      store,
      attackIds: ['prompt-injection-secret-access'],
    });

    expect(results).toHaveLength(1);
    expect(results[0]?.contained).toBe(true);
    expect(results[0]?.passed).toBe(true);
    expect(results[0]?.attackId).toBe('prompt-injection-secret-access');
    expect(results[0]?.decisions.some((d) => d.ruleId === 'SECRET_ACCESS')).toBe(true);
    expect(
      results[0]?.signals.some((s) => s.type === 'injection_then_secret_access'),
    ).toBe(true);

    expect(summary.containedCount).toBe(1);
    expect(summary.totalCount).toBe(1);
    expect(summary.mode).toBe('simulation');
    expect(report.violations.length).toBeGreaterThan(0);
    expect(report.violations.some((v) => v.rule === 'SECRET_ACCESS')).toBe(true);
    expect(report.violations.some((v) => v.decision === 'BLOCK')).toBe(true);
    expect(report.runtimeHonesty).toBe('SIMULATION');
    expect(report.mode).toBe('simulation');
    expect(report.secretExposure).toBe('NONE');
    expect(report.blockedBeforeExecution).toBe(true);
    expect(report.topFinding?.rule).toBe('SECRET_ACCESS');
    expect(report.runtimeProof).toBeNull();
    expect(report.disclaimer).toMatch(/User-space hooks/i);

    const text = formatExplainReport(report);
    expect(text).toContain('SECRET_ACCESS');
    expect(text).toContain('BLOCK');
    expect(text).toContain('Fix authentication bug');
    expect(text).toContain('Runtime honesty:');
    expect(text).toContain('SIMULATION');
    expect(text).not.toMatch(/\d+%/);

    store.close();
  });

  it('accepts legacy attack id alias', async () => {
    const store = SqliteVeyraStore.openMemory();
    const { results } = await runAttacks({
      store,
      attackIds: ['01-prompt-injection-secrets'],
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.attackId).toBe('prompt-injection-secret-access');
    store.close();
  });

  it('records a timeline with blocked secret access', async () => {
    const store = SqliteVeyraStore.openMemory();
    const { report } = await runAttacks({
      store,
      attackIds: ['prompt-injection-secret-access'],
    });

    const blocked = report.timeline.filter((t) => t.mark === 'block');
    expect(blocked.some((t) => t.target.includes('.env'))).toBe(true);

    store.close();
  });
});
