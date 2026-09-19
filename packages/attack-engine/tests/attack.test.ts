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
  it('lists 10 scenarios', () => {
    expect(listAttacks()).toHaveLength(10);
  });

  it('contains all corpus attacks when run together', async () => {
    const store = SqliteVeyraStore.openMemory();
    const { summary, results } = await runAttacks({ store });

    expect(results).toHaveLength(10);
    expect(summary.totalCount).toBe(10);
    expect(summary.containedCount).toBe(10);
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
      attackIds: ['01-prompt-injection-secrets'],
    });

    expect(results).toHaveLength(1);
    expect(results[0]?.contained).toBe(true);
    expect(results[0]?.passed).toBe(true);
    expect(results[0]?.decisions.some((d) => d.ruleId === 'SECRET_ACCESS')).toBe(true);
    expect(
      results[0]?.signals.some((s) => s.type === 'injection_then_secret_access'),
    ).toBe(true);

    expect(summary.containedCount).toBe(1);
    expect(summary.totalCount).toBe(1);
    expect(report.violations.length).toBeGreaterThan(0);
    expect(report.violations.some((v) => v.rule === 'SECRET_ACCESS')).toBe(true);
    expect(report.violations.some((v) => v.decision === 'BLOCK')).toBe(true);

    const text = formatExplainReport(report);
    expect(text).toContain('SECRET_ACCESS');
    expect(text).toContain('BLOCK');
    expect(text).toContain('Fix authentication bug');

    store.close();
  });

  it('records a timeline with blocked secret access', async () => {
    const store = SqliteVeyraStore.openMemory();
    const { report } = await runAttacks({
      store,
      attackIds: ['01-prompt-injection-secrets'],
    });

    const blocked = report.timeline.filter((t) => t.mark === 'block');
    expect(blocked.some((t) => t.target.includes('.env'))).toBe(true);

    store.close();
  });
});
