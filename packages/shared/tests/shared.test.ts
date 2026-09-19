import { describe, expect, it } from 'vitest';
import { createId, isSeverity, maxSeverity, severityRank } from '../src/index.js';

describe('@veyra/shared', () => {
  it('ranks severities', () => {
    expect(severityRank('LOW')).toBeLessThan(severityRank('CRITICAL'));
    expect(maxSeverity('LOW', 'HIGH')).toBe('HIGH');
  });

  it('validates severity values', () => {
    expect(isSeverity('HIGH')).toBe(true);
    expect(isSeverity('NOPE')).toBe(false);
  });

  it('creates prefixed ids', () => {
    expect(createId('evt')).toMatch(/^evt_/);
  });
});
