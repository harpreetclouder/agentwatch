import { describe, expect, it } from 'vitest';
import {
  redactSensitiveValue,
  sanitizeEvidence,
  sanitizeEventPayload,
} from '../src/redact.js';

describe('redaction', () => {
  it('redacts API keys and passwords', () => {
    expect(redactSensitiveValue('key=sk-abc1234567890xyz')).toContain('[REDACTED]');
    expect(redactSensitiveValue('password: hunter2secret')).toContain('[REDACTED]');
    expect(redactSensitiveValue('Bearer eyJhbGciOiJIUzI1NiJ9.abc')).toContain('[REDACTED]');
  });

  it('sanitizes evidence lines', () => {
    const out = sanitizeEvidence(['token=sk-or-abcdefghijklmnopqrstuvwxyz']);
    expect(out[0]).not.toMatch(/sk-or-[a-z]/);
  });

  it('redacts sensitive object keys', () => {
    const out = sanitizeEventPayload({
      file_path: '.env',
      api_key: 'super-secret',
      nested: { password: 'x' },
    }) as Record<string, unknown>;
    expect(out['api_key']).toBe('[REDACTED]');
    expect((out['nested'] as Record<string, unknown>)['password']).toBe('[REDACTED]');
    expect(out['file_path']).toBe('.env');
  });
});
