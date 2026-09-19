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

  it('redacts authorization headers, AWS keys, and private key blocks', () => {
    expect(redactSensitiveValue('Authorization: Bearer super-secret-token-value')).toContain(
      '[REDACTED]',
    );
    expect(redactSensitiveValue('aws_access_key_id = AKIAIOSFODNN7EXAMPLE')).toContain(
      '[REDACTED]',
    );
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----';
    expect(redactSensitiveValue(pem)).toBe('[REDACTED_PRIVATE_KEY]');
    expect(redactSensitiveValue(pem)).not.toContain('MIIE');
  });

  it('sanitizes evidence lines without storing secret contents', () => {
    const out = sanitizeEvidence([
      'token=sk-or-abcdefghijklmnopqrstuvwxyz',
      'resource=.env',
      'category=env_or_credential_file',
    ]);
    expect(out[0]).not.toMatch(/sk-or-[a-z]/);
    expect(out[1]).toContain('resource=.env');
    expect(out[2]).toContain('category=');
  });

  it('redacts sensitive object keys', () => {
    const out = sanitizeEventPayload({
      file_path: '.env',
      api_key: 'super-secret',
      authorization: 'Bearer abc',
      nested: { password: 'x', client_secret: 'y' },
    }) as Record<string, unknown>;
    expect(out['api_key']).toBe('[REDACTED]');
    expect(out['authorization']).toBe('[REDACTED]');
    expect((out['nested'] as Record<string, unknown>)['password']).toBe('[REDACTED]');
    expect((out['nested'] as Record<string, unknown>)['client_secret']).toBe('[REDACTED]');
    expect(out['file_path']).toBe('.env');
  });
});
