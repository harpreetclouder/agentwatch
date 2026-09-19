/**
 * Redact secret-looking values from logs and evidence.
 * Never log secret contents — only resource identity.
 */

const SECRET_PATTERNS: readonly RegExp[] = [
  /\b(sk-[a-zA-Z0-9_-]{8,})\b/g,
  /\b(sk-or-[a-zA-Z0-9_-]{8,})\b/g,
  /\b(sk-proj-[a-zA-Z0-9_-]{8,})\b/g,
  /\b(ghp_[a-zA-Z0-9]{20,})\b/g,
  /\b(AKIA[0-9A-Z]{16})\b/g,
  /\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi,
  /\b(api[_-]?key|password|passwd|secret|token)\s*[:=]\s*["']?[^\s"',;]{4,}/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

export function redactSensitiveValue(value: string): string {
  let out = value;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (match) => {
      if (/^Bearer\s+/i.test(match)) {
        return 'Bearer [REDACTED]';
      }
      if (/BEGIN .*PRIVATE KEY/i.test(match)) {
        return '[REDACTED_PRIVATE_KEY]';
      }
      const eq = match.match(/^([^:=]+)([:=]\s*)/i);
      if (eq) {
        return `${eq[1]}${eq[2]}[REDACTED]`;
      }
      return '[REDACTED]';
    });
  }
  return out;
}

export function sanitizeEvidence(evidence: string[]): string[] {
  return evidence.map((line) => redactSensitiveValue(line));
}

export function sanitizeEventPayload(payload: unknown): unknown {
  if (typeof payload === 'string') {
    return redactSensitiveValue(payload);
  }
  if (Array.isArray(payload)) {
    return payload.map((item) => sanitizeEventPayload(item));
  }
  if (payload && typeof payload === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
      const lower = key.toLowerCase();
      if (
        lower.includes('password') ||
        lower.includes('secret') ||
        lower.includes('token') ||
        lower.includes('authorization') ||
        lower.includes('api_key') ||
        lower.includes('apikey')
      ) {
        out[key] = '[REDACTED]';
      } else {
        out[key] = sanitizeEventPayload(value);
      }
    }
    return out;
  }
  return payload;
}
