/**
 * Shared primitives for VEYRA Watchdog.
 * Keep this package free of domain security logic.
 */

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type SecurityState =
  | 'NORMAL'
  | 'WARNING'
  | 'RESTRICTED'
  | 'QUARANTINED'
  | 'REVOKED';

export type Environment = 'local' | 'development' | 'staging' | 'production';

export const SEVERITIES: readonly Severity[] = [
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
] as const;

export const SECURITY_STATES: readonly SecurityState[] = [
  'NORMAL',
  'WARNING',
  'RESTRICTED',
  'QUARANTINED',
  'REVOKED',
] as const;

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

export function isSecurityState(value: unknown): value is SecurityState {
  return typeof value === 'string' && (SECURITY_STATES as readonly string[]).includes(value);
}

export function severityRank(severity: Severity): number {
  switch (severity) {
    case 'LOW':
      return 1;
    case 'MEDIUM':
      return 2;
    case 'HIGH':
      return 3;
    case 'CRITICAL':
      return 4;
  }
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return severityRank(a) >= severityRank(b) ? a : b;
}

export function createId(prefix = 'veyra'): string {
  const rand = Math.random().toString(36).slice(2, 10);
  const time = Date.now().toString(36);
  return `${prefix}_${time}_${rand}`;
}

export function assertNever(value: never, message = 'Unexpected value'): never {
  throw new Error(`${message}: ${String(value)}`);
}
