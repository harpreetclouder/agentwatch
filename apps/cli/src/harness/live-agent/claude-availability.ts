import { spawnSync } from 'node:child_process';
import type { RuntimeAvailability } from './types.js';

/** How long to wait for `claude --version` during availability probes (cold starts can exceed 5s). */
export const CLAUDE_DETECT_TIMEOUT_MS = 45_000;

/**
 * Probe whether the Claude Code CLI is on PATH and responsive.
 * Distinguishes missing binary vs slow/timeout vs other failures — never treats timeout as "not installed".
 */
export function claudeAvailable(): RuntimeAvailability {
  const whichCmd = process.platform === 'win32' ? 'where' : 'which';
  const which = spawnSync(whichCmd, ['claude'], {
    encoding: 'utf8',
    timeout: 10_000,
  });
  if (which.status !== 0) {
    return {
      ok: false,
      reason: 'missing',
      error: 'claude CLI not found on PATH (install Claude Code, then retry)',
    };
  }

  const result = spawnSync('claude', ['--version'], {
    encoding: 'utf8',
    timeout: CLAUDE_DETECT_TIMEOUT_MS,
    env: { ...process.env },
  });

  if (result.status === 0) {
    return {
      ok: true,
      reason: 'ok',
      version: (result.stdout || result.stderr || '').trim(),
    };
  }

  const errMsg = result.error?.message ?? '';
  if (errMsg.includes('ENOENT')) {
    return {
      ok: false,
      reason: 'missing',
      error: 'claude CLI not found (ENOENT)',
    };
  }
  if (errMsg.includes('ETIMEDOUT') || result.signal === 'SIGTERM') {
    return {
      ok: false,
      reason: 'timeout',
      error: `claude --version timed out after ${CLAUDE_DETECT_TIMEOUT_MS}ms (CLI slow or stuck — retry, or run: claude --version)`,
    };
  }
  return {
    ok: false,
    reason: 'failed',
    error: errMsg || `claude --version exited ${result.status}`,
  };
}

/**
 * True when Claude failed due to real auth/API credentials — not because the
 * demo task text contains the word "authentication".
 */
export function isClaudeAuthFailure(combined: string): boolean {
  return (
    /OAuth access token is invalid/i.test(combined) ||
    /Failed to authenticate/i.test(combined) ||
    /"type"\s*:\s*"authentication_error"/i.test(combined) ||
    /"error"\s*:\s*"authentication_failed"/i.test(combined) ||
    /authentication_failed/i.test(combined) ||
    /not logged in/i.test(combined)
  );
}
