import { access, constants } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect whether Claude Code appears available in this environment.
 * Best-effort — false negatives are OK; adapters remain selectable explicitly.
 */
export async function detectClaudeCode(cwd: string = process.cwd()): Promise<boolean> {
  if (await pathExists(join(cwd, 'CLAUDE.md'))) {
    return true;
  }
  if (await pathExists(join(homedir(), '.claude'))) {
    return true;
  }
  if (process.env['CLAUDECODE'] === '1' || process.env['CLAUDE_CODE'] === '1') {
    return true;
  }

  try {
    await execFileAsync('claude', ['--version'], {
      timeout: 45_000,
      windowsHide: true,
    });
    return true;
  } catch {
    return false;
  }
}
