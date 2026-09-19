import { access, constants } from 'node:fs/promises';
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

export async function detectCodex(cwd: string = process.cwd()): Promise<boolean> {
  if (await pathExists(join(cwd, 'AGENTS.md'))) {
    return true;
  }
  if (process.env['CODEX'] === '1' || process.env['OPENAI_CODEX'] === '1') {
    return true;
  }

  try {
    await execFileAsync('codex', ['--version'], {
      timeout: 3000,
      windowsHide: true,
    });
    return true;
  } catch {
    return false;
  }
}
