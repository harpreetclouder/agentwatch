import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveProjectRoot, VEYRA_DIR_NAME } from '@veyra/storage';

export const BRIDGE_MARKER = 'veyra-watchdog-bridge';
export const CLAUDE_BRIDGE_SCRIPT = 'claude-bridge.sh';
export const CODEX_BRIDGE_SCRIPT = 'codex-bridge.sh';

/** Absolute path to the compiled CLI entry (apps/cli/dist/index.js). */
export function resolveCliEntry(): string {
  // commands/*.js → dist/
  return join(dirname(fileURLToPath(import.meta.url)), '..', 'index.js');
}

export function resolveBridgeRoot(cwd: string = process.cwd()): {
  projectRoot: string;
  veyraDir: string;
  hooksDir: string;
  claudeSettingsPath: string;
  codexHooksPath: string;
  claudeScriptPath: string;
  codexScriptPath: string;
  manifestPath: string;
  cliEntry: string;
} {
  const projectRoot = resolveProjectRoot(cwd);
  const veyraDir = join(projectRoot, VEYRA_DIR_NAME);
  const hooksDir = join(veyraDir, 'hooks');
  return {
    projectRoot,
    veyraDir,
    hooksDir,
    claudeSettingsPath: join(projectRoot, '.claude', 'settings.json'),
    codexHooksPath: join(projectRoot, '.codex', 'hooks.json'),
    claudeScriptPath: join(hooksDir, CLAUDE_BRIDGE_SCRIPT),
    codexScriptPath: join(hooksDir, CODEX_BRIDGE_SCRIPT),
    manifestPath: join(hooksDir, 'manifest.json'),
    cliEntry: resolveCliEntry(),
  };
}

export function isVeyraManagedCommand(command: string): boolean {
  return (
    command.includes(CLAUDE_BRIDGE_SCRIPT) ||
    command.includes(CODEX_BRIDGE_SCRIPT) ||
    command.includes(BRIDGE_MARKER)
  );
}

export type BridgeManifest = {
  version: string;
  installedAt: string;
  adapters: Array<'claude-code' | 'codex'>;
  cliEntry: string;
  /** Absolute path to pre-install Claude settings backup (restored on uninstall). */
  claudeSettingsBackup?: string;
  /** Absolute path to pre-install Codex hooks backup (restored on uninstall). */
  codexHooksBackup?: string;
};
