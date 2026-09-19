import { printBanner } from '../ui.js';
import { bridgeStatus, installBridge, uninstallBridge } from '../bridge/install.js';
import { ensureLocalStore } from '../store.js';

function flagValue(args: string[], name: string): string | undefined {
  const prefixed = args.find((a) => a.startsWith(`${name}=`));
  if (prefixed) {
    return prefixed.slice(name.length + 1);
  }
  const idx = args.indexOf(name);
  if (idx >= 0 && args[idx + 1] && !args[idx + 1]!.startsWith('-')) {
    return args[idx + 1];
  }
  return undefined;
}

function parseAdapters(args: string[]): Array<'claude-code' | 'codex'> {
  const raw = (flagValue(args, '--adapter') ?? 'all').toLowerCase();
  if (raw === 'claude-code' || raw === 'claude') {
    return ['claude-code'];
  }
  if (raw === 'codex') {
    return ['codex'];
  }
  return ['claude-code', 'codex'];
}

/**
 * Live adapter bridge: install / uninstall / status for Claude Code + Codex hooks.
 */
export async function cmdBridge(args: string[]): Promise<number> {
  printBanner();
  const [sub, ...rest] = args;
  const action = sub ?? 'status';

  // Ensure .veyra plane exists for scripts/manifest
  const { store, rootDir } = ensureLocalStore();
  store.close();

  if (action === 'install') {
    const adapters = parseAdapters(rest);
    const result = installBridge({ adapters });
    console.log('Live bridge installed.');
    console.log('');
    console.log(`  Plane:    ${rootDir}`);
    console.log(`  Adapters: ${result.adapters.join(', ')}`);
    if (adapters.includes('claude-code')) {
      if (result.claudeMode === 'live') {
        console.log(`  Claude:   ${result.claudeSettingsPath}`);
      } else {
        console.log(`  Claude:   PATCH ONLY (could not write .claude/settings.json)`);
        console.log(`  Patch:    ${result.claudePatchPath}`);
        console.log('            Merge patch hooks into .claude/settings.json, or re-run');
        console.log('            `veyra bridge install` in a normal (non-sandboxed) terminal.');
      }
    }
    if (adapters.includes('codex')) {
      console.log(`  Codex:    ${result.codexHooksPath}`);
    }
    console.log('');
    console.log('Next:');
    console.log('  • Restart Claude Code / Codex so hooks reload');
    console.log('  • Codex: review + trust hooks via /hooks');
    console.log('  • Agent tool calls now flow through VEYRA Watchdog');
    console.log('');
    return 0;
  }

  if (action === 'uninstall') {
    const result = uninstallBridge();
    console.log('Live bridge uninstalled (VEYRA-managed hooks removed).');
    if (result.restored) {
      console.log('  Restored pre-install Claude/Codex configuration from backup.');
    }
    console.log('');
    console.log(`  Project: ${result.projectRoot}`);
    console.log('');
    return 0;
  }

  if (action === 'status') {
    const status = bridgeStatus();
    console.log('Live bridge status');
    console.log('');
    console.log(`  Project:  ${status.projectRoot}`);
    console.log(`  Claude:   ${status.claudeInstalled ? 'INSTALLED' : 'not installed'}`);
    console.log(`  Codex:    ${status.codexInstalled ? 'INSTALLED' : 'not installed'}`);
    if (status.manifest?.installedAt) {
      console.log(`  Manifest: ${status.manifest.installedAt}`);
      console.log(`  Adapters: ${(status.manifest.adapters ?? []).join(', ') || '(none)'}`);
    }
    console.log('');
    console.log('Usage:');
    console.log('  veyra bridge install [--adapter=claude-code|codex|all]');
    console.log('  veyra bridge uninstall');
    console.log('  veyra bridge status');
    console.log('');
    return 0;
  }

  console.error(`Unknown bridge subcommand: ${action}`);
  console.log('Use: veyra bridge install | uninstall | status');
  console.log('Help: veyra bridge --help');
  return 1;
}
