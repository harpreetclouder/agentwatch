import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { printBanner } from '../ui.js';
import { resolveCliEntry } from '../harness/test-workspace.js';
import {
  materializeExampleIntoTemp,
  prepareDemoWorkspace,
  printDemoProof,
  runHookProtocolProof,
  runHookTrajectoryProof,
  runLiveClaudeRuntimeProof,
  runLiveTrajectoryAttack,
  type DemoMode,
} from '../harness/demo-proof.js';
import { printProductDemo, runProductDemo } from '../harness/product-demo.js';
import { resolveProjectRoot } from '@veyra/storage';
import { printLiveWatchHint } from '../harness/watchable-plane.js';

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

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

/**
 * Stage 8 default = product demo.
 * Advanced modes remain available via --mode=.
 */
function resolveMode(args: string[]): DemoMode | 'product' {
  if (!flagValue(args, '--mode') && !hasFlag(args, '--hook') && !hasFlag(args, '--runtime')) {
    return 'product';
  }
  const mode = (flagValue(args, '--mode') ?? 'hook').toLowerCase();
  if (mode === 'product' || mode === 'stage8') {
    return 'product';
  }
  if (mode === 'runtime' || mode === 'live' || mode === 'claude' || hasFlag(args, '--runtime')) {
    return 'runtime';
  }
  if (
    mode === 'live-trajectory-attack' ||
    mode === 'live-trajectory' ||
    mode === 'live_trajectory'
  ) {
    return 'live-trajectory-attack';
  }
  // Honest rename; stage6 / trajectory / exfil remain temporary aliases.
  if (
    mode === 'hook-trajectory-proof' ||
    mode === 'hook-trajectory' ||
    mode === 'stage6' ||
    mode === 'trajectory' ||
    mode === 'exfil'
  ) {
    return 'hook-trajectory-proof';
  }
  return 'hook';
}

/**
 * `veyra demo` — Stage 8 product demonstration (default).
 *
 * Advanced:
 * - --mode=hook                   deterministic PreToolUse proof
 * - --mode=runtime                live Claude only (exit 2 if unavailable)
 * - --mode=hook-trajectory-proof  multi-step hook trajectory + localhost collector
 * - --mode=live-trajectory-attack live Claude multi-step (exit 2 if unavailable)
 * Aliases: --mode=stage6 → hook-trajectory-proof
 */
export async function cmdDemo(args: string[]): Promise<number> {
  const cleaned = args.filter((a) => a !== '--');
  const mode = resolveMode(cleaned);
  const cli = resolveCliEntry();
  if (!existsSync(cli)) {
    console.error('CLI not built. Run: pnpm --filter veyra build');
    return 1;
  }

  // Stage 8 product demo — defaults to examples/real-agent-demo (LIVE-watchable)
  if (mode === 'product') {
    try {
      const workspaceFlag = flagValue(cleaned, '--workspace');
      const report = await runProductDemo({
        cliEntry: cli,
        ...(workspaceFlag
          ? {
              workspace: resolve(
                resolveProjectRoot(process.cwd()),
                workspaceFlag,
              ),
            }
          : {}),
        isolated: hasFlag(cleaned, '--isolated'),
      });
      // No generic WATCHDOG banner — product demo has its own header
      printProductDemo(report);
      return report.contained ? 0 : 1;
    } catch (err) {
      printBanner();
      console.error(err instanceof Error ? err.message : String(err));
      return 1;
    }
  }

  printBanner();
  const projectRoot = resolveProjectRoot(process.cwd());
  const exampleRoot = join(projectRoot, 'examples', 'real-agent-demo');
  const workspaceFlag = flagValue(cleaned, '--workspace');

  let workspace: string;
  let cleanup: (() => void) | null = null;

  const needsExample =
    mode === 'runtime' ||
    mode === 'hook-trajectory-proof' ||
    mode === 'live-trajectory-attack';

  if (workspaceFlag) {
    workspace = resolve(projectRoot, workspaceFlag);
    prepareDemoWorkspace(workspace, exampleRoot);
  } else if (hasFlag(cleaned, '--isolated')) {
    const tmp = mkdtempSync(join(tmpdir(), 'veyra-demo-'));
    materializeExampleIntoTemp(exampleRoot, tmp);
    workspace = tmp;
    cleanup = () => rmSync(tmp, { recursive: true, force: true });
  } else if (needsExample && existsSync(exampleRoot)) {
    workspace = exampleRoot;
    prepareDemoWorkspace(workspace, exampleRoot);
  } else if (existsSync(exampleRoot)) {
    // Default hook mode also uses watchable plane for LIVE parity
    workspace = exampleRoot;
    prepareDemoWorkspace(workspace, exampleRoot);
  } else {
    const tmp = mkdtempSync(join(tmpdir(), 'veyra-demo-'));
    materializeExampleIntoTemp(exampleRoot, tmp);
    workspace = tmp;
    cleanup = () => rmSync(tmp, { recursive: true, force: true });
  }

  if (!cleanup) {
    printLiveWatchHint(workspace);
  }

  try {
    if (mode === 'hook-trajectory-proof') {
      const report = await runHookTrajectoryProof({
        workspace,
        cliEntry: cli,
      });
      printDemoProof(report);
      return report.claimReady ? 0 : 1;
    }

    if (mode === 'live-trajectory-attack') {
      const report = await runLiveTrajectoryAttack({
        workspace,
        cliEntry: cli,
      });
      printDemoProof(report);
      if (report.mode === 'RUNTIME_NOT_EXECUTED') {
        return 2;
      }
      return report.claimReady ? 0 : 1;
    }

    if (mode === 'runtime') {
      const report = await runLiveClaudeRuntimeProof({
        workspace,
        cliEntry: cli,
      });
      printDemoProof(report);
      if (report.mode === 'RUNTIME_NOT_EXECUTED') {
        return 2;
      }
      return report.claimReady ? 0 : 1;
    }

    const report = await runHookProtocolProof({
      workspace,
      cliEntry: cli,
    });
    printDemoProof(report);
    return report.claimReady ? 0 : 1;
  } finally {
    cleanup?.();
  }
}
