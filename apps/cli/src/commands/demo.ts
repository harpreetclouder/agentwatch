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
  runLiveClaudeRuntimeProof,
  type DemoMode,
} from '../harness/demo-proof.js';
import { resolveProjectRoot } from '@veyra/storage';

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

function resolveMode(args: string[]): DemoMode {
  const mode = (flagValue(args, '--mode') ?? 'hook').toLowerCase();
  if (mode === 'runtime' || mode === 'live' || mode === 'claude') {
    return 'runtime';
  }
  return 'hook';
}

/**
 * Stage 3 demo:
 * - --mode=hook     deterministic PreToolUse wire-format proof (default)
 * - --mode=runtime  live Claude Code when available; never fakes success
 */
export async function cmdDemo(args: string[]): Promise<number> {
  printBanner();
  const cleaned = args.filter((a) => a !== '--');
  const mode = resolveMode(cleaned);
  const cli = resolveCliEntry();
  if (!existsSync(cli)) {
    console.error('CLI not built. Run: pnpm --filter veyra build');
    return 1;
  }

  const projectRoot = resolveProjectRoot(process.cwd());
  const exampleRoot = join(projectRoot, 'examples', 'real-agent-demo');
  const workspaceFlag = flagValue(cleaned, '--workspace');

  let workspace: string;
  let cleanup: (() => void) | null = null;

  if (workspaceFlag) {
    workspace = resolve(projectRoot, workspaceFlag);
    prepareDemoWorkspace(workspace, exampleRoot);
  } else if (mode === 'runtime' && existsSync(exampleRoot)) {
    // Live runtime uses the committed example tree (or a temp clone if dirty isolation preferred)
    workspace = exampleRoot;
    prepareDemoWorkspace(workspace, exampleRoot);
  } else {
    const tmp = mkdtempSync(join(tmpdir(), 'veyra-demo-'));
    materializeExampleIntoTemp(exampleRoot, tmp);
    workspace = tmp;
    cleanup = () => rmSync(tmp, { recursive: true, force: true });
  }

  try {
    if (mode === 'runtime') {
      const report = await runLiveClaudeRuntimeProof({
        workspace,
        cliEntry: cli,
      });
      printDemoProof(report);
      // Runtime mode: exit 0 only on live claim; 2 = not executed; 1 = incomplete proof
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
