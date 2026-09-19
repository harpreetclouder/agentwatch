import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  formatExplainReport,
  getAttack,
  listAttacks,
  runAttacks,
  type AttackMode,
  type SecurityReport,
} from '@veyra/attack-engine';
import { resolveProjectRoot, VEYRA_DIR_NAME } from '@veyra/storage';
import { printBanner } from '../ui.js';
import { ensureLocalStore } from '../store.js';
import {
  printRuntimeAttackResult,
  runRuntimeAttackById,
} from '../harness/runtime-attack.js';

function shortId(id: string): string {
  return id.length > 8 ? `${id.slice(0, 8)}` : id;
}

function mark(contained: boolean): string {
  return contained ? '✓ BLOCKED' : '✕ ESCAPED';
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

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

function resolveMode(args: string[]): AttackMode {
  if (
    hasFlag(args, '--runtime') ||
    flagValue(args, '--mode') === 'runtime'
  ) {
    return 'runtime';
  }
  if (
    hasFlag(args, '--simulation') ||
    flagValue(args, '--mode') === 'simulation' ||
    flagValue(args, '--mode') === 'sim'
  ) {
    return 'simulation';
  }
  // Default: simulation (policy corpus)
  return 'simulation';
}

export async function cmdAttack(args: string[]): Promise<number> {
  printBanner();
  const cleaned = args.filter((a) => a !== '--');
  const mode = resolveMode(cleaned);

  if (hasFlag(cleaned, '--list') || hasFlag(cleaned, '-l')) {
    console.log(`Attack corpus (${mode}):`);
    console.log('');
    for (const attack of listAttacks(mode)) {
      const flags = [
        attack.simulationSupported ? 'sim' : null,
        attack.runtimeSupported ? 'runtime' : null,
      ]
        .filter(Boolean)
        .join('+');
      console.log(`  ${attack.id.padEnd(32)} ${attack.name}`);
      console.log(
        `  ${''.padEnd(32)} ${attack.category} · ${attack.severity} · ${flags}`,
      );
      console.log(
        `  ${''.padEnd(32)} expect ${attack.expectedPolicy}/${attack.expectedDecision} → ${attack.expectedFinalState}`,
      );
      console.log('');
    }
    console.log(`Total: ${listAttacks(mode).length}`);
    console.log('');
    console.log(
      'Run: veyra attack --mode=simulation|runtime [--id=<attack-id>]',
    );
    console.log('     veyra attack --simulation | --runtime');
    console.log('');
    return 0;
  }

  if (mode === 'runtime') {
    return runRuntimeMode(cleaned);
  }

  return runSimulationMode(cleaned);
}

async function runRuntimeMode(args: string[]): Promise<number> {
  const id =
    flagValue(args, '--id') ?? 'prompt-injection-secret-access';
  const attack = getAttack(id);
  if (!attack?.runtimeSupported) {
    console.error(`Attack "${id}" is not runtime-supported.`);
    console.error('Use: veyra attack --mode=runtime --list');
    return 1;
  }

  try {
    const result = await runRuntimeAttackById(attack.id);
    printRuntimeAttackResult(result);
    return result.contained ? 0 : 1;
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    return 1;
  }
}

async function runSimulationMode(args: string[]): Promise<number> {
  console.log('VEYRA ATTACK LAB');
  console.log('');
  console.log('Mode:');
  console.log('SIMULATION');
  console.log('');

  const id = flagValue(args, '--id');
  const { store, rootDir } = ensureLocalStore();

  try {
    const resolvedIds = id
      ? [getAttack(id)?.id ?? id].filter(Boolean)
      : undefined;

    const { summary, report } = await runAttacks({
      store,
      agentName: 'Claude Code',
      ...(resolvedIds ? { attackIds: resolvedIds } : {}),
    });

    if (summary.totalCount === 0) {
      console.log(`No simulation attacks matched${id ? ` id=${id}` : ''}.`);
      console.log('Use: veyra attack --mode=simulation --list');
      console.log('');
      return 1;
    }

    console.log('Agent:');
    console.log(summary.agentName);
    console.log('');
    console.log(`Session: ${shortId(summary.sessionId)}`);
    console.log('');
    console.log('Result:');
    console.log('');

    summary.results.forEach((result, index) => {
      const n = `${index + 1}/${summary.totalCount}`;
      const name = result.name.padEnd(36);
      console.log(`[${n}] ${name} ${mark(result.contained)}`);
    });

    console.log('');
    console.log('RESULT:');
    console.log('');
    console.log(
      `  ${summary.containedCount}/${summary.totalCount} controlled attack scenarios contained.`,
    );
    console.log('');
    console.log('Do not claim complete security.');
    console.log('');

    const primary = report.violations[0];
    if (primary) {
      console.log('------------------------------------------');
      console.log('');
      console.log('TASK');
      console.log(report.task);
      console.log('');
      console.log('REQUESTED ACTION');
      console.log(primary.event);
      console.log('');
      console.log('AUTHORITY');
      console.log('DENIED');
      console.log('');
      console.log('RULE');
      console.log(primary.rule);
      console.log('');
      console.log('REASON');
      console.log(primary.why);
      console.log('');
      console.log('ACTION');
      console.log(
        primary.decision === 'BLOCK' || primary.decision === 'QUARANTINE'
          ? 'BLOCKED'
          : primary.decision,
      );
      console.log('');
    }

    saveLastReport(rootDir, report);

    console.log('View report:');
    console.log('');
    console.log('  veyra explain');
    console.log('');

    return summary.containedCount === summary.totalCount ? 0 : 1;
  } finally {
    store.close();
  }
}

function saveLastReport(securityPlaneRoot: string, report: SecurityReport): void {
  const reportsDir = join(securityPlaneRoot, 'reports');
  mkdirSync(reportsDir, { recursive: true });
  writeFileSync(join(reportsDir, 'last.json'), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  writeFileSync(join(reportsDir, 'last.txt'), formatExplainReport(report), 'utf8');
}

export function lastReportPath(cwd: string = process.cwd()): string {
  const projectRoot = resolveProjectRoot(cwd);
  return join(projectRoot, VEYRA_DIR_NAME, 'reports', 'last.json');
}
