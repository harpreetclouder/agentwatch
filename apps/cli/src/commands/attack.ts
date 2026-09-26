import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  buildSecurityReportFromRuntimeResult,
  formatExplainReport,
  getAttack,
  listAttacks,
  runAttacks,
  type AttackMode,
  type AttackResult,
  type SecurityReport,
} from '@veyra/attack-engine';
import { resolveProjectRoot, VEYRA_DIR_NAME } from '@veyra/storage';
import {
  printAttackLabBanner,
  printAttackLabFooter,
  printAttackLabHeader,
} from '../ui.js';
import { ensureLocalStore } from '../store.js';
import {
  printRuntimeAttackResult,
  runHookAttackById,
  runLiveRuntimeAttackById,
} from '../harness/runtime-attack.js';
import { resolveWatchableDemoRoot } from '../harness/watchable-plane.js';

const SECRET_CATEGORIES = new Set([
  'credential-access',
  'secret-exfiltration',
  'prompt-injection',
]);

const EXECUTION_CATEGORIES = new Set([
  'dangerous-shell',
  'production-access',
  'mcp-tool-poisoning',
  'privilege-escalation',
  'authority-escalation',
  'control-plane-tampering',
]);

function mark(contained: boolean): string {
  return contained ? '✓' : '✕';
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

/**
 * Resolve lab mode. Distinct: simulation | hook | runtime.
 * `--ci` defaults to simulation (regression corpus).
 */
function resolveMode(args: string[]): AttackMode {
  const explicit = flagValue(args, '--mode')?.toLowerCase();
  if (explicit === 'runtime' || hasFlag(args, '--runtime')) {
    return 'runtime';
  }
  if (explicit === 'hook' || hasFlag(args, '--hook')) {
    return 'hook';
  }
  if (
    explicit === 'simulation' ||
    explicit === 'sim' ||
    hasFlag(args, '--simulation') ||
    hasFlag(args, '--ci')
  ) {
    return 'simulation';
  }
  return 'simulation';
}

export type AttackLabTally = {
  containedCount: number;
  totalCount: number;
  secretExposure: string;
  unauthorizedExecution: string;
  criticalEscapes: number;
};

/** Derive honest containment tallies — never percentage scores. */
export function tallyAttackResults(results: AttackResult[]): AttackLabTally {
  const escaped = results.filter((r) => !r.contained);
  const containedCount = results.length - escaped.length;
  const secretEscapes = escaped.filter((r) => SECRET_CATEGORIES.has(r.category));
  const execEscapes = escaped.filter((r) => EXECUTION_CATEGORIES.has(r.category));
  const criticalEscapes = escaped.filter((r) => {
    const sev = getAttack(r.attackId)?.severity;
    return sev === 'CRITICAL' || sev === 'HIGH';
  }).length;

  return {
    containedCount,
    totalCount: results.length,
    secretExposure:
      secretEscapes.length === 0
        ? 'NONE'
        : secretEscapes.map((r) => r.name).join(', '),
    unauthorizedExecution:
      execEscapes.length === 0
        ? 'NONE'
        : execEscapes.map((r) => r.name).join(', '),
    criticalEscapes,
  };
}

export function printContainedSummary(tally: AttackLabTally): void {
  console.log(
    `${tally.containedCount} / ${tally.totalCount} CONTROLLED ATTACKS CONTAINED`,
  );
  console.log(`Secret exposure: ${tally.secretExposure}`);
  console.log(`Unauthorized execution: ${tally.unauthorizedExecution}`);
  console.log(`Critical escapes: ${tally.criticalEscapes}`);
  console.log('');
}

export async function cmdAttack(args: string[]): Promise<number> {
  const cleaned = args.filter((a) => a !== '--');
  const mode = resolveMode(cleaned);
  const ci = hasFlag(cleaned, '--ci');

  if (hasFlag(cleaned, '--list') || hasFlag(cleaned, '-l')) {
    printAttackLabBanner();
    console.log(`Attack corpus (${mode}):`);
    console.log('');
    for (const attack of listAttacks(mode)) {
      const flags = [
        attack.simulationSupported ? 'sim' : null,
        attack.runtimeSupported ? 'hook+runtime' : null,
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
    console.log('Runtime labels (honest — never upgrade):');
    console.log('  SIMULATION              --mode=simulation   Synthetic AgentEvent → PolicyEngine → Watchdog');
    console.log('  HOOK                    --mode=hook         Claude-shaped PreToolUse → Veyra → deny');
    console.log('  RUNTIME                 --mode=runtime      REAL Claude Code → PreToolUse → Veyra → deny');
    console.log('  RUNTIME (UNAVAILABLE)   Claude missing under --mode=runtime (exit 2; not contained)');
    console.log('');
    console.log(
      'Run: veyra attack --mode=simulation|hook|runtime [--id=<attack-id>]',
    );
    console.log('     veyra attack --ci                 # SIMULATION regression, CI exit codes');
    console.log('');
    return 0;
  }

  if (mode === 'hook') {
    return runHookMode(cleaned);
  }
  if (mode === 'runtime') {
    return runLiveRuntimeMode(cleaned);
  }

  return runSimulationMode(cleaned, { ci });
}

async function runHookMode(args: string[]): Promise<number> {
  const id = flagValue(args, '--id') ?? 'prompt-injection-secret-access';
  const attack = getAttack(id);
  if (!attack?.runtimeSupported) {
    console.error(`Attack "${id}" is not hook-supported.`);
    console.error('Use: veyra attack --mode=hook --list');
    return 1;
  }

  try {
    const workspace = flagValue(args, '--workspace');
    const isolated = hasFlag(args, '--isolated');
    const result = await runHookAttackById(attack.id, {
      ...(workspace ? { workspace } : {}),
      isolated,
    });
    printRuntimeAttackResult(result, {
      ...(isolated
        ? {}
        : {
            livePlaneRoot: workspace
              ? resolve(resolveProjectRoot(), workspace)
              : resolveWatchableDemoRoot(),
          }),
    });
    saveLastReport(
      reportPlaneRoots({ ...(workspace ? { workspace } : {}), isolated }),
      buildSecurityReportFromRuntimeResult(result),
    );
    return result.contained ? 0 : 1;
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    return 1;
  }
}

async function runLiveRuntimeMode(args: string[]): Promise<number> {
  const id = flagValue(args, '--id') ?? 'prompt-injection-secret-access';
  const attack = getAttack(id);
  if (!attack?.runtimeSupported) {
    console.error(`Attack "${id}" is not runtime-supported.`);
    console.error('Use: veyra attack --mode=runtime --list');
    return 1;
  }

  try {
    const workspace = flagValue(args, '--workspace');
    const isolated = hasFlag(args, '--isolated');
    const result = await runLiveRuntimeAttackById(attack.id, {
      ...(workspace ? { workspace } : {}),
      isolated,
    });
    printRuntimeAttackResult(result, {
      ...(isolated
        ? {}
        : {
            livePlaneRoot: workspace
              ? resolve(resolveProjectRoot(), workspace)
              : resolveWatchableDemoRoot(),
          }),
    });
    saveLastReport(
      reportPlaneRoots({ ...(workspace ? { workspace } : {}), isolated }),
      buildSecurityReportFromRuntimeResult(result),
    );
    if (result.unavailableReason) {
      return 2;
    }
    return result.contained ? 0 : 1;
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    return 1;
  }
}

async function runSimulationMode(
  args: string[],
  options: { ci?: boolean } = {},
): Promise<number> {
  printAttackLabHeader({ runtime: 'SIMULATION' });
  if (options.ci) {
    console.log('CI regression corpus (simulation only).');
    console.log('');
  }
  console.log('Running controlled security attacks...');
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

    summary.results.forEach((result) => {
      console.log(`  ${mark(result.contained)} ${result.name}`);
    });

    console.log('');
    const tally = tallyAttackResults(summary.results);
    printContainedSummary(tally);

    saveLastReport([rootDir], report);
    printAttackLabFooter(options.ci ? { ci: true } : undefined);

    return tally.containedCount === tally.totalCount ? 0 : 1;
  } finally {
    store.close();
  }
}

/**
 * Planes that receive last.json.
 * Always the project `.veyra` so `veyra report` works with no flags.
 * Hook/runtime also copy onto the watchable demo plane (unless --isolated).
 */
function reportPlaneRoots(options: { workspace?: string; isolated: boolean }): string[] {
  const project = join(resolveProjectRoot(), VEYRA_DIR_NAME);
  if (options.isolated) return [project];
  const ws = options.workspace
    ? resolve(resolveProjectRoot(), options.workspace)
    : resolveWatchableDemoRoot();
  const plane = join(ws, VEYRA_DIR_NAME);
  return resolve(plane) === resolve(project) ? [project] : [project, plane];
}

function saveLastReport(securityPlaneRoots: string[], report: SecurityReport): void {
  const seen = new Set<string>();
  const written: string[] = [];
  for (const plane of securityPlaneRoots) {
    const resolved = resolve(plane);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    const reportsDir = join(resolved, 'reports');
    mkdirSync(reportsDir, { recursive: true });
    const file = join(reportsDir, 'last.json');
    writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    writeFileSync(join(reportsDir, 'last.txt'), formatExplainReport(report), 'utf8');
    written.push(file);
  }
  const primary = lastReportPath();
  console.log(`Report: ${primary}`);
  for (const file of written) {
    if (resolve(file) !== resolve(primary)) {
      console.log(`Report copy: ${file}`);
    }
  }
}

/** Candidate last.json paths: project plane, then examples/real-agent-demo plane. */
export function lastReportCandidates(cwd: string = process.cwd()): string[] {
  const project = join(resolveProjectRoot(cwd), VEYRA_DIR_NAME, 'reports', 'last.json');
  const demo = join(resolveWatchableDemoRoot(cwd), VEYRA_DIR_NAME, 'reports', 'last.json');
  return resolve(project) === resolve(demo) ? [project] : [project, demo];
}

/**
 * Path `veyra report` reads. Newest artifact wins so a runtime run on the
 * demo plane beats a stale simulation report (and the reverse).
 */
export function lastReportPath(cwd: string = process.cwd()): string {
  const candidates = lastReportCandidates(cwd);
  const existing = candidates.filter((path) => existsSync(path));
  if (existing.length === 0) {
    return candidates[0]!;
  }
  const demo = candidates[1];
  existing.sort((a, b) => {
    const delta = statSync(b).mtimeMs - statSync(a).mtimeMs;
    if (delta !== 0) return delta;
    if (demo && resolve(a) === resolve(demo)) return -1;
    if (demo && resolve(b) === resolve(demo)) return 1;
    return 0;
  });
  return existing[0]!;
}
