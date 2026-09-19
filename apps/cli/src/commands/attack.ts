import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  formatExplainReport,
  listAttacks,
  runAttacks,
  type SecurityReport,
} from '@jev/attack-engine';
import { resolveProjectRoot, JEV_DIR_NAME } from '@jev/storage';
import { printBanner } from '../ui.js';
import { ensureLocalStore } from '../store.js';

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

export async function cmdAttack(args: string[]): Promise<number> {
  printBanner();

  if (hasFlag(args, '--list') || hasFlag(args, '-l')) {
    console.log('Attack corpus:');
    console.log('');
    for (const attack of listAttacks()) {
      console.log(`  ${attack.id.padEnd(28)} ${attack.name}`);
      console.log(`  ${''.padEnd(28)} ${attack.category} · ${attack.severity}`);
      console.log('');
    }
    console.log(`Total: ${listAttacks().length}`);
    console.log('');
    console.log('Run: jev attack [--id=<attack-id>]');
    console.log('');
    return 0;
  }

  console.log('╭────────────────────────────────────╮');
  console.log('│      JEV AGENT SECURITY TEST       │');
  console.log('╰────────────────────────────────────╯');
  console.log('');

  const id = flagValue(args, '--id');
  const { store, rootDir } = ensureLocalStore();

  try {
    const { summary, report } = await runAttacks({
      store,
      agentName: 'Claude Code',
      ...(id ? { attackIds: [id] } : {}),
    });

    if (summary.totalCount === 0) {
      console.log(`No attacks matched${id ? ` id=${id}` : ''}.`);
      console.log('Use: jev attack --list');
      console.log('');
      return 1;
    }

    console.log(`Target:  ${summary.agentName}`);
    console.log(`Session: ${shortId(summary.sessionId)}`);
    console.log('');

    summary.results.forEach((result, index) => {
      const n = `${index + 1}/${summary.totalCount}`;
      const name = result.name.padEnd(32);
      console.log(`[${n}] ${name} ${mark(result.contained)}`);
    });

    console.log('');
    console.log('Result:');
    console.log('');
    console.log(`  ${summary.containedCount}/${summary.totalCount} simulated attacks contained.`);
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
    console.log('  jev explain');
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
  return join(projectRoot, JEV_DIR_NAME, 'reports', 'last.json');
}
