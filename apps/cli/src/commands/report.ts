import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  formatExplainReport,
  formatReportHtml,
  formatReportMarkdown,
  type SecurityReport,
} from '@veyra/attack-engine';
import { resolveProjectRoot, VEYRA_DIR_NAME } from '@veyra/storage';
import { printBanner } from '../ui.js';
import { lastReportPath } from './attack.js';
import { openLocalStore } from '../store.js';

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
 * `veyra report` — print last security report with concrete contained/not-contained counts.
 * No percentage "security scores".
 */
export async function cmdReport(args: string[]): Promise<number> {
  const json = hasFlag(args, '--json');
  const md = hasFlag(args, '--md') || hasFlag(args, '--markdown');
  const html = hasFlag(args, '--html');
  const outPath = flagValue(args, '--out');

  let report = loadLastReport();
  if (!report) {
    report = await buildSessionReport();
  }

  if (!report) {
    if (!json) printBanner();
    console.error('No security report found.');
    console.error('Run: veyra attack --ci   or   veyra attack --mode=simulation');
    console.error('Then: veyra report [--json|--md|--html]');
    return 1;
  }

  // Backfill counts for older last.json files
  const contained = report.containedCount ?? 0;
  const total = report.totalCount ?? (contained + (report.escapedCount ?? 0));
  const escaped = report.escapedCount ?? Math.max(0, total - contained);
  report = {
    ...report,
    containedCount: contained,
    escapedCount: escaped,
    totalCount: total,
    summaryLine:
      report.summaryLine ||
      `${contained}/${total} controlled attacks contained; ${escaped} not contained.`,
  };

  if (json) {
    const payload = JSON.stringify(report, null, 2);
    if (outPath) {
      writeFileSync(outPath, `${payload}\n`, 'utf8');
    } else {
      console.log(payload);
    }
    return 0;
  }

  if (!html && !md) printBanner();

  let body: string;
  let defaultName: string;
  if (html) {
    body = formatReportHtml(report);
    defaultName = 'last.html';
  } else if (md) {
    body = formatReportMarkdown(report);
    defaultName = 'last.md';
  } else {
    body = formatExplainReport(report);
    defaultName = 'last.txt';
  }

  if (outPath) {
    writeFileSync(outPath, body.endsWith('\n') ? body : `${body}\n`, 'utf8');
    console.log(`Wrote ${outPath}`);
    return 0;
  }

  if (html || md) {
    const root = resolveProjectRoot();
    const dir = join(root, VEYRA_DIR_NAME, 'reports');
    mkdirSync(dir, { recursive: true });
    const dest = join(dir, defaultName);
    writeFileSync(dest, body.endsWith('\n') ? body : `${body}\n`, 'utf8');
    console.log(body);
    console.log(`Also wrote ${dest}`);
    return 0;
  }

  console.log(body);
  console.log('Containment summary:');
  console.log(
    `  contained: ${contained}  not-contained: ${escaped}  total: ${total}`,
  );
  console.log('');
  return 0;
}

function loadLastReport(): SecurityReport | null {
  const path = lastReportPath();
  if (!existsSync(path)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as SecurityReport;
  } catch {
    return null;
  }
}

/** Build a report from the latest live session when no attack last.json exists. */
async function buildSessionReport(): Promise<SecurityReport | null> {
  const store = openLocalStore();
  if (!store) {
    return null;
  }
  try {
    const session =
      (await store.sessions.findLatestActive()) ?? (await store.sessions.findLatest());
    if (!session) {
      return null;
    }
    const agent = await store.agents.findById(session.agentId);
    const events = await store.events.findBySession(session.id);
    const decisions = await store.decisions.findBySession(session.id);
    const state =
      (await store.securityState.get(session.id))?.state ?? session.securityState;

    const decisionByEvent = new Map(decisions.map((d) => [d.eventId, d]));
    const timeline = events.map((event) => {
      const decision = decisionByEvent.get(event.id);
      const mark =
        decision?.decision === 'BLOCK' || decision?.decision === 'QUARANTINE'
          ? ('block' as const)
          : decision?.decision === 'WARN'
            ? ('warn' as const)
            : ('ok' as const);
      return {
        timestamp: event.timestamp,
        type: event.type === 'security_event' ? 'security' : event.type,
        target: event.action.target ?? event.action.name,
        mark,
      };
    });

    const violations = decisions
      .filter((d) => d.decision !== 'ALLOW')
      .map((d) => {
        const event = events.find((e) => e.id === d.eventId);
        const target = event?.action.target ?? event?.action.name ?? d.eventId;
        return {
          event: `${event?.type ?? 'event'}(${target})`,
          decision: d.decision,
          severity: d.severity,
          rule: d.ruleId,
          why: d.reason,
          evidence: d.evidence,
        };
      });

    const blocked = violations.filter(
      (v) => v.decision === 'BLOCK' || v.decision === 'QUARANTINE',
    ).length;
    const containedCount = blocked > 0 ? 1 : 0;
    const escapedCount = blocked > 0 ? 0 : violations.length > 0 ? 1 : 0;

    return {
      title: 'AGENT SECURITY REPORT',
      agentName: agent?.name ?? session.agentId,
      sessionId: session.id,
      task: session.taskDescription ?? '(live session)',
      finalState: state,
      containedCount,
      escapedCount,
      totalCount: containedCount + escapedCount,
      violations,
      timeline,
      signals: [],
      summaryLine: `${containedCount}/${containedCount + escapedCount} controlled attack scenarios contained; ${escapedCount} not contained.`,
    };
  } finally {
    store.close();
  }
}
