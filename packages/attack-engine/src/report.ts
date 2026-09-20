import type { VeyraStore } from '@veyra/storage';
import type { Watchdog } from '@veyra/watchdog';
import type { AttackRunSummary, SecurityReport } from './types.js';

export async function buildSecurityReport(
  store: VeyraStore,
  summary: AttackRunSummary,
  watchdog?: Watchdog,
): Promise<SecurityReport> {
  const events = await store.events.findBySession(summary.sessionId);
  const decisions = await store.decisions.findBySession(summary.sessionId);
  const state = await store.securityState.get(summary.sessionId);
  const session = await store.sessions.findById(summary.sessionId);

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

  const signals = (watchdog?.getSignals(summary.sessionId) ?? []).map((s) => ({
    type: s.type,
    severity: s.severity,
    evidence: s.evidence,
  }));

  // Fallback: collect from attack results if watchdog not passed
  if (signals.length === 0) {
    for (const result of summary.results) {
      for (const signal of result.signals ?? []) {
        signals.push({
          type: signal.type,
          severity: signal.severity,
          evidence: signal.evidence,
        });
      }
    }
  }

  return {
    title: 'AGENT SECURITY REPORT',
    agentName: summary.agentName,
    sessionId: summary.sessionId,
    task: session?.taskDescription ?? 'Fix authentication bug',
    finalState: state?.state ?? session?.securityState ?? 'UNKNOWN',
    containedCount: summary.containedCount,
    escapedCount: summary.totalCount - summary.containedCount,
    totalCount: summary.totalCount,
    violations,
    timeline,
    signals,
    summaryLine: `${summary.containedCount}/${summary.totalCount} controlled attacks contained; ${summary.totalCount - summary.containedCount} not contained.`,
  };
}

export function formatExplainReport(report: SecurityReport): string {
  const lines: string[] = [];
  lines.push(report.title);
  lines.push('');
  lines.push(`Agent:`);
  lines.push(report.agentName);
  lines.push('');
  lines.push(`Task:`);
  lines.push(report.task);
  lines.push('');
  lines.push(`Session:`);
  lines.push(report.sessionId);
  lines.push('');
  lines.push('------------------------------------------');
  lines.push('');

  if (report.violations.length === 0) {
    lines.push('No policy violations recorded.');
    lines.push('');
  } else {
    report.violations.forEach((v, index) => {
      lines.push(`VIOLATION #${index + 1}`);
      lines.push('');
      lines.push(`Event:`);
      lines.push(v.event);
      lines.push('');
      lines.push(`Decision:`);
      lines.push(v.decision);
      lines.push('');
      lines.push(`Severity:`);
      lines.push(v.severity);
      lines.push('');
      lines.push(`Rule:`);
      lines.push(v.rule);
      lines.push('');
      lines.push(`Why:`);
      lines.push(v.why);
      lines.push('');
      lines.push(`Evidence:`);
      for (const item of v.evidence) {
        lines.push(`- ${item}`);
      }
      lines.push('');
      lines.push('------------------------------------------');
      lines.push('');
    });
  }

  if (report.signals.length > 0) {
    lines.push('WATCHDOG SIGNALS');
    lines.push('');
    for (const signal of report.signals) {
      lines.push(`[${signal.severity}] ${signal.type}`);
      for (const item of signal.evidence) {
        lines.push(`  - ${item}`);
      }
      lines.push('');
    }
    lines.push('------------------------------------------');
    lines.push('');
  }

  lines.push(`Final state:`);
  lines.push('');
  lines.push(report.finalState);
  lines.push('');
  lines.push('Containment:');
  lines.push(
    `  contained: ${report.containedCount ?? 0}  not-contained: ${report.escapedCount ?? 0}  total: ${report.totalCount ?? 0}`,
  );
  lines.push('');
  lines.push(report.summaryLine);
  lines.push('');
  return lines.join('\n');
}

/** Markdown export for sharing — counts only, no fake security scores. */
export function formatReportMarkdown(report: SecurityReport): string {
  const lines: string[] = [
    `# ${report.title}`,
    '',
    `- **Agent:** ${report.agentName}`,
    `- **Session:** ${report.sessionId}`,
    `- **Task:** ${report.task}`,
    `- **Final state:** ${report.finalState}`,
    `- **Contained:** ${report.containedCount ?? 0}`,
    `- **Not contained:** ${report.escapedCount ?? 0}`,
    `- **Total:** ${report.totalCount ?? 0}`,
    '',
    '## Violations',
    '',
  ];
  if (report.violations.length === 0) {
    lines.push('_No policy violations recorded._', '');
  } else {
    for (const [i, v] of report.violations.entries()) {
      lines.push(`### ${i + 1}. ${v.rule} — ${v.decision} (${v.severity})`);
      lines.push('');
      lines.push(`- Event: \`${v.event}\``);
      lines.push(`- Why: ${v.why}`);
      for (const e of v.evidence) {
        lines.push(`  - ${e}`);
      }
      lines.push('');
    }
  }
  lines.push(report.summaryLine, '');
  lines.push('_Do not claim complete agent security from this report._', '');
  return lines.join('\n');
}

/** Minimal HTML export for sharing — no charts or percentage scores. */
export function formatReportHtml(report: SecurityReport): string {
  const esc = (s: string) =>
    s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  const rows = report.violations
    .map(
      (v) =>
        `<tr><td>${esc(v.rule)}</td><td>${esc(v.decision)}</td><td>${esc(v.severity)}</td><td>${esc(v.event)}</td><td>${esc(v.why)}</td></tr>`,
    )
    .join('\n');
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>${esc(report.title)}</title>
<style>
body{font-family:ui-monospace,Menlo,monospace;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.45;color:#111;background:#fafafa}
h1{font-size:1.25rem} table{border-collapse:collapse;width:100%;font-size:0.85rem}
th,td{border:1px solid #ccc;padding:0.4rem 0.5rem;text-align:left;vertical-align:top}
th{background:#eee} .meta{margin:1rem 0} .note{color:#555;margin-top:1.5rem}
</style></head><body>
<h1>${esc(report.title)}</h1>
<div class="meta">
<div>Agent: ${esc(report.agentName)}</div>
<div>Session: ${esc(report.sessionId)}</div>
<div>Task: ${esc(report.task)}</div>
<div>Final state: ${esc(report.finalState)}</div>
<div>Contained: ${report.containedCount ?? 0} · Not contained: ${report.escapedCount ?? 0} · Total: ${report.totalCount ?? 0}</div>
</div>
<table><thead><tr><th>Rule</th><th>Decision</th><th>Severity</th><th>Event</th><th>Why</th></tr></thead>
<tbody>${rows || '<tr><td colspan="5">No violations</td></tr>'}</tbody></table>
<p>${esc(report.summaryLine)}</p>
<p class="note">Do not claim complete agent security from this report.</p>
</body></html>
`;
}
