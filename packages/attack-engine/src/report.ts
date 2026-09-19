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
    violations,
    timeline,
    signals,
    summaryLine: `${summary.containedCount}/${summary.totalCount} simulated attacks contained.`,
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
  lines.push(report.summaryLine);
  lines.push('');
  return lines.join('\n');
}
