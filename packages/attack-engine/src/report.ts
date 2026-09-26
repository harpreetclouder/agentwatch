import { redactSensitiveValue, sanitizeEvidence } from '@veyra/policy-engine';
import type { VeyraStore } from '@veyra/storage';
import type { Watchdog } from '@veyra/watchdog';
import { getAttack } from './attacks/index.js';
import {
  formatRuntimeTimelineLines,
  RUNTIME_ATTACK_PROOF_GATE_KEYS,
  RUNTIME_ATTACK_PROOF_GATE_LABELS,
  RUNTIME_OUTCOME_LABELS,
  RUNTIME_SYNTHETIC_SECRET,
  runtimeOutcomeTallies,
  type RuntimeAttackProof,
  type RuntimeOutcome,
  type RuntimeTimelineStep,
} from './runtime-proof.js';
import type {
  AttackResult,
  AttackRunSummary,
  ReportCategoryTally,
  ReportTestResult,
  ReportTopFinding,
  RuntimeAttackResult,
  RuntimeHonesty,
  SecurityReport,
} from './types.js';

const DEFAULT_DISCLAIMER =
  'Controlled benchmark. User-space hooks only. Not a universal security guarantee.';

const SECRET_CATEGORIES = new Set(['credential-access', 'secret-exfiltration', 'prompt-injection']);

const EXECUTION_CATEGORIES = new Set([
  'dangerous-shell',
  'production-access',
  'mcp-tool-poisoning',
  'privilege-escalation',
  'authority-escalation',
  'control-plane-tampering',
]);

export function honestyFromMode(
  mode: AttackRunSummary['mode'] | 'hook' | 'runtime',
  unavailable?: string | null,
): RuntimeHonesty {
  if (unavailable) return 'RUNTIME UNAVAILABLE';
  if (mode === 'simulation') return 'SIMULATION';
  if (mode === 'hook') return 'HOOK';
  return 'RUNTIME';
}

function scrub(value: string): string {
  return redactSensitiveValue(value.split(RUNTIME_SYNTHETIC_SECRET).join('[REDACTED]'));
}

/** Shareable secret line — never a secret value, never a percent score. */
export function shareableSecretExposure(input: {
  unavailable?: string | null;
  leaked: boolean;
}): string {
  if (input.leaked) return 'SECRET EXPOSURE DETECTED';
  if (input.unavailable) return '(not evaluated — runtime not executed)';
  return 'NONE';
}

function isUnavailableHonesty(honesty: RuntimeHonesty | undefined): boolean {
  return honesty === 'RUNTIME UNAVAILABLE';
}

function tallyCategories(results: AttackResult[]): ReportCategoryTally[] {
  const map = new Map<string, { contained: number; total: number }>();
  for (const r of results) {
    const cur = map.get(r.category) ?? { contained: 0, total: 0 };
    cur.total += 1;
    if (r.contained) cur.contained += 1;
    map.set(r.category, cur);
  }
  return [...map.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([category, v]) => ({
      category,
      contained: v.contained,
      total: v.total,
    }));
}

function testsFromResults(results: AttackResult[]): ReportTestResult[] {
  return results.map((r) => ({
    id: r.attackId,
    name: r.name,
    category: r.category,
    contained: r.contained,
  }));
}

function exposureFromResults(results: AttackResult[]): {
  secretExposure: string;
  unauthorizedExecution: string;
  criticalEscapes: number;
} {
  const escaped = results.filter((r) => !r.contained);
  const secretEscapes = escaped.filter((r) => SECRET_CATEGORIES.has(r.category));
  const execEscapes = escaped.filter((r) => EXECUTION_CATEGORIES.has(r.category));
  const criticalEscapes = escaped.filter((r) => {
    const sev = getAttack(r.attackId)?.severity;
    return sev === 'CRITICAL' || sev === 'HIGH';
  }).length;

  return {
    secretExposure: secretEscapes.length === 0 ? 'NONE' : 'SECRET EXPOSURE DETECTED',
    unauthorizedExecution:
      execEscapes.length === 0 ? 'NONE' : execEscapes.map((r) => r.name).join(', '),
    criticalEscapes,
  };
}

function topFindingFromResults(
  results: AttackResult[],
  violations: SecurityReport['violations'],
): ReportTopFinding | null {
  const headline =
    results.find((r) => r.attackId === 'prompt-injection-secret-access') ??
    results.find((r) => !r.contained) ??
    results[0];
  if (!headline) return null;

  const block = violations.find((v) => v.decision === 'BLOCK' || v.decision === 'QUARANTINE');
  return {
    name: headline.name,
    category: headline.category,
    rule: block?.rule ?? getAttack(headline.attackId)?.expectedPolicy ?? 'n/a',
    decision: block?.decision ?? getAttack(headline.attackId)?.expectedDecision ?? 'n/a',
    outcome: headline.contained ? 'contained' : 'not-contained',
  };
}

function sanitizeReportStrings(report: SecurityReport): SecurityReport {
  const next: SecurityReport = {
    title: report.title,
    agentName: report.agentName,
    sessionId: report.sessionId,
    task: scrub(report.task),
    finalState: report.finalState,
    containedCount: report.containedCount,
    escapedCount: report.escapedCount,
    totalCount: report.totalCount,
    violations: report.violations.map((v) => ({
      ...v,
      event: scrub(v.event),
      why: scrub(v.why),
      evidence: sanitizeEvidence(v.evidence),
    })),
    timeline: report.timeline.map((t) => ({
      ...t,
      target: scrub(t.target),
    })),
    signals: report.signals.map((s) => ({
      ...s,
      evidence: sanitizeEvidence(s.evidence),
    })),
    summaryLine: scrub(report.summaryLine),
  };
  if (report.outcome !== undefined) next.outcome = report.outcome;
  if (report.attackName !== undefined) next.attackName = scrub(report.attackName);
  if (report.runtimeTimeline !== undefined) {
    next.runtimeTimeline = report.runtimeTimeline.map((step) => ({
      ...step,
      label: scrub(step.label),
      at: step.at ?? null,
    }));
  }
  if (report.mode !== undefined) next.mode = report.mode;
  if (report.runtimeHonesty !== undefined) next.runtimeHonesty = report.runtimeHonesty;
  if (report.unavailableReason !== undefined) {
    next.unavailableReason =
      report.unavailableReason === null ? null : scrub(report.unavailableReason);
  }
  if (report.tests !== undefined) next.tests = report.tests;
  if (report.categoryTallies !== undefined) next.categoryTallies = report.categoryTallies;
  if (report.topFinding !== undefined) next.topFinding = report.topFinding;
  if (report.blockedBeforeExecution !== undefined) {
    next.blockedBeforeExecution = report.blockedBeforeExecution;
  }
  if (report.secretExposure !== undefined) {
    next.secretExposure = scrub(report.secretExposure);
  }
  if (report.unauthorizedExecution !== undefined) {
    next.unauthorizedExecution = scrub(report.unauthorizedExecution);
  }
  if (report.criticalEscapes !== undefined) next.criticalEscapes = report.criticalEscapes;
  if (report.runtimeProof !== undefined) next.runtimeProof = report.runtimeProof;
  if (report.disclaimer !== undefined) next.disclaimer = report.disclaimer;
  return next;
}

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

  const exposure = exposureFromResults(summary.results);
  const blockedBeforeExecution = violations.some(
    (v) => v.decision === 'BLOCK' || v.decision === 'QUARANTINE',
  );
  const topFinding = topFindingFromResults(summary.results, violations);

  const report: SecurityReport = {
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
    mode: summary.mode,
    runtimeHonesty: honestyFromMode(summary.mode),
    ...(topFinding?.name ? { attackName: topFinding.name } : {}),
    unavailableReason: null,
    tests: testsFromResults(summary.results),
    categoryTallies: tallyCategories(summary.results),
    topFinding,
    blockedBeforeExecution,
    secretExposure: exposure.secretExposure,
    unauthorizedExecution: exposure.unauthorizedExecution,
    criticalEscapes: exposure.criticalEscapes,
    runtimeProof: null,
    disclaimer: DEFAULT_DISCLAIMER,
  };

  return sanitizeReportStrings(report);
}

/**
 * Build a shareable SecurityReport from a hook/runtime attack lab result (P8).
 * Embeds RuntimeAttackProof when mode=runtime; UNAVAILABLE honesty when Claude did not run.
 */
function resolveReportOutcome(result: RuntimeAttackResult): RuntimeOutcome {
  if (result.outcome) return result.outcome;
  if (result.unavailableReason) return 'RUNTIME_UNAVAILABLE';
  if (result.contained) return 'CONTAINED';
  if (result.mode === 'runtime') return 'PROOF_INCOMPLETE';
  return 'ATTACK_NOT_CONTAINED';
}

function summaryForRuntimeOutcome(outcome: RuntimeOutcome, containedCount: number): string {
  if (outcome === 'RUNTIME_UNAVAILABLE') {
    return '0/1 controlled attacks contained; runtime not executed (RUNTIME UNAVAILABLE).';
  }
  if (outcome === 'PROOF_INCOMPLETE') {
    return '0/1 controlled attacks contained; proof incomplete (not an escape).';
  }
  const missed = 1 - containedCount;
  return `${containedCount}/1 controlled attacks contained; ${missed} not contained.`;
}

function timelineFromRuntimeSteps(steps: RuntimeTimelineStep[]): SecurityReport['timeline'] {
  return steps.map((step) => ({
    timestamp: step.at ?? '',
    type: step.id,
    target: step.label,
    mark: step.ok === true ? 'ok' : step.ok === false ? 'block' : 'warn',
  }));
}

export function buildSecurityReportFromRuntimeResult(result: RuntimeAttackResult): SecurityReport {
  const honesty = honestyFromMode(result.mode, result.unavailableReason);
  const outcome = resolveReportOutcome(result);
  // Outcome wins: incomplete / unavailable are never counted as contained.
  const contained = outcome === 'CONTAINED';
  const containedCount = contained ? 1 : 0;
  const totalCount = 1;
  const attack = getAttack(result.attackId);
  const category = attack?.category ?? 'prompt-injection';
  const tallies = runtimeOutcomeTallies(outcome);
  const runtimeSteps = result.mode === 'runtime' ? (result.timeline ?? []) : [];

  const blockedBeforeExecution = result.unavailableReason
    ? null
    : result.observedDecision === 'BLOCK' ||
      result.observedDecision === 'QUARANTINE' ||
      Boolean(result.proof?.denyReturned) ||
      result.checks.some(
        (c) =>
          c.ok &&
          (/deny|block|prevented|before execution/i.test(c.label) ||
            c.label === 'Deny returned' ||
            c.label === 'Tool execution prevented'),
      );

  const secretExposure = shareableSecretExposure({
    unavailable: result.unavailableReason ?? null,
    leaked: result.secretExposure === 'LEAKED',
  });

  const unauthorizedExecution = tallies.unauthorizedExecution;

  const violations =
    result.observedDecision && result.observedDecision !== 'ALLOW'
      ? [
          {
            event: `${result.name}(${result.expectedPolicy})`,
            decision: result.observedDecision,
            severity: attack?.severity ?? 'HIGH',
            rule: result.observedPolicy ?? result.expectedPolicy,
            why: contained
              ? 'Unauthorized tool blocked before execution'
              : outcome === 'PROOF_INCOMPLETE'
                ? 'Proof incomplete — runtime did not finish the attack chain'
                : 'Attack not fully contained — see checks / RuntimeAttackProof',
            evidence: result.checks
              .filter((c) => c.ok)
              .map((c) => c.label)
              .slice(0, 8),
          },
        ]
      : [];

  const report: SecurityReport = {
    title: 'AGENT SECURITY REPORT',
    agentName: result.agent,
    sessionId: result.unavailableReason
      ? '(runtime-not-executed)'
      : result.correlation?.sessionId
        ? result.correlation.sessionId
        : `attack:${result.attackId}`,
    task: attack?.task ?? 'Fix authentication bug',
    finalState:
      result.observedFinalState ??
      (result.unavailableReason ? 'UNKNOWN' : result.expectedFinalState),
    containedCount,
    escapedCount: totalCount - containedCount,
    totalCount,
    violations,
    timeline: timelineFromRuntimeSteps(runtimeSteps),
    signals: [],
    summaryLine: summaryForRuntimeOutcome(outcome, containedCount),
    mode: result.mode,
    runtimeHonesty: honesty,
    outcome,
    attackName: result.name,
    runtimeTimeline: runtimeSteps,
    unavailableReason: result.unavailableReason ?? null,
    tests: [
      {
        id: result.attackId,
        name: result.name,
        category,
        contained,
      },
    ],
    categoryTallies: [
      {
        category,
        contained: containedCount,
        total: totalCount,
      },
    ],
    topFinding: {
      name: result.name,
      category,
      rule: result.observedPolicy ?? result.expectedPolicy,
      decision: result.observedDecision ?? result.expectedDecision,
      outcome: contained ? 'contained' : 'not-contained',
    },
    blockedBeforeExecution,
    secretExposure,
    unauthorizedExecution,
    criticalEscapes: tallies.criticalEscapes,
    runtimeProof: result.mode === 'runtime' ? (result.proof ?? null) : null,
    disclaimer: DEFAULT_DISCLAIMER,
  };

  return sanitizeReportStrings(report);
}

function formatProofGateTable(proof: RuntimeAttackProof): string[] {
  return RUNTIME_ATTACK_PROOF_GATE_KEYS.map((key) => {
    const mark = proof[key] ? 'YES' : 'NO';
    return `  ${RUNTIME_ATTACK_PROOF_GATE_LABELS[key]}: ${mark}`;
  });
}

export function formatExplainReport(report: SecurityReport): string {
  const lines: string[] = [];
  lines.push(report.title);
  lines.push('');
  lines.push('Agent:');
  lines.push(report.agentName);
  lines.push('');
  if (report.runtimeHonesty) {
    lines.push('Runtime honesty:');
    lines.push(report.runtimeHonesty);
    lines.push('');
  }
  if (report.mode) {
    lines.push('Mode:');
    lines.push(report.mode);
    lines.push('');
  }
  if (report.attackName) {
    lines.push('Attack:');
    lines.push(report.attackName);
    lines.push('');
  }
  if (report.outcome) {
    lines.push('Outcome:');
    lines.push(RUNTIME_OUTCOME_LABELS[report.outcome]);
    lines.push('');
  }
  if (report.unavailableReason) {
    lines.push('Unavailable:');
    lines.push(report.unavailableReason);
    lines.push('');
  }
  lines.push('Task:');
  lines.push(report.task);
  lines.push('');
  lines.push('Session:');
  lines.push(report.sessionId);
  lines.push('');
  lines.push('------------------------------------------');
  lines.push('');

  if (report.tests && report.tests.length > 0) {
    lines.push('TESTS');
    lines.push('');
    for (const t of report.tests) {
      lines.push(`  ${t.contained ? '✓' : '✕'} ${t.name} (${t.category})`);
    }
    lines.push('');
    lines.push('------------------------------------------');
    lines.push('');
  }

  if (report.topFinding) {
    lines.push('TOP FINDING');
    lines.push('');
    lines.push(report.topFinding.name);
    lines.push(`Rule: ${report.topFinding.rule} · Decision: ${report.topFinding.decision}`);
    lines.push(
      `Outcome: ${report.outcome ? RUNTIME_OUTCOME_LABELS[report.outcome] : report.topFinding.outcome}`,
    );
    lines.push('');
  }

  if (report.blockedBeforeExecution != null) {
    lines.push(`BLOCKED BEFORE EXECUTION: ${report.blockedBeforeExecution ? 'YES' : 'NO'}`);
    lines.push('');
  } else if (isUnavailableHonesty(report.runtimeHonesty)) {
    lines.push('BLOCKED BEFORE EXECUTION: (not evaluated — RUNTIME UNAVAILABLE)');
    lines.push('');
  }

  if (report.secretExposure) {
    lines.push(`Secret exposure: ${report.secretExposure}`);
  }
  if (report.unauthorizedExecution) {
    lines.push(`Unauthorized execution: ${report.unauthorizedExecution}`);
  }
  if (report.criticalEscapes != null) {
    lines.push(`Critical escapes: ${report.criticalEscapes}`);
  }
  if (report.secretExposure || report.unauthorizedExecution || report.criticalEscapes != null) {
    lines.push('');
  }

  if (report.categoryTallies && report.categoryTallies.length > 0) {
    lines.push('Category tallies:');
    for (const c of report.categoryTallies) {
      lines.push(`  ${c.category}: ${c.contained}/${c.total} contained`);
    }
    lines.push('');
  }

  if (isUnavailableHonesty(report.runtimeHonesty)) {
    lines.push('RuntimeAttackProof: RUNTIME UNAVAILABLE (runtime not executed)');
    lines.push('');
  } else if (report.runtimeProof) {
    lines.push('RuntimeAttackProof:');
    lines.push('');
    for (const line of formatProofGateTable(report.runtimeProof)) {
      lines.push(line);
    }
    lines.push('');
  }

  if (report.runtimeTimeline && report.runtimeTimeline.length > 0) {
    lines.push('Timeline:');
    lines.push('');
    for (const line of formatRuntimeTimelineLines(report.runtimeTimeline)) {
      lines.push(`  ${line}`);
    }
    lines.push('');
  }

  if (report.violations.length === 0) {
    if (!report.tests?.length) {
      lines.push('No policy violations recorded.');
      lines.push('');
    }
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

  lines.push('Final state:');
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
  lines.push(report.disclaimer ?? DEFAULT_DISCLAIMER);
  lines.push('');
  return lines.join('\n');
}

/** Markdown export for sharing — counts only, no fake security scores. */
export function formatReportMarkdown(report: SecurityReport): string {
  const lines: string[] = [`# ${report.title}`, '', `- **Agent:** ${report.agentName}`];
  if (report.runtimeHonesty) {
    lines.push(`- **Runtime honesty:** ${report.runtimeHonesty}`);
  }
  if (report.mode) {
    lines.push(`- **Mode:** ${report.mode}`);
  }
  if (report.attackName) {
    lines.push(`- **Attack:** ${report.attackName}`);
  }
  if (report.outcome) {
    lines.push(`- **Outcome:** ${RUNTIME_OUTCOME_LABELS[report.outcome]}`);
  }
  if (report.unavailableReason) {
    lines.push(`- **Unavailable:** ${report.unavailableReason}`);
  }
  lines.push(
    `- **Session:** ${report.sessionId}`,
    `- **Task:** ${report.task}`,
    `- **Final state:** ${report.finalState}`,
    `- **Contained:** ${report.containedCount ?? 0}`,
    `- **Not contained:** ${report.escapedCount ?? 0}`,
    `- **Total:** ${report.totalCount ?? 0}`,
  );
  if (report.secretExposure) {
    lines.push(`- **Secret exposure:** ${report.secretExposure}`);
  }
  if (report.blockedBeforeExecution != null) {
    lines.push(`- **Blocked before execution:** ${report.blockedBeforeExecution ? 'YES' : 'NO'}`);
  }
  lines.push('');

  if (report.tests && report.tests.length > 0) {
    lines.push('## Tests', '');
    for (const t of report.tests) {
      lines.push(`- ${t.contained ? '✓' : '✕'} **${t.name}** (${t.category})`);
    }
    lines.push('');
  }

  if (report.topFinding) {
    lines.push('## Top finding', '');
    lines.push(`**${report.topFinding.name}**`);
    lines.push('');
    lines.push(
      `- Rule: \`${report.topFinding.rule}\` · Decision: \`${report.topFinding.decision}\``,
    );
    lines.push(
      `- Outcome: ${report.outcome ? RUNTIME_OUTCOME_LABELS[report.outcome] : report.topFinding.outcome}`,
    );
    lines.push('');
  }

  if (report.categoryTallies && report.categoryTallies.length > 0) {
    lines.push('## Category tallies', '');
    for (const c of report.categoryTallies) {
      lines.push(`- \`${c.category}\`: ${c.contained}/${c.total} contained`);
    }
    lines.push('');
  }

  if (isUnavailableHonesty(report.runtimeHonesty)) {
    lines.push('## RuntimeAttackProof', '', '_RUNTIME UNAVAILABLE — runtime not executed._', '');
  } else if (report.runtimeProof) {
    lines.push('## RuntimeAttackProof', '');
    for (const key of RUNTIME_ATTACK_PROOF_GATE_KEYS) {
      const mark = report.runtimeProof[key] ? 'YES' : 'NO';
      lines.push(`- ${RUNTIME_ATTACK_PROOF_GATE_LABELS[key]}: **${mark}**`);
    }
    lines.push('');
  }

  if (report.runtimeTimeline && report.runtimeTimeline.length > 0) {
    lines.push('## Timeline', '');
    for (const line of formatRuntimeTimelineLines(report.runtimeTimeline)) {
      lines.push(`- ${line}`);
    }
    lines.push('');
  }

  lines.push('## Violations', '');
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
  lines.push(`_${report.disclaimer ?? DEFAULT_DISCLAIMER}_`, '');
  return lines.join('\n');
}

function htmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Shareable HTML never prints secret values, even if a fixture field still holds one. */
function htmlText(value: string): string {
  return htmlEscape(scrub(value));
}

function outcomeBadgeClass(outcome: RuntimeOutcome): string {
  switch (outcome) {
    case 'CONTAINED':
      return 'badge badge-contained';
    case 'PROOF_INCOMPLETE':
      return 'badge badge-incomplete';
    case 'RUNTIME_UNAVAILABLE':
      return 'badge badge-unavailable';
    case 'ATTACK_NOT_CONTAINED':
      return 'badge badge-escaped';
  }
}

function honestyNote(honesty: RuntimeHonesty | undefined, mode: SecurityReport['mode']): string {
  if (honesty === 'RUNTIME') {
    return 'The agent process was live Claude Code. VEYRA evaluated the tool request before execution.';
  }
  if (honesty === 'HOOK') {
    return 'This run used the hook protocol (Claude-shaped PreToolUse). Live Claude Code was not launched.';
  }
  if (honesty === 'SIMULATION') {
    return 'This run used synthetic agent events inside the lab. Live Claude Code was not launched.';
  }
  if (honesty === 'RUNTIME UNAVAILABLE') {
    return 'Runtime was requested. Live Claude Code did not run, so this file does not record a runtime result.';
  }
  if (mode) return `Recorded mode: ${mode}.`;
  return 'Mode was not recorded on this artifact.';
}

function proofHtml(report: SecurityReport): string {
  if (isUnavailableHonesty(report.runtimeHonesty) || report.outcome === 'RUNTIME_UNAVAILABLE') {
    const reason = report.unavailableReason ? `<p>${htmlText(report.unavailableReason)}</p>` : '';
    return `<h2>Proof gates</h2>
<h3>RuntimeAttackProof</h3>
<p class="unavailable">RUNTIME UNAVAILABLE — runtime not executed.</p>
${reason}`;
  }

  const runtimeRecorded =
    report.runtimeHonesty === 'RUNTIME' ||
    (report.runtimeHonesty == null && report.mode === 'runtime');

  if (runtimeRecorded && report.runtimeProof) {
    const passed = RUNTIME_ATTACK_PROOF_GATE_KEYS.filter((key) => report.runtimeProof![key]).length;
    const total = RUNTIME_ATTACK_PROOF_GATE_KEYS.length;
    const rows = RUNTIME_ATTACK_PROOF_GATE_KEYS.map((key) => {
      const met = report.runtimeProof![key];
      return `<tr><td>${htmlText(RUNTIME_ATTACK_PROOF_GATE_LABELS[key])}</td><td class="${met ? 'yes' : 'no'}">${met ? 'YES' : 'NO'}</td></tr>`;
    }).join('\n');
    return `<h2>Proof gates</h2>
<h3>RuntimeAttackProof</h3>
<p>Gates met: ${passed} of ${total}. These are the stored gates for this runtime run.</p>
<table><thead><tr><th>Gate</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  if (runtimeRecorded) {
    return `<h2>Proof gates</h2>
<p>Runtime honesty is RUNTIME. RuntimeAttackProof gates were not stored with this record.</p>`;
  }

  const label =
    report.runtimeHonesty ??
    (report.mode === 'hook' ? 'HOOK' : report.mode === 'simulation' ? 'SIMULATION' : 'UNRECORDED');
  return `<h2>Proof gates</h2>
<p>This record is not a runtime proof.</p>
<p>Runtime honesty is ${htmlText(label)}. The twelve RuntimeAttackProof gates are stored only when a live runtime run records them.</p>`;
}

function timelineHtml(report: SecurityReport): string {
  const steps = report.runtimeTimeline ?? [];
  if (steps.length > 0) {
    const items = steps
      .map((step) => {
        const state =
          step.ok === true ? 'Observed' : step.ok === false ? 'Missing' : 'Not applicable';
        const when = step.at ? ` <span class="when">${htmlText(step.at)}</span>` : '';
        return `<li><span class="step-state">${state}</span> ${htmlText(step.label)}${when}</li>`;
      })
      .join('');
    return `<h2>Timeline</h2>
<p>Order of stored events for this run.</p>
<ol class="timeline">${items}</ol>`;
  }

  if (report.timeline.length > 0) {
    const items = report.timeline
      .map((entry) => {
        const when = entry.timestamp ? `${htmlText(entry.timestamp)} ` : '';
        return `<li>${when}${htmlText(entry.target)}</li>`;
      })
      .join('');
    return `<h2>Timeline</h2><ol class="timeline">${items}</ol>`;
  }

  const empty =
    report.runtimeHonesty === 'HOOK' || report.mode === 'hook'
      ? 'No timeline was recorded. Hook records do not include a live runtime timeline.'
      : 'No timeline was recorded for this run.';
  return `<h2>Timeline</h2><p>${empty}</p>`;
}

function categoryHtml(report: SecurityReport): string {
  const tallies = report.categoryTallies ?? [];
  if (tallies.length === 0) return '';
  const rows = tallies
    .map(
      (row) =>
        `<tr><td>${htmlText(row.category)}</td><td>${row.contained} of ${row.total}</td></tr>`,
    )
    .join('\n');
  return `<h2>Category tallies</h2>
<table><thead><tr><th>Category</th><th>Contained</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function findingHtml(report: SecurityReport): string {
  const finding = report.topFinding;
  if (!finding) {
    return `<h2>Top finding</h2><p>No finding was recorded.</p>`;
  }
  const evidence = report.violations
    .slice(0, 3)
    .map((v) => `<li>${htmlText(v.rule)} · ${htmlText(v.decision)} · ${htmlText(v.why)}</li>`)
    .join('');
  return `<h2>Top finding</h2>
<p class="attack-name">${htmlText(finding.name)}</p>
<dl>
<dt>Rule</dt><dd>${htmlText(finding.rule)}</dd>
<dt>Decision</dt><dd>${htmlText(finding.decision)}</dd>
<dt>Category</dt><dd>${htmlText(finding.category)}</dd>
</dl>
${evidence ? `<ul class="evidence">${evidence}</ul>` : ''}`;
}

const REPORT_HTML_CSS = `
:root {
  --ink: #1c1915;
  --muted: #5c564c;
  --line: #e4ddd2;
  --paper: #f4f0e8;
  --card: #fffdf8;
  --ok: #0f6b3a;
  --ok-bg: #e5f6ec;
  --bad: #8d1d1d;
  --bad-bg: #fdecec;
  --warn: #8a5a00;
  --warn-bg: #fff4d6;
  --idle: #3d4a57;
  --idle-bg: #e8eef3;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  color: var(--ink);
  background: var(--paper);
  font-family: "Iowan Old Style", Palatino, Georgia, serif;
  line-height: 1.5;
}
.wrap { max-width: 44rem; margin: 0 auto; padding: 2.25rem 1.25rem 3.5rem; }
.brand {
  margin: 0;
  font-family: ui-sans-serif, system-ui, sans-serif;
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.18em;
}
.kicker {
  margin: 0.25rem 0 0;
  color: var(--muted);
  font-family: ui-sans-serif, system-ui, sans-serif;
  font-size: 0.92rem;
}
h1 { font-size: 2rem; line-height: 1.15; margin: 0.7rem 0 0.45rem; }
.lede { margin: 0; max-width: 38rem; }
section {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 1rem 1.15rem 1.1rem;
  margin: 0.9rem 0;
}
h2 {
  margin: 0 0 0.55rem;
  font-family: ui-sans-serif, system-ui, sans-serif;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--muted);
}
h3 { margin: 0 0 0.4rem; font-size: 1.05rem; }
p { margin: 0.35rem 0; }
dl { display: grid; grid-template-columns: 9.5rem 1fr; gap: 0.35rem 0.75rem; margin: 0.5rem 0; }
dt { color: var(--muted); font-family: ui-sans-serif, system-ui, sans-serif; font-size: 0.88rem; }
dd { margin: 0; }
.badge {
  display: inline-block;
  margin: 0.15rem 0 0.35rem;
  padding: 0.28rem 0.7rem;
  border-radius: 999px;
  font-family: ui-sans-serif, system-ui, sans-serif;
  font-size: 0.82rem;
  font-weight: 700;
  letter-spacing: 0.04em;
}
.badge-contained { color: var(--ok); background: var(--ok-bg); }
.badge-incomplete { color: var(--warn); background: var(--warn-bg); }
.badge-unavailable { color: var(--idle); background: var(--idle-bg); }
.badge-escaped { color: var(--bad); background: var(--bad-bg); }
.honesty { font-family: ui-sans-serif, system-ui, sans-serif; font-weight: 700; }
.attack-name { font-size: 1.35rem; margin: 0.1rem 0 0.35rem; }
ol.timeline { margin: 0.4rem 0 0; padding-left: 1.2rem; }
ol.timeline li { margin: 0.28rem 0; }
.step-state { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 0.78rem; letter-spacing: 0.04em; text-transform: uppercase; color: var(--muted); }
.when { color: var(--muted); font-size: 0.88rem; }
table { border-collapse: collapse; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 0.92rem; }
th, td { text-align: left; padding: 0.42rem 0.3rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-size: 0.72rem; letter-spacing: 0.05em; text-transform: uppercase; }
.yes { color: var(--ok); font-weight: 700; }
.no { color: var(--bad); font-weight: 700; }
.unavailable { color: var(--idle); }
ul.evidence { margin: 0.4rem 0 0; padding-left: 1.1rem; }
footer { margin-top: 1.25rem; color: var(--muted); font-size: 0.95rem; }
`.trim();

/**
 * Self-contained shareable HTML for one attack artifact.
 * Inline CSS only. N/M counts. Never a percent score. Never secret values.
 */
export function formatReportHtml(report: SecurityReport): string {
  const honesty = report.runtimeHonesty
    ? `<p>Runtime honesty: <strong class="honesty">${htmlText(report.runtimeHonesty)}</strong></p>`
    : '<p>Runtime honesty: not recorded</p>';
  const mode = report.mode
    ? `<p>Mode: <strong>${htmlText(report.mode)}</strong></p>`
    : '<p>Mode: not recorded</p>';
  const outcome = report.outcome
    ? `<p class="${outcomeBadgeClass(report.outcome)}">${htmlText(RUNTIME_OUTCOME_LABELS[report.outcome])}</p>`
    : '<p>Outcome was not labeled on this artifact. Use the contained counts below.</p>';
  const blocked =
    report.blockedBeforeExecution != null
      ? `<dt>Blocked before execution</dt><dd>${report.blockedBeforeExecution ? 'YES' : 'NO'}</dd>`
      : isUnavailableHonesty(report.runtimeHonesty)
        ? '<dt>Blocked before execution</dt><dd>not evaluated — RUNTIME UNAVAILABLE</dd>'
        : '';
  const attackTitle = report.attackName ?? report.topFinding?.name ?? report.title;
  const disclaimer = report.disclaimer ?? DEFAULT_DISCLAIMER;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>VEYRA — ${htmlText(attackTitle)}</title>
<style>
${REPORT_HTML_CSS}
</style>
</head>
<body>
<main class="wrap">
<header>
<p class="brand">VEYRA</p>
<p class="kicker">Controlled benchmark</p>
<h1>Attack lab report</h1>
<p class="lede">Controlled attack lab artifact. This page is a standalone record of one run: which agent was tested, which mode actually ran, and what VEYRA decided. Contained ${report.containedCount} of ${report.totalCount}. Not contained: ${report.escapedCount}.</p>
</header>
<section>
<h2>Agent</h2>
${honesty}
${mode}
<p>${htmlText(honestyNote(report.runtimeHonesty, report.mode))}</p>
<dl>
<dt>Agent</dt><dd>${htmlText(report.agentName)}</dd>
<dt>Session</dt><dd>${htmlText(report.sessionId)}</dd>
<dt>Final state</dt><dd>${htmlText(report.finalState)}</dd>
${blocked}
</dl>
</section>
<section>
<h2>Outcome</h2>
${outcome}
<p>${htmlText(report.summaryLine)}</p>
</section>
<section>
<h2>Attack</h2>
<p class="attack-name">${htmlText(attackTitle)}</p>
<p>Task: ${htmlText(report.task)}</p>
</section>
<section>
${timelineHtml(report)}
</section>
<section>
${proofHtml(report)}
</section>
${categoryHtml(report) ? `<section>\n${categoryHtml(report)}\n</section>` : ''}
<section>
${findingHtml(report)}
</section>
<section>
<h2>Secret exposure</h2>
<p><strong>${htmlText(report.secretExposure ?? 'Not recorded')}</strong></p>
<p>Secret values are omitted from this file.</p>
</section>
<footer>
<p class="note">${htmlText(disclaimer)}</p>
</footer>
</main>
</body>
</html>
`;
}
