import { redactSensitiveValue, sanitizeEvidence } from '@veyra/policy-engine';
import type { VeyraStore } from '@veyra/storage';
import type { Watchdog } from '@veyra/watchdog';
import { getAttack } from './attacks/index.js';
import {
  RUNTIME_ATTACK_PROOF_GATE_KEYS,
  RUNTIME_ATTACK_PROOF_GATE_LABELS,
  runtimeOutcomeTallies,
  type RuntimeAttackProof,
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
  'User-space hooks only. Do not claim complete agent security.';

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

export function honestyFromMode(
  mode: AttackRunSummary['mode'] | 'hook' | 'runtime',
  unavailable?: string | null,
): RuntimeHonesty {
  if (unavailable) return 'UNAVAILABLE';
  if (mode === 'simulation') return 'SIMULATION';
  if (mode === 'hook') return 'HOOK';
  return 'LIVE';
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

function topFindingFromResults(
  results: AttackResult[],
  violations: SecurityReport['violations'],
): ReportTopFinding | null {
  const headline =
    results.find((r) => r.attackId === 'prompt-injection-secret-access') ??
    results.find((r) => !r.contained) ??
    results[0];
  if (!headline) return null;

  const block = violations.find(
    (v) => v.decision === 'BLOCK' || v.decision === 'QUARANTINE',
  );
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
    task: redactSensitiveValue(report.task),
    finalState: report.finalState,
    containedCount: report.containedCount,
    escapedCount: report.escapedCount,
    totalCount: report.totalCount,
    violations: report.violations.map((v) => ({
      ...v,
      event: redactSensitiveValue(v.event),
      why: redactSensitiveValue(v.why),
      evidence: sanitizeEvidence(v.evidence),
    })),
    timeline: report.timeline.map((t) => ({
      ...t,
      target: redactSensitiveValue(t.target),
    })),
    signals: report.signals.map((s) => ({
      ...s,
      evidence: sanitizeEvidence(s.evidence),
    })),
    summaryLine: redactSensitiveValue(report.summaryLine),
  };
  if (report.mode !== undefined) next.mode = report.mode;
  if (report.runtimeHonesty !== undefined) next.runtimeHonesty = report.runtimeHonesty;
  if (report.unavailableReason !== undefined) {
    next.unavailableReason =
      report.unavailableReason === null
        ? null
        : redactSensitiveValue(report.unavailableReason);
  }
  if (report.tests !== undefined) next.tests = report.tests;
  if (report.categoryTallies !== undefined) next.categoryTallies = report.categoryTallies;
  if (report.topFinding !== undefined) next.topFinding = report.topFinding;
  if (report.blockedBeforeExecution !== undefined) {
    next.blockedBeforeExecution = report.blockedBeforeExecution;
  }
  if (report.secretExposure !== undefined) {
    next.secretExposure = redactSensitiveValue(report.secretExposure);
  }
  if (report.unauthorizedExecution !== undefined) {
    next.unauthorizedExecution = redactSensitiveValue(report.unauthorizedExecution);
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
    unavailableReason: null,
    tests: testsFromResults(summary.results),
    categoryTallies: tallyCategories(summary.results),
    topFinding: topFindingFromResults(summary.results, violations),
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
export function buildSecurityReportFromRuntimeResult(
  result: RuntimeAttackResult,
): SecurityReport {
  const honesty = honestyFromMode(result.mode, result.unavailableReason);
  const containedCount = result.contained ? 1 : 0;
  const totalCount = 1;
  const attack = getAttack(result.attackId);
  const category = attack?.category ?? 'prompt-injection';

  const outcome =
    result.outcome ??
    (result.unavailableReason
      ? 'RUNTIME_UNAVAILABLE'
      : result.contained
        ? 'CONTAINED'
        : result.mode === 'runtime'
          ? 'PROOF_INCOMPLETE'
          : 'ATTACK_NOT_CONTAINED');
  const tallies = runtimeOutcomeTallies(outcome);

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

  const secretExposure = result.unavailableReason
    ? tallies.secretExposureHint
    : result.secretExposure === 'LEAKED' || result.proof?.secretNotExposed === false
      ? 'LEAKED'
      : result.contained
        ? 'NONE'
        : outcome === 'PROOF_INCOMPLETE'
          ? result.secretExposure === 'NONE'
            ? 'NONE'
            : tallies.secretExposureHint
          : tallies.secretExposureHint;

  const unauthorizedExecution = tallies.unauthorizedExecution;

  const violations =
    result.observedDecision && result.observedDecision !== 'ALLOW'
      ? [
          {
            event: `${result.name}(${result.expectedPolicy})`,
            decision: result.observedDecision,
            severity: attack?.severity ?? 'HIGH',
            rule: result.observedPolicy ?? result.expectedPolicy,
            why: result.contained
              ? 'Unauthorized tool blocked before execution'
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
      : `attack:${result.attackId}`,
    task: 'Fix authentication bug',
    finalState:
      result.observedFinalState ??
      (result.unavailableReason ? 'UNKNOWN' : result.expectedFinalState),
    containedCount,
    escapedCount: totalCount - containedCount,
    totalCount,
    violations,
    timeline: [],
    signals: [],
    summaryLine: result.unavailableReason
      ? '0/1 controlled attacks contained; runtime not executed (UNAVAILABLE).'
      : `${containedCount}/${totalCount} controlled attacks contained; ${totalCount - containedCount} not contained.`,
    mode: result.mode,
    runtimeHonesty: honesty,
    unavailableReason: result.unavailableReason ?? null,
    tests: [
      {
        id: result.attackId,
        name: result.name,
        category,
        contained: result.contained,
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
      outcome: result.contained ? 'contained' : 'not-contained',
    },
    blockedBeforeExecution,
    secretExposure,
    unauthorizedExecution,
    criticalEscapes: tallies.criticalEscapes,
    runtimeProof:
      result.mode === 'runtime' ? (result.proof ?? null) : null,
    disclaimer: result.disclaimer || DEFAULT_DISCLAIMER,
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
    lines.push(
      `Rule: ${report.topFinding.rule} · Decision: ${report.topFinding.decision}`,
    );
    lines.push(`Outcome: ${report.topFinding.outcome}`);
    lines.push('');
  }

  if (report.blockedBeforeExecution != null) {
    lines.push(
      `BLOCKED BEFORE EXECUTION: ${report.blockedBeforeExecution ? 'YES' : 'NO'}`,
    );
    lines.push('');
  } else if (report.runtimeHonesty === 'UNAVAILABLE') {
    lines.push('BLOCKED BEFORE EXECUTION: (not evaluated — UNAVAILABLE)');
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

  if (report.runtimeHonesty === 'UNAVAILABLE') {
    lines.push('RuntimeAttackProof: UNAVAILABLE (runtime not executed)');
    lines.push('');
  } else if (report.runtimeProof) {
    lines.push('RuntimeAttackProof:');
    lines.push('');
    for (const line of formatProofGateTable(report.runtimeProof)) {
      lines.push(line);
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
  const lines: string[] = [
    `# ${report.title}`,
    '',
    `- **Agent:** ${report.agentName}`,
  ];
  if (report.runtimeHonesty) {
    lines.push(`- **Runtime honesty:** ${report.runtimeHonesty}`);
  }
  if (report.mode) {
    lines.push(`- **Mode:** ${report.mode}`);
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
    lines.push(
      `- **Blocked before execution:** ${report.blockedBeforeExecution ? 'YES' : 'NO'}`,
    );
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
    lines.push(`- Outcome: ${report.topFinding.outcome}`);
    lines.push('');
  }

  if (report.categoryTallies && report.categoryTallies.length > 0) {
    lines.push('## Category tallies', '');
    for (const c of report.categoryTallies) {
      lines.push(`- \`${c.category}\`: ${c.contained}/${c.total} contained`);
    }
    lines.push('');
  }

  if (report.runtimeHonesty === 'UNAVAILABLE') {
    lines.push('## RuntimeAttackProof', '', '_UNAVAILABLE — runtime not executed._', '');
  } else if (report.runtimeProof) {
    lines.push('## RuntimeAttackProof', '');
    for (const key of RUNTIME_ATTACK_PROOF_GATE_KEYS) {
      const mark = report.runtimeProof[key] ? 'YES' : 'NO';
      lines.push(`- ${RUNTIME_ATTACK_PROOF_GATE_LABELS[key]}: **${mark}**`);
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

/** Minimal HTML export for sharing — no charts or percentage scores. */
export function formatReportHtml(report: SecurityReport): string {
  const esc = (s: string) =>
    s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');

  const honestyBadge = report.runtimeHonesty
    ? `<div class="honesty">Runtime honesty: <strong>${esc(report.runtimeHonesty)}</strong></div>`
    : '';

  const testRows =
    report.tests
      ?.map(
        (t) =>
          `<tr><td>${t.contained ? '✓' : '✕'}</td><td>${esc(t.name)}</td><td>${esc(t.category)}</td></tr>`,
      )
      .join('\n') ?? '';

  const categoryRows =
    report.categoryTallies
      ?.map(
        (c) =>
          `<tr><td>${esc(c.category)}</td><td>${c.contained}/${c.total}</td></tr>`,
      )
      .join('\n') ?? '';

  const proofSection =
    report.runtimeHonesty === 'UNAVAILABLE'
      ? `<h2>RuntimeAttackProof</h2><p class="unavailable">UNAVAILABLE — runtime not executed.</p>${
          report.unavailableReason
            ? `<p>${esc(report.unavailableReason)}</p>`
            : ''
        }`
      : report.runtimeProof
        ? `<h2>RuntimeAttackProof</h2><table><thead><tr><th>Gate</th><th>Result</th></tr></thead><tbody>${RUNTIME_ATTACK_PROOF_GATE_KEYS.map(
            (key) =>
              `<tr><td>${esc(RUNTIME_ATTACK_PROOF_GATE_LABELS[key])}</td><td>${
                report.runtimeProof![key] ? 'YES' : 'NO'
              }</td></tr>`,
          ).join('\n')}</tbody></table>`
        : '';

  const top =
    report.topFinding != null
      ? `<h2>Top finding</h2>
<div class="finding">
<div><strong>${esc(report.topFinding.name)}</strong></div>
<div>Rule: ${esc(report.topFinding.rule)} · Decision: ${esc(report.topFinding.decision)}</div>
<div>Outcome: ${esc(report.topFinding.outcome)}</div>
</div>`
      : '';

  const blocked =
    report.blockedBeforeExecution != null
      ? `<div>BLOCKED BEFORE EXECUTION: <strong>${
          report.blockedBeforeExecution ? 'YES' : 'NO'
        }</strong></div>`
      : report.runtimeHonesty === 'UNAVAILABLE'
        ? `<div>BLOCKED BEFORE EXECUTION: (not evaluated — UNAVAILABLE)</div>`
        : '';

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
h1{font-size:1.25rem} h2{font-size:1rem;margin-top:1.5rem}
table{border-collapse:collapse;width:100%;font-size:0.85rem;margin:0.75rem 0}
th,td{border:1px solid #ccc;padding:0.4rem 0.5rem;text-align:left;vertical-align:top}
th{background:#eee} .meta{margin:1rem 0} .note{color:#555;margin-top:1.5rem}
.honesty{display:inline-block;padding:0.25rem 0.5rem;border:1px solid #333;margin:0.5rem 0}
.finding{border-left:3px solid #333;padding-left:0.75rem;margin:0.75rem 0}
.unavailable{color:#666;font-style:italic}
.counts{font-weight:600;margin:1rem 0}
</style></head><body>
<h1>${esc(report.title)}</h1>
<p>Controlled attack lab artifact — concrete N/M contained counts (not a security score).</p>
${honestyBadge}
<div class="meta">
<div>Agent: ${esc(report.agentName)}</div>
${report.mode ? `<div>Mode: ${esc(report.mode)}</div>` : ''}
<div>Session: ${esc(report.sessionId)}</div>
<div>Task: ${esc(report.task)}</div>
<div>Final state: ${esc(report.finalState)}</div>
<div class="counts">Contained: ${report.containedCount ?? 0} · Not contained: ${report.escapedCount ?? 0} · Total: ${report.totalCount ?? 0}</div>
${report.secretExposure ? `<div>Secret exposure: ${esc(report.secretExposure)}</div>` : ''}
${blocked}
</div>
${
  testRows
    ? `<h2>Tests</h2><table><thead><tr><th></th><th>Test</th><th>Category</th></tr></thead><tbody>${testRows}</tbody></table>`
    : ''
}
${top}
${
  categoryRows
    ? `<h2>Category tallies</h2><table><thead><tr><th>Category</th><th>Contained</th></tr></thead><tbody>${categoryRows}</tbody></table>`
    : ''
}
${proofSection}
<h2>Violations</h2>
<table><thead><tr><th>Rule</th><th>Decision</th><th>Severity</th><th>Event</th><th>Why</th></tr></thead>
<tbody>${rows || '<tr><td colspan="5">No violations</td></tr>'}</tbody></table>
<p>${esc(report.summaryLine)}</p>
<p class="note">${esc(report.disclaimer ?? DEFAULT_DISCLAIMER)}</p>
</body></html>
`;
}
