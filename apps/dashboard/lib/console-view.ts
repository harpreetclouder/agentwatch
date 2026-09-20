import type { TelemetryEvent } from './telemetry';

export const SECURITY_STATE_LADDER = [
  'NORMAL',
  'WARNING',
  'RESTRICTED',
  'QUARANTINED',
  'REVOKED',
] as const;

export type ActivityMark = 'ok' | 'warn' | 'block' | 'lock';

export type ActivityRow = {
  id: string;
  kind: 'event' | 'annotation';
  mark: ActivityMark;
  label: string;
  timestamp: string;
  action: string;
  resource: string;
  decision: string | null;
};

export type IncidentView = {
  policy: string;
  severity: string;
  reason: string;
  trajectory: string[];
  enforcement: string;
  eventId: string;
  decisionId: string | null;
  sessionId: string;
  timestamp: string;
};

function isReadme(evt: TelemetryEvent): boolean {
  const t = (evt.action.target ?? '').toLowerCase();
  return t.includes('readme');
}

function isSecretBlock(evt: TelemetryEvent): boolean {
  return (
    (evt.decision === 'BLOCK' || evt.decision === 'QUARANTINE') &&
    (evt.policy === 'SECRET_ACCESS' ||
      (evt.action.target ?? '').includes('.env') ||
      (evt.action.target ?? '').includes('credentials'))
  );
}

function markFor(evt: TelemetryEvent): ActivityMark {
  if (evt.decision === 'BLOCK' || evt.decision === 'QUARANTINE') return 'block';
  if (evt.decision === 'WARN') return 'warn';
  return 'ok';
}

/** Short resource label for ops tail (auth.ts, README, .env). */
function shortResource(target: string | undefined): string {
  if (!target) return '';
  const base = target.replace(/\\/g, '/').split('/').pop() ?? target;
  if (base.toLowerCase().startsWith('readme')) return 'README';
  if (base === 'auth.ts' || target.endsWith('/auth.ts') || target.endsWith('src/auth.ts')) {
    return 'auth';
  }
  return base;
}

/** Claude-shaped tool verb for display (Read / Write / …). */
function toolVerb(actionName: string): string {
  const n = actionName.replace(/_/g, ' ').trim();
  const lower = n.toLowerCase();
  if (lower === 'read file' || lower === 'file read' || lower === 'read') return 'Read';
  if (lower === 'write file' || lower === 'file write' || lower === 'write' || lower === 'edit file') {
    return 'Write';
  }
  if (lower === 'bash' || lower === 'shell') return 'Bash';
  // Preserve PascalCase tool names from Claude (Read, Edit, …)
  if (/^[A-Z][A-Za-z0-9]*$/.test(actionName)) return actionName;
  return n.replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Ops-tail labels: "Read auth", "Read README", ".env BLOCKED".
 * Never includes secret contents.
 */
export function actionLabel(evt: TelemetryEvent): string {
  const resource = shortResource(evt.action.target);
  const verb = toolVerb(evt.action.name);
  if (evt.decision === 'BLOCK' || evt.decision === 'QUARANTINE') {
    return resource ? `${resource} BLOCKED` : `${verb} BLOCKED`;
  }
  return resource ? `${verb} ${resource}` : verb;
}

/**
 * Build live activity rows from real telemetry.
 * Inserts injection + SECRET_ACCESS annotations when README precedes a
 * secret block (trajectory signal) — ops-log parity with CLI proof story.
 */
export function buildActivityRows(events: TelemetryEvent[]): ActivityRow[] {
  const hasInjectionTrajectory =
    events.some(isReadme) && events.some(isSecretBlock);
  const rows: ActivityRow[] = [];
  let injectionShown = false;

  for (const evt of events) {
    rows.push({
      id: evt.eventId,
      kind: 'event',
      mark: markFor(evt),
      label: actionLabel(evt),
      timestamp: evt.timestamp,
      action: evt.action.name,
      resource: evt.action.target ?? '—',
      decision: evt.decision,
    });

    if (hasInjectionTrajectory && isReadme(evt) && !injectionShown) {
      injectionShown = true;
      rows.push({
        id: `ann-inject-${evt.eventId}`,
        kind: 'annotation',
        mark: 'warn',
        label: 'injection',
        timestamp: evt.timestamp,
        action: 'trajectory',
        resource: evt.action.target ?? 'README',
        decision: 'WARN',
      });
    }

    // Policy lock line after SECRET_ACCESS / .env deny (honest rule id, no contents).
    if (isSecretBlock(evt)) {
      const policy = evt.policy ?? 'SECRET_ACCESS';
      rows.push({
        id: `ann-policy-${evt.eventId}`,
        kind: 'annotation',
        mark: 'lock',
        label: policy,
        timestamp: evt.timestamp,
        action: 'policy',
        resource: evt.action.target ?? '.env',
        decision: evt.decision,
      });
    }
  }

  return rows;
}

/** Latest blocking/quarantine decision for the incident panel. */
export function buildIncident(events: TelemetryEvent[]): IncidentView | null {
  const blocked = [...events]
    .reverse()
    .find((e) => e.decision === 'BLOCK' || e.decision === 'QUARANTINE');
  if (!blocked || !blocked.policy) return null;
  return incidentFromEvent(events, blocked);
}

/** Focus a specific event when user selects a stream row. */
export function buildIncidentForSelection(
  events: TelemetryEvent[],
  selectedId: string | null,
): IncidentView | null {
  if (!selectedId) return buildIncident(events);

  const eventId = unwrapAnnotationId(selectedId);

  const selected = events.find((e) => e.eventId === eventId);
  if (!selected) return buildIncident(events);

  if (selected.decision === 'BLOCK' || selected.decision === 'QUARANTINE') {
    return incidentFromEvent(events, selected);
  }

  return null;
}

/** Strip annotation prefixes (ann-inject- / ann-policy-) to the backing event id. */
export function unwrapAnnotationId(selectedId: string): string {
  if (selectedId.startsWith('ann-inject-')) {
    return selectedId.slice('ann-inject-'.length);
  }
  if (selectedId.startsWith('ann-policy-')) {
    return selectedId.slice('ann-policy-'.length);
  }
  return selectedId;
}

function incidentFromEvent(
  events: TelemetryEvent[],
  blocked: TelemetryEvent,
): IncidentView {
  const trajectory: string[] = [];
  if (events.some(isReadme) && isSecretBlock(blocked)) {
    trajectory.push('PROMPT_INJECTION');
  }
  trajectory.push(blocked.policy ?? 'UNKNOWN');

  return {
    policy: blocked.policy ?? 'UNKNOWN',
    severity: blocked.severity ?? 'HIGH',
    reason:
      blocked.reason ??
      'Agent attempted to access a secret-bearing resource outside its authority.',
    trajectory,
    // Honest hook vocabulary — deny happens on PreToolUse before tool runs.
    enforcement: 'PreToolUse DENY · BLOCKED BEFORE EXECUTION',
    eventId: blocked.eventId,
    decisionId: blocked.decisionId,
    sessionId: blocked.sessionId,
    timestamp: blocked.timestamp,
  };
}

/** Newest block/quarantine event id for auto-focus. */
export function latestBlockEventId(events: TelemetryEvent[]): string | null {
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    if (e && (e.decision === 'BLOCK' || e.decision === 'QUARANTINE')) {
      return e.eventId;
    }
  }
  return null;
}

/** Ordered unique states observed (for transition ladder). */
export function buildStatePath(
  events: TelemetryEvent[],
  current: string | null,
): string[] {
  const path: string[] = [];
  for (const evt of events) {
    const s = evt.securityState;
    if (!s) continue;
    if (path[path.length - 1] !== s) path.push(s);
  }
  if (current && path[path.length - 1] !== current) {
    path.push(current);
  }
  if (path.length === 0 && current) return [current];
  if (path.length === 0) return ['NORMAL'];
  return path;
}

export function displayAgentName(name: string, runtime: string): string {
  const n = (name ?? '').toLowerCase();
  const r = (runtime ?? '').toLowerCase();
  if (n.includes('claude') || r.includes('claude')) return 'Claude Code';
  if ((name ?? '').trim()) return name;
  return runtime || 'Agent';
}

/**
 * Task line for Live Session detail.
 * Legacy bridge sessions stored "live-bridge" — show honest label, never invent a task.
 */
export function displayTask(task: string): string {
  const t = (task ?? '').trim();
  if (!t || t === 'No task description') return '—';
  if (t === 'live-bridge') return 'Claude Code PreToolUse (bridge)';
  return t;
}
