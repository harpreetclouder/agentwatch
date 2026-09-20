import type { AgentEvent } from '@veyra/agent-events';
import type { SecurityState } from '@veyra/shared';
import type {
  AgentRecord,
  SecurityDecisionRecord,
  SessionRecord,
  SessionStatus,
  VeyraStore,
} from '@veyra/storage';
import { listTelemetryAfter, toTelemetryEvent, type TelemetryEvent } from './telemetry';

/** No new events for this long → treat plane as idle (Datadog-style waiting). */
export const LIVE_IDLE_GAP_MS = 120_000;

/** When live, seed only this recent window — not the full sticky last-run dump. */
export const LIVE_RECENT_WINDOW_MS = 5 * 60_000;

export type LiveStreamMode = 'live' | 'idle' | 'history';

export type LiveSessionSnapshot = {
  sessionId: string;
  agentId: string;
  agentName: string;
  agentRuntime: string;
  task: string;
  workingDirectory: string;
  securityState: string;
  status: SessionStatus;
};

export type LiveEventsPayload = {
  root: string;
  sessionId: string | null;
  securityState: string | null;
  session: LiveSessionSnapshot | null;
  events: TelemetryEvent[];
  streamMode: LiveStreamMode;
  /** True when SQLite has a session that can be opened via history. */
  hasHistory: boolean;
  /** Tip of resolved session (for seek-without-replay). */
  tipEventId: string | null;
  error?: string;
  message?: string;
};

export type ResolveLiveOptions = {
  /** Load latest session including ENDED (explicit history view). */
  history?: boolean;
};

export async function resolveLiveSession(
  store: VeyraStore,
  sessionIdParam: string | null,
  options: ResolveLiveOptions = {},
): Promise<{
  session: SessionRecord;
  agent: AgentRecord | null;
} | null> {
  let sessionId = sessionIdParam;
  if (!sessionId) {
    if (options.history) {
      const latest = await store.sessions.findLatest();
      if (!latest) return null;
      sessionId = latest.id;
    } else {
      // Live tail: only ACTIVE/QUARANTINED — never sticky ENDED last-run.
      const active = await store.sessions.findLatestActive();
      if (!active) return null;
      sessionId = active.id;
    }
  }
  const session = await store.sessions.findById(sessionId);
  if (!session) return null;
  const agent = await store.agents.findById(session.agentId);
  return { session, agent };
}

export function toSessionSnapshot(
  session: SessionRecord,
  agent: AgentRecord | null,
): LiveSessionSnapshot {
  return {
    sessionId: session.id,
    agentId: session.agentId,
    agentName: agent?.name ?? 'Unknown agent',
    agentRuntime: agent?.runtime ?? 'unknown',
    task: session.taskDescription ?? 'No task description',
    workingDirectory: session.workingDirectory,
    securityState: session.securityState,
    status: session.status,
  };
}

export function isSessionFresh(
  session: SessionRecord,
  lastEventTimestamp: string | null,
  nowMs: number = Date.now(),
): boolean {
  if (session.status === 'ENDED' || session.status === 'IDLE') return false;
  if (lastEventTimestamp) {
    const t = Date.parse(lastEventTimestamp);
    if (Number.isFinite(t) && nowMs - t <= LIVE_IDLE_GAP_MS) return true;
  }
  const started = Date.parse(session.startedAt);
  if (Number.isFinite(started) && nowMs - started <= LIVE_IDLE_GAP_MS) return true;
  return false;
}

export function filterRecentEvents(
  events: TelemetryEvent[],
  nowMs: number = Date.now(),
  windowMs: number = LIVE_RECENT_WINDOW_MS,
): TelemetryEvent[] {
  const cutoff = nowMs - windowMs;
  return events.filter((e) => {
    const t = Date.parse(e.timestamp);
    return Number.isFinite(t) && t >= cutoff;
  });
}

export async function loadTelemetryBatch(
  store: VeyraStore,
  sessionId: string,
  after: string | null,
  securityState: SecurityState | string,
): Promise<TelemetryEvent[]> {
  const [events, decisions] = await Promise.all([
    store.events.findBySession(sessionId),
    store.decisions.findBySession(sessionId),
  ]);
  return listTelemetryAfter(events, decisions, securityState, after);
}

export type LiveBatchResult = {
  root: string;
  session: LiveSessionSnapshot | null;
  events: TelemetryEvent[];
  streamMode: LiveStreamMode;
  hasHistory: boolean;
  tipEventId: string | null;
  error?: string;
};

/**
 * Kafka/Datadog-style live batch:
 * - Default: active session only; seed recent window or seek to tip when idle.
 * - history=1: full latest (or pinned) session, labeled history.
 * - after= cursor: incremental only (no sticky full replay).
 */
export async function readLiveEventsBatch(
  store: VeyraStore,
  root: string,
  sessionIdParam: string | null,
  after: string | null,
  history: boolean,
  nowMs: number = Date.now(),
): Promise<LiveBatchResult> {
  const latestAny = await store.sessions.findLatest();
  const hasHistory = latestAny !== null;

  const resolved = await resolveLiveSession(store, sessionIdParam, { history });
  if (!resolved) {
    return {
      root,
      session: null,
      events: [],
      streamMode: 'idle',
      hasHistory,
      tipEventId: null,
    };
  }

  const snapshot = toSessionSnapshot(resolved.session, resolved.agent);
  const all = await loadTelemetryBatch(
    store,
    resolved.session.id,
    null,
    resolved.session.securityState,
  );
  const tipEventId = all.at(-1)?.eventId ?? null;
  const lastTs = all.at(-1)?.timestamp ?? null;

  // Pinned session page or explicit history → allow full/incremental replay.
  if (history || sessionIdParam) {
    const events = after
      ? await loadTelemetryBatch(
          store,
          resolved.session.id,
          after,
          resolved.session.securityState,
        )
      : all;
    const fresh = isSessionFresh(resolved.session, lastTs, nowMs);
    const streamMode: LiveStreamMode =
      history || !fresh || resolved.session.status === 'ENDED' || resolved.session.status === 'IDLE'
        ? 'history'
        : 'live';
    return {
      root,
      session: snapshot,
      events,
      streamMode,
      hasHistory,
      tipEventId,
    };
  }

  // Unpinned /live tail
  const fresh = isSessionFresh(resolved.session, lastTs, nowMs);

  if (after) {
    const events = await loadTelemetryBatch(
      store,
      resolved.session.id,
      after,
      resolved.session.securityState,
    );
    if (events.length > 0 || fresh) {
      return {
        root,
        session: snapshot,
        events,
        streamMode: 'live',
        hasHistory,
        tipEventId,
      };
    }
    // Stale active, no new events — idle, do not re-dump backlog.
    return {
      root,
      session: null,
      events: [],
      streamMode: 'idle',
      hasHistory,
      tipEventId,
    };
  }

  if (!fresh) {
    // Seek to tip without emitting backlog — waiting for next event.
    return {
      root,
      session: null,
      events: [],
      streamMode: 'idle',
      hasHistory,
      tipEventId,
    };
  }

  // Fresh live: seed recent window only (not entire last run).
  return {
    root,
    session: snapshot,
    events: filterRecentEvents(all, nowMs),
    streamMode: 'live',
    hasHistory,
    tipEventId,
  };
}

/** Build full telemetry list (no cursor) for mapping tests / incident derivation. */
export function mapSessionTelemetry(
  events: AgentEvent[],
  decisions: SecurityDecisionRecord[],
  securityState: string,
): TelemetryEvent[] {
  const byEvent = new Map(decisions.map((d) => [d.eventId, d]));
  return events.map((event) =>
    toTelemetryEvent({
      event,
      decision: byEvent.get(event.id) ?? null,
      securityState,
    }),
  );
}
