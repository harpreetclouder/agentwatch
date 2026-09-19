import type { AgentEvent } from '@veyra/agent-events';
import type { SecurityState } from '@veyra/shared';
import type {
  AgentRecord,
  SecurityDecisionRecord,
  SessionRecord,
  VeyraStore,
} from '@veyra/storage';
import { listTelemetryAfter, toTelemetryEvent, type TelemetryEvent } from './telemetry';

export type LiveSessionSnapshot = {
  sessionId: string;
  agentId: string;
  agentName: string;
  agentRuntime: string;
  task: string;
  workingDirectory: string;
  securityState: string;
};

export type LiveEventsPayload = {
  root: string;
  sessionId: string | null;
  securityState: string | null;
  session: LiveSessionSnapshot | null;
  events: TelemetryEvent[];
  error?: string;
  message?: string;
};

export async function resolveLiveSession(
  store: VeyraStore,
  sessionIdParam: string | null,
): Promise<{
  session: SessionRecord;
  agent: AgentRecord | null;
} | null> {
  let sessionId = sessionIdParam;
  if (!sessionId) {
    const latest =
      (await store.sessions.findLatestActive()) ?? (await store.sessions.findLatest());
    if (!latest) return null;
    sessionId = latest.id;
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
  };
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
