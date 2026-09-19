import { openDashboardStore } from '@/lib/store';
import {
  loadTelemetryBatch,
  resolveLiveSession,
  toSessionSnapshot,
  type LiveEventsPayload,
} from '@/lib/live-session';
import type { TelemetryEvent } from '@/lib/telemetry';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}

/**
 * Short-poll fallback for live telemetry.
 * GET /api/events?sessionId=&after=
 */
export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const sessionIdParam = url.searchParams.get('sessionId');
  const after = url.searchParams.get('after');

  let opened: ReturnType<typeof openDashboardStore>;
  try {
    opened = openDashboardStore();
  } catch (err) {
    return json(
      {
        error: 'plane_unavailable',
        message: String(err),
        events: [] as TelemetryEvent[],
        session: null,
        sessionId: null,
        securityState: null,
        root: '',
      } satisfies LiveEventsPayload,
      503,
    );
  }

  if (!opened) {
    return json(
      {
        error: 'security_plane_uninitialized',
        events: [] as TelemetryEvent[],
        session: null,
        sessionId: null,
        securityState: null,
        root: '',
      } satisfies LiveEventsPayload,
      503,
    );
  }

  const { store, root } = opened;
  try {
    const resolved = await resolveLiveSession(store, sessionIdParam);
    if (!resolved) {
      return json({
        root,
        sessionId: null,
        securityState: null,
        session: null,
        events: [],
      } satisfies LiveEventsPayload);
    }

    const { session, agent } = resolved;
    const snapshot = toSessionSnapshot(session, agent);
    const events = await loadTelemetryBatch(
      store,
      session.id,
      after,
      session.securityState,
    );

    return json({
      root,
      sessionId: session.id,
      securityState: session.securityState,
      session: snapshot,
      events,
    } satisfies LiveEventsPayload);
  } catch (err) {
    return json(
      {
        root,
        sessionId: sessionIdParam,
        securityState: null,
        session: null,
        events: [] as TelemetryEvent[],
        error: 'plane_busy',
        message: String(err),
      } satisfies LiveEventsPayload,
      503,
    );
  } finally {
    try {
      store.close();
    } catch {
      /* ignore */
    }
  }
}
