import { openDashboardStore } from '@/lib/store';
import {
  readLiveEventsBatch,
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

function emptyPayload(
  partial: Partial<LiveEventsPayload> & { root?: string },
): LiveEventsPayload {
  return {
    root: partial.root ?? '',
    sessionId: partial.sessionId ?? null,
    securityState: partial.securityState ?? null,
    session: partial.session ?? null,
    events: (partial.events ?? []) as TelemetryEvent[],
    streamMode: partial.streamMode ?? 'idle',
    hasHistory: partial.hasHistory ?? false,
    tipEventId: partial.tipEventId ?? null,
    ...(partial.error ? { error: partial.error } : {}),
    ...(partial.message ? { message: partial.message } : {}),
  };
}

/**
 * Short-poll fallback for live telemetry.
 * GET /api/events?sessionId=&after=&history=1
 */
export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const sessionIdParam = url.searchParams.get('sessionId');
  const after = url.searchParams.get('after');
  const history = url.searchParams.get('history') === '1';

  let opened: ReturnType<typeof openDashboardStore>;
  try {
    opened = openDashboardStore();
  } catch (err) {
    return json(
      emptyPayload({
        error: 'plane_unavailable',
        message: String(err),
      }),
      503,
    );
  }

  if (!opened) {
    return json(
      emptyPayload({
        error: 'security_plane_uninitialized',
      }),
      503,
    );
  }

  const { store, root } = opened;
  try {
    const batch = await readLiveEventsBatch(
      store,
      root,
      sessionIdParam,
      after,
      history,
    );

    return json({
      root: batch.root,
      sessionId: batch.session?.sessionId ?? null,
      securityState: batch.session?.securityState ?? null,
      session: batch.session,
      events: batch.events,
      streamMode: batch.streamMode,
      hasHistory: batch.hasHistory,
      tipEventId: batch.tipEventId,
    } satisfies LiveEventsPayload);
  } catch (err) {
    return json(
      emptyPayload({
        root,
        sessionId: sessionIdParam,
        error: 'plane_busy',
        message: String(err),
      }),
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
