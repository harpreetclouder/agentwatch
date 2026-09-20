import { openDashboardStore } from '@/lib/store';
import {
  readLiveEventsBatch,
  type LiveSessionSnapshot,
  type LiveStreamMode,
} from '@/lib/live-session';
import type { TelemetryEvent } from '@/lib/telemetry';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const POLL_MS = 750;
const HEARTBEAT_EVERY = 8;

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException('Aborted', 'AbortError'));
    }
    const t = setTimeout(resolve, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(t);
        reject(new DOMException('Aborted', 'AbortError'));
      },
      { once: true },
    );
  });
}

/**
 * SSE live telemetry stream.
 * GET /api/events/stream?sessionId=&history=1
 *
 * Live (default): seeks to tip / recent window — does not sticky-replay last run.
 */
export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const sessionIdParam = url.searchParams.get('sessionId');
  const history = url.searchParams.get('history') === '1';
  const encoder = new TextEncoder();
  let cursor: string | null = null;
  let ticks = 0;
  let lastStreamMode: LiveStreamMode | null = null;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: string, data: unknown) => {
        controller.enqueue(
          encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
        );
      };

      send('ready', { ok: true, pollMs: POLL_MS });

      try {
        while (!request.signal.aborted) {
          const batch = await readBatch(sessionIdParam, cursor, history);
          if (batch.error === 'uninitialized') {
            send('error', { error: 'security_plane_uninitialized' });
            break;
          }
          if (batch.error === 'session_not_found') {
            cursor = null;
          }

          // Seek past backlog when idle (or first live seed) without replaying forever.
          if (cursor === null && batch.tipEventId && batch.events.length === 0) {
            cursor = batch.tipEventId;
          }

          if (batch.streamMode !== lastStreamMode) {
            lastStreamMode = batch.streamMode;
            send('mode', {
              streamMode: batch.streamMode,
              hasHistory: batch.hasHistory,
              tipEventId: batch.tipEventId,
              root: batch.root,
            });
          }

          if (batch.snapshot) {
            send('session', {
              ...batch.snapshot,
              root: batch.root,
              streamMode: batch.streamMode,
              hasHistory: batch.hasHistory,
            });
          } else if (batch.streamMode === 'idle') {
            send('idle', {
              hasHistory: batch.hasHistory,
              tipEventId: batch.tipEventId,
              root: batch.root,
            });
          }

          for (const evt of batch.events) {
            send('security', evt);
            cursor = evt.eventId;
          }

          // After seeding a recent window, advance cursor to tip so we don't re-send.
          if (
            cursor === null &&
            batch.tipEventId &&
            batch.events.length > 0
          ) {
            cursor = batch.tipEventId;
          } else if (batch.events.length > 0) {
            cursor = batch.events.at(-1)!.eventId;
          }

          ticks += 1;
          if (ticks % HEARTBEAT_EVERY === 0) {
            send('heartbeat', {
              t: new Date().toISOString(),
              cursor,
              streamMode: batch.streamMode,
            });
          }

          await sleep(POLL_MS, request.signal);
        }
      } catch (err) {
        if ((err as Error).name !== 'AbortError') {
          try {
            send('error', { error: 'stream_failed', message: String(err) });
          } catch {
            /* closed */
          }
        }
      } finally {
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      }
    },
    cancel() {
      /* abort via request.signal */
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
}

async function readBatch(
  sessionIdParam: string | null,
  after: string | null,
  history: boolean,
): Promise<{
  root: string | null;
  snapshot: LiveSessionSnapshot | null;
  events: TelemetryEvent[];
  streamMode: LiveStreamMode;
  hasHistory: boolean;
  tipEventId: string | null;
  error?: string;
}> {
  let opened: ReturnType<typeof openDashboardStore>;
  try {
    opened = openDashboardStore();
  } catch {
    return {
      root: null,
      snapshot: null,
      events: [],
      streamMode: 'idle',
      hasHistory: false,
      tipEventId: null,
      error: 'plane_busy',
    };
  }
  if (!opened) {
    return {
      root: null,
      snapshot: null,
      events: [],
      streamMode: 'idle',
      hasHistory: false,
      tipEventId: null,
      error: 'uninitialized',
    };
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
    return {
      root: batch.root,
      snapshot: batch.session,
      events: batch.events,
      streamMode: batch.streamMode,
      hasHistory: batch.hasHistory,
      tipEventId: batch.tipEventId,
      ...(batch.error ? { error: batch.error } : {}),
    };
  } catch {
    return {
      root,
      snapshot: null,
      events: [],
      streamMode: 'idle',
      hasHistory: false,
      tipEventId: null,
      error: 'plane_busy',
    };
  } finally {
    try {
      store.close();
    } catch {
      /* ignore */
    }
  }
}
