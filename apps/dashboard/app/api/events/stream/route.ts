import { openDashboardStore } from '@/lib/store';
import {
  loadTelemetryBatch,
  resolveLiveSession,
  toSessionSnapshot,
  type LiveSessionSnapshot,
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
      return;
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
 * GET /api/events/stream?sessionId=
 */
export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const sessionIdParam = url.searchParams.get('sessionId');
  const encoder = new TextEncoder();
  let cursor: string | null = null;
  let ticks = 0;

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
          const batch = await readBatch(sessionIdParam, cursor);
          if (batch.error === 'uninitialized') {
            send('error', { error: 'security_plane_uninitialized' });
            break;
          }
          if (batch.error === 'session_not_found') {
            cursor = null;
          }

          if (batch.snapshot) {
            send('session', { ...batch.snapshot, root: batch.root });
          }

          for (const evt of batch.events) {
            send('security', evt);
            cursor = evt.eventId;
          }

          ticks += 1;
          if (ticks % HEARTBEAT_EVERY === 0) {
            send('heartbeat', { t: new Date().toISOString(), cursor });
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
): Promise<{
  root: string | null;
  snapshot: LiveSessionSnapshot | null;
  events: TelemetryEvent[];
  error?: string;
}> {
  let opened: ReturnType<typeof openDashboardStore>;
  try {
    opened = openDashboardStore();
  } catch {
    return { root: null, snapshot: null, events: [], error: 'plane_busy' };
  }
  if (!opened) {
    return { root: null, snapshot: null, events: [], error: 'uninitialized' };
  }
  const { store, root } = opened;
  try {
    const resolved = await resolveLiveSession(store, sessionIdParam);
    if (!resolved) {
      return { root, snapshot: null, events: [], error: 'session_not_found' };
    }
    const snapshot = toSessionSnapshot(resolved.session, resolved.agent);
    const events = await loadTelemetryBatch(
      store,
      resolved.session.id,
      after,
      resolved.session.securityState,
    );
    return { root, snapshot, events };
  } catch {
    return { root, snapshot: null, events: [], error: 'plane_busy' };
  } finally {
    try {
      store.close();
    } catch {
      /* ignore */
    }
  }
}
