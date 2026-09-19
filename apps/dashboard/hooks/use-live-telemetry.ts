'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { LiveEventsPayload, LiveSessionSnapshot } from '@/lib/live-session';
import type { TelemetryEvent } from '@/lib/telemetry';

export type FeedStatus = 'connecting' | 'live-sse' | 'live-poll' | 'error';

export function useLiveTelemetry(options: {
  sessionId?: string | undefined;
  pollMs?: number | undefined;
} = {}) {
  const { sessionId, pollMs = 750 } = options;
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [status, setStatus] = useState<FeedStatus>('connecting');
  const [session, setSession] = useState<LiveSessionSnapshot | null>(null);
  const [planeRoot, setPlaneRoot] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Mirror of events — after= cursor MUST track rendered state (survives HMR desync). */
  const eventsRef = useRef<TelemetryEvent[]>([]);
  eventsRef.current = events;
  const trackedSession = useRef<string | null>(sessionId ?? null);
  const modeRef = useRef<FeedStatus>('connecting');

  const resetFeed = useCallback(() => {
    setEvents([]);
  }, []);

  const noteSession = useCallback(
    (snap: LiveSessionSnapshot | null) => {
      if (!snap?.sessionId) return;
      if (
        trackedSession.current &&
        trackedSession.current !== snap.sessionId &&
        !sessionId
      ) {
        resetFeed();
      }
      trackedSession.current = snap.sessionId;
      setSession(snap);
    },
    [resetFeed, sessionId],
  );

  const append = useCallback((batch: TelemetryEvent[]) => {
    if (batch.length === 0) return;
    setEvents((prev) => {
      const seen = new Set(prev.map((e) => e.eventId));
      const next = [...prev];
      for (const evt of batch) {
        if (!evt?.eventId || seen.has(evt.eventId)) continue;
        seen.add(evt.eventId);
        next.push(evt);
      }
      return next;
    });
  }, []);

  useEffect(() => {
    let cancelled = false;
    let es: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const setFeedStatus = (s: FeedStatus) => {
      modeRef.current = s;
      setStatus(s);
    };

    const applyPayload = (body: LiveEventsPayload) => {
      if (body.root) setPlaneRoot(body.root);
      if (body.session?.sessionId) {
        noteSession(body.session);
      }
      append(body.events ?? []);
    };

    const pollOnce = async () => {
      const params = new URLSearchParams();
      if (sessionId) params.set('sessionId', sessionId);
      // after= only when the UI already holds events — never a detached cursor.
      const after = eventsRef.current.at(-1)?.eventId;
      if (after) params.set('after', after);
      const res = await fetch(`/api/events?${params.toString()}`);
      if (res.status === 503) return;
      if (!res.ok) throw new Error(`poll ${res.status}`);
      const body = (await res.json()) as LiveEventsPayload;
      if (cancelled) return;
      if (body.error === 'session_not_found') {
        resetFeed();
        trackedSession.current = null;
        setSession(null);
        return;
      }
      if (body.error === 'plane_busy' || body.error === 'plane_unavailable') return;
      if (body.error) {
        setError(body.error);
        return;
      }
      setError(null);
      applyPayload(body);
    };

    // Always poll for catch-up — SSE alone misses events across sqlite wipes / reconnect races.
    const startPolling = () => {
      if (pollTimer || cancelled) return;
      void pollOnce().catch((err) => {
        if (!cancelled) setError(String(err));
      });
      pollTimer = setInterval(() => {
        void pollOnce().catch((err) => {
          if (!cancelled) setError(String(err));
        });
      }, pollMs);
    };

    const streamParams = new URLSearchParams();
    if (sessionId) streamParams.set('sessionId', sessionId);
    const streamUrl = `/api/events/stream?${streamParams.toString()}`;

    try {
      es = new EventSource(streamUrl);

      es.addEventListener('ready', () => {
        if (!cancelled) {
          setFeedStatus('live-sse');
          setError(null);
        }
      });

      es.addEventListener('session', (msg) => {
        try {
          const data = JSON.parse((msg as MessageEvent).data) as LiveSessionSnapshot & {
            root?: string;
          };
          if (cancelled) return;
          if (data.root) setPlaneRoot(data.root);
          noteSession(data);
        } catch {
          /* ignore */
        }
      });

      es.addEventListener('security', (msg) => {
        try {
          const data = JSON.parse((msg as MessageEvent).data) as TelemetryEvent;
          if (cancelled) return;
          append([data]);
          setError(null);
        } catch {
          /* ignore */
        }
      });

      es.onerror = () => {
        if (cancelled) return;
        if (modeRef.current === 'live-sse') setFeedStatus('live-poll');
      };
    } catch {
      setFeedStatus('live-poll');
    }

    startPolling();
    if (modeRef.current === 'connecting') {
      // Prefer showing live-poll until SSE ready fires
      setFeedStatus('live-poll');
    }

    return () => {
      cancelled = true;
      es?.close();
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [sessionId, pollMs, append, noteSession, resetFeed]);

  return {
    events,
    session,
    status,
    planeRoot,
    error,
    securityState: session?.securityState ?? null,
  };
}
