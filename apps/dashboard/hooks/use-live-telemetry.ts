'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  LiveEventsPayload,
  LiveSessionSnapshot,
  LiveStreamMode,
} from '@/lib/live-session';
import type { TelemetryEvent } from '@/lib/telemetry';

export type FeedStatus = 'connecting' | 'live-sse' | 'live-poll' | 'error';

export function useLiveTelemetry(options: {
  sessionId?: string | undefined;
  pollMs?: number | undefined;
  /** Explicit history / previous-run view. */
  showHistory?: boolean | undefined;
} = {}) {
  const { sessionId, pollMs = 500, showHistory = false } = options;
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [status, setStatus] = useState<FeedStatus>('connecting');
  const [session, setSession] = useState<LiveSessionSnapshot | null>(null);
  const [planeRoot, setPlaneRoot] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [streamMode, setStreamMode] = useState<LiveStreamMode>('idle');
  const [hasHistory, setHasHistory] = useState(false);
  /** When true, parent should drop history view (new live activity). */
  const [liveWake, setLiveWake] = useState(false);
  /** Mirror of events — after= cursor MUST track rendered state (survives HMR desync). */
  const eventsRef = useRef<TelemetryEvent[]>([]);
  eventsRef.current = events;
  /** Seek tip when idle so we don't sticky-replay backlog on every poll. */
  const tipRef = useRef<string | null>(null);
  const trackedSession = useRef<string | null>(sessionId ?? null);
  const modeRef = useRef<FeedStatus>('connecting');
  const showHistoryRef = useRef(showHistory);
  showHistoryRef.current = showHistory;

  const resetFeed = useCallback(() => {
    setEvents([]);
    tipRef.current = null;
  }, []);

  const noteSession = useCallback(
    (snap: LiveSessionSnapshot | null) => {
      if (!snap?.sessionId) {
        if (!sessionId && !showHistoryRef.current) {
          setSession(null);
        }
        return;
      }
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

  // History toggle / session pin changes → hard reset feed
  useEffect(() => {
    resetFeed();
    trackedSession.current = sessionId ?? null;
    setSession(null);
    setStreamMode(showHistory ? 'history' : 'idle');
    setLiveWake(false);
  }, [showHistory, sessionId, resetFeed]);

  useEffect(() => {
    let cancelled = false;
    let es: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const setFeedStatus = (s: FeedStatus) => {
      modeRef.current = s;
      setStatus(s);
    };

    const applyMeta = (body: {
      root?: string | null;
      streamMode?: LiveStreamMode;
      hasHistory?: boolean;
      tipEventId?: string | null;
      session?: LiveSessionSnapshot | null;
    }) => {
      if (body.root) setPlaneRoot(body.root);
      if (body.hasHistory !== undefined) setHasHistory(body.hasHistory);
      if (body.tipEventId) tipRef.current = body.tipEventId;
      if (body.streamMode) setStreamMode(body.streamMode);
      if (body.session?.sessionId) {
        noteSession(body.session);
      } else if (body.streamMode === 'idle' && !sessionId && !showHistoryRef.current) {
        noteSession(null);
      }
    };

    const applyPayload = (body: LiveEventsPayload) => {
      applyMeta(body);
      // Auto-leave history when a fresh live session starts delivering events
      // and the operator is on unpinned /live without asking for history.
      if (
        !sessionId &&
        !showHistoryRef.current &&
        body.streamMode === 'live' &&
        (body.events?.length ?? 0) > 0
      ) {
        setStreamMode('live');
      }
      append(body.events ?? []);
    };

    const pollOnce = async () => {
      const params = new URLSearchParams();
      if (sessionId) params.set('sessionId', sessionId);
      if (showHistoryRef.current && !sessionId) params.set('history', '1');
      const after =
        eventsRef.current.at(-1)?.eventId ??
        (showHistoryRef.current ? null : tipRef.current);
      // after= only when we have a cursor — never a detached id from another session.
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
        setStreamMode('idle');
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
    if (showHistory && !sessionId) streamParams.set('history', '1');
    const streamUrl = `/api/events/stream?${streamParams.toString()}`;

    try {
      es = new EventSource(streamUrl);

      es.addEventListener('ready', () => {
        if (!cancelled) {
          setFeedStatus('live-sse');
          setError(null);
        }
      });

      es.addEventListener('mode', (msg) => {
        try {
          const data = JSON.parse((msg as MessageEvent).data) as {
            streamMode: LiveStreamMode;
            hasHistory?: boolean;
            tipEventId?: string | null;
            root?: string;
          };
          if (cancelled) return;
          applyMeta(data);
        } catch {
          /* ignore */
        }
      });

      es.addEventListener('idle', (msg) => {
        try {
          const data = JSON.parse((msg as MessageEvent).data) as {
            hasHistory?: boolean;
            tipEventId?: string | null;
            root?: string;
          };
          if (cancelled) return;
          applyMeta({ ...data, streamMode: 'idle', session: null });
          if (!sessionId && !showHistoryRef.current) {
            // Keep tip for seek; clear sticky previous-run UI.
            setSession(null);
          }
        } catch {
          /* ignore */
        }
      });

      es.addEventListener('session', (msg) => {
        try {
          const data = JSON.parse((msg as MessageEvent).data) as LiveSessionSnapshot & {
            root?: string;
            streamMode?: LiveStreamMode;
            hasHistory?: boolean;
          };
          if (cancelled) return;
          applyMeta(data);
        } catch {
          /* ignore */
        }
      });

      es.addEventListener('security', (msg) => {
        try {
          const data = JSON.parse((msg as MessageEvent).data) as TelemetryEvent;
          if (cancelled) return;
          append([data]);
          if (!showHistoryRef.current) setStreamMode('live');
          tipRef.current = data.eventId;
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
      setFeedStatus('live-poll');
    }

    // While viewing history, probe live tail so a new run can auto-focus.
    let probeTimer: ReturnType<typeof setInterval> | null = null;
    if (showHistory && !sessionId) {
      const probeLive = async () => {
        try {
          const res = await fetch('/api/events');
          if (!res.ok || cancelled) return;
          const body = (await res.json()) as LiveEventsPayload;
          if (body.streamMode === 'live' && (body.events?.length ?? 0) > 0) {
            setLiveWake(true);
          }
        } catch {
          /* ignore */
        }
      };
      void probeLive();
      probeTimer = setInterval(() => void probeLive(), Math.max(pollMs * 2, 1500));
    }

    return () => {
      cancelled = true;
      es?.close();
      if (pollTimer) clearInterval(pollTimer);
      if (probeTimer) clearInterval(probeTimer);
    };
  }, [sessionId, pollMs, showHistory, append, noteSession, resetFeed]);

  return {
    events,
    session,
    status,
    planeRoot,
    error,
    streamMode,
    hasHistory,
    liveWake,
    securityState: session?.securityState ?? null,
  };
}
