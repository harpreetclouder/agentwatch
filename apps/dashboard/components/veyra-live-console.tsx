'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useLiveTelemetry } from '@/hooks/use-live-telemetry';
import {
  buildActivityRows,
  buildIncidentForSelection,
  buildStatePath,
  displayAgentName,
  displayTask,
  latestBlockEventId,
  unwrapAnnotationId,
  type ActivityRow,
} from '@/lib/console-view';
import type { LiveStreamMode } from '@/lib/live-session';
import type { TelemetryEvent } from '@/lib/telemetry';
import { DecisionBadge, Mono, SeverityBadge, StateBadge } from '@/lib/ui';

type Props = {
  sessionId?: string;
};

const markGlyph = { ok: '✓', warn: '⚠', block: '✕', lock: '🔒' } as const;

export function VeyraLiveConsole({ sessionId }: Props) {
  const [showHistory, setShowHistory] = useState(false);
  const live = useLiveTelemetry(
    sessionId ? { sessionId, pollMs: 500 } : { showHistory, pollMs: 500 },
  );
  const {
    events,
    session,
    status,
    planeRoot,
    error,
    securityState,
    streamMode,
    hasHistory,
    liveWake,
  } = live;

  // New live activity while viewing previous run → snap back to live tail
  useEffect(() => {
    if (liveWake && showHistory) setShowHistory(false);
  }, [liveWake, showHistory]);

  const activity = useMemo(() => buildActivityRows(events), [events]);
  const statePath = useMemo(
    () => buildStatePath(events, securityState),
    [events, securityState],
  );

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [userLocked, setUserLocked] = useState(false);
  const [pulseId, setPulseId] = useState<string | null>(null);
  const [follow, setFollow] = useState(true);
  const prevBlockRef = useRef<string | null>(null);
  const listRef = useRef<HTMLUListElement | null>(null);
  const prevLenRef = useRef(0);

  // Auto-focus newest BLOCK; pulse when a new one arrives
  useEffect(() => {
    const newest = latestBlockEventId(events);
    if (!newest) return;
    if (newest !== prevBlockRef.current) {
      prevBlockRef.current = newest;
      setPulseId(newest);
      const t = window.setTimeout(() => setPulseId(null), 1200);
      if (!userLocked) {
        setSelectedId(newest);
      }
      return () => window.clearTimeout(t);
    }
  }, [events, userLocked]);

  // Esc clears lock / selection
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setUserLocked(false);
        setSelectedId(latestBlockEventId(events));
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [events]);

  // Pause follow when operator scrolls up (log-tail UX)
  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    const onScroll = () => {
      const dist = el.scrollHeight - el.scrollTop - el.clientHeight;
      setFollow(dist < 48);
    };
    el.addEventListener('scroll', onScroll, { passive: true });
    return () => el.removeEventListener('scroll', onScroll);
  }, [activity.length > 0]);

  // Auto-scroll to latest on new events when following
  useEffect(() => {
    if (!follow || !listRef.current) return;
    if (events.length <= prevLenRef.current) {
      prevLenRef.current = events.length;
      return;
    }
    prevLenRef.current = events.length;
    const el = listRef.current;
    el.scrollTop = el.scrollHeight;
  }, [events.length, follow]);

  // Keep selected row visible when not free-scrolling
  useEffect(() => {
    if (!selectedId || !listRef.current || !userLocked) return;
    const safe =
      typeof CSS !== 'undefined' && typeof CSS.escape === 'function'
        ? CSS.escape(selectedId)
        : selectedId.replace(/"/g, '\\"');
    const el = listRef.current.querySelector(`[data-row-id="${safe}"]`);
    el?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [selectedId, userLocked]);

  const incident = useMemo(
    () => buildIncidentForSelection(events, selectedId),
    [events, selectedId],
  );

  const selectedEvent = useMemo(() => {
    if (!selectedId) return null;
    const id = unwrapAnnotationId(selectedId);
    return events.find((e) => e.eventId === id) ?? null;
  }, [events, selectedId]);

  const selectedRow = activity.find((r) => r.id === selectedId) ?? null;

  const onSelect = (row: ActivityRow) => {
    setSelectedId(row.id);
    setUserLocked(true);
  };

  const effectiveMode: LiveStreamMode = sessionId
    ? streamMode
    : showHistory
      ? 'history'
      : streamMode;

  const statusLabel = statusLabelFor(status, effectiveMode, follow);
  const waiting = activity.length === 0 && effectiveMode !== 'history';

  return (
    <div className="split-board">
      <header className="split-top">
        <div>
          <p className="live-eyebrow">VEYRA</p>
          <h1 className="live-title">LIVE</h1>
          <p className="live-subtitle">Live Session</p>
        </div>
        <div className="live-status-pill">
          <span
            className={`live-dot live-dot-${
              status === 'error'
                ? 'err'
                : effectiveMode === 'live'
                  ? 'ok'
                  : effectiveMode === 'history'
                    ? 'hist'
                    : 'idle'
            }`}
          />
          <span>{statusLabel}</span>
          {securityState && effectiveMode !== 'idle' ? (
            <StateBadge state={securityState} />
          ) : null}
        </div>
      </header>

      {error ? <p className="live-transient">Transient: {error} (retrying…)</p> : null}
      {planeRoot ? (
        <p className="muted live-plane">
          Plane: <Mono>{planeRoot}</Mono>
          <span className="split-hint"> · click a row to inspect · Esc clears</span>
        </p>
      ) : null}

      {!sessionId ? (
        <div className="live-mode-bar">
          {effectiveMode === 'history' ? (
            <span className="live-mode-tag is-history">Previous run</span>
          ) : effectiveMode === 'live' ? (
            <span className="live-mode-tag is-live">Streaming</span>
          ) : (
            <span className="live-mode-tag is-idle">Idle</span>
          )}
          {hasHistory ? (
            <button
              type="button"
              className="live-history-btn"
              onClick={() => setShowHistory((v) => !v)}
            >
              {showHistory ? 'Back to live tail' : 'Show history'}
            </button>
          ) : null}
          {!follow && activity.length > 0 ? (
            <button
              type="button"
              className="live-history-btn"
              onClick={() => {
                setFollow(true);
                if (listRef.current) {
                  listRef.current.scrollTop = listRef.current.scrollHeight;
                }
              }}
            >
              Jump to latest
            </button>
          ) : null}
        </div>
      ) : null}

      <div className="split-frame">
        <aside className="split-stream">
          <div className="split-stream-head">
            {effectiveMode === 'history' ? 'Session History' : 'Live Activity'}
          </div>
          {waiting ? (
            <p className="muted split-empty split-waiting">
              Waiting for events…
              <span className="split-waiting-sub">
                Idle tail on the local .veyra plane (prefers{' '}
                <Mono>examples/real-agent-demo</Mono>). Run a live agent or
                runtime attack against that workspace to stream PreToolUse
                decisions here. Temp product-demo workspaces are not visible.
              </span>
            </p>
          ) : activity.length === 0 ? (
            <p className="muted split-empty">No events in this session.</p>
          ) : (
            <ul className="split-activity" ref={listRef}>
              {activity.map((row) => {
                const selected = row.id === selectedId;
                const pulsing = pulseId !== null && row.id === pulseId;
                return (
                  <li key={row.id}>
                    <button
                      type="button"
                      data-row-id={row.id}
                      className={`split-row mark-${row.mark}${selected ? ' is-selected' : ''}${
                        pulsing ? ' is-pulse' : ''
                      }`}
                      onClick={() => onSelect(row)}
                    >
                      <span className="activity-glyph" aria-hidden>
                        {markGlyph[row.mark]}
                      </span>
                      <span className="split-row-body">
                        <span className="activity-label">{row.label}</span>
                        <span className="activity-meta">
                          <span>{new Date(row.timestamp).toLocaleTimeString()}</span>
                          <span>·</span>
                          <span>{row.action}</span>
                          <span>·</span>
                          <Mono>{row.resource}</Mono>
                          {row.decision ? (
                            <>
                              <span>·</span>
                              <DecisionBadge decision={row.decision} />
                            </>
                          ) : null}
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          <div className="split-stream-foot">
            {effectiveMode === 'live'
              ? follow
                ? 'Auto-scroll on · streaming'
                : 'Scroll paused · jump to latest to resume'
              : effectiveMode === 'history'
                ? 'Previous run · not a live stream'
                : 'Idle · waiting for the next session'}
          </div>
        </aside>

        <aside className="split-detail">
          <DetailAgent session={session} mode={effectiveMode} />
          <DetailStatePath path={statePath} current={securityState} />
          <DetailIncident
            incident={incident}
            selectedRow={selectedRow}
            selectedEvent={selectedEvent}
          />
          <DetailEvidence incident={incident} selectedEvent={selectedEvent} />
        </aside>
      </div>
    </div>
  );
}

function statusLabelFor(
  status: string,
  mode: LiveStreamMode,
  follow: boolean,
): string {
  if (status === 'error') return 'error';
  if (mode === 'history') return 'history';
  if (mode === 'idle') return 'waiting';
  if (!follow) return 'paused';
  return status === 'live-sse' ? 'streaming' : status === 'live-poll' ? 'streaming' : status;
}

function DetailAgent({
  session,
  mode,
}: {
  session: {
    agentName: string;
    agentRuntime: string;
    agentId: string;
    sessionId: string;
    task: string;
    workingDirectory: string;
  } | null;
  mode: LiveStreamMode;
}) {
  return (
    <section className="split-detail-block">
      <h2>Agent</h2>
      {session ? (
        <>
          <div className="split-agent-name">
            {displayAgentName(session.agentName, session.agentRuntime)}
          </div>
          {mode === 'history' ? (
            <p className="split-detail-muted">Previous run (not live)</p>
          ) : null}
          <div className="split-mono-stack">
            <div>
              <span className="split-k">Session</span> <Mono>{session.sessionId}</Mono>
            </div>
            <div>
              <span className="split-k">Task</span> {displayTask(session.task)}
            </div>
            <div>
              <span className="split-k">CWD</span> <Mono>{session.workingDirectory}</Mono>
            </div>
          </div>
        </>
      ) : (
        <p className="split-detail-muted">Waiting for a live session…</p>
      )}
    </section>
  );
}

function DetailStatePath({ path, current }: { path: string[]; current: string | null }) {
  return (
    <section className="split-detail-block">
      <h2>State</h2>
      <div className="state-path" key={path.join('-')}>
        {path.map((state, i) => (
          <span key={`${state}-${i}`} className="state-path-item">
            {i > 0 ? <span className="state-path-arrow">→</span> : null}
            <span className={state === current ? 'state-path-current' : 'state-path-past'}>
              {state}
            </span>
          </span>
        ))}
      </div>
      <p className="split-detail-muted split-state-hint">
        NORMAL → WARNING → RESTRICTED / QUARANTINED
      </p>
    </section>
  );
}

function DetailIncident({
  incident,
  selectedRow,
  selectedEvent,
}: {
  incident: ReturnType<typeof buildIncidentForSelection>;
  selectedRow: ActivityRow | null;
  selectedEvent: TelemetryEvent | null;
}) {
  return (
    <section className="split-detail-block split-incident">
      <h2>Incident</h2>
      {incident ? (
        <>
          <div className="split-policy">{incident.policy}</div>
          <div className="split-sev">
            <SeverityBadge severity={incident.severity} />
          </div>
          <p className="split-reason">{incident.reason}</p>
          <div className="split-traj">
            {incident.trajectory.map((step, i) => (
              <span key={step}>
                {i > 0 ? <span className="traj-arrow"> → </span> : null}
                <Mono>{step}</Mono>
              </span>
            ))}
          </div>
          <div className="enforcement">{incident.enforcement}</div>
        </>
      ) : selectedEvent || selectedRow ? (
        <>
          <p className="split-detail-muted">No block on this event.</p>
          <div className="split-policy soft">{selectedRow?.label ?? selectedEvent?.action.name}</div>
          <p className="split-reason">
            {selectedEvent?.action.target
              ? `Resource: ${selectedEvent.action.target}`
              : 'Select a blocked event to open an incident.'}
          </p>
        </>
      ) : (
        <p className="split-detail-muted">No blocking incident yet.</p>
      )}
    </section>
  );
}

function DetailEvidence({
  incident,
  selectedEvent,
}: {
  incident: ReturnType<typeof buildIncidentForSelection>;
  selectedEvent: TelemetryEvent | null;
}) {
  const eventId = incident?.eventId ?? selectedEvent?.eventId;
  const decisionId = incident?.decisionId ?? selectedEvent?.decisionId;
  const sessionId = incident?.sessionId ?? selectedEvent?.sessionId;
  const policy = incident?.policy ?? selectedEvent?.policy;
  const timestamp = incident?.timestamp ?? selectedEvent?.timestamp;

  return (
    <section className="split-detail-block">
      <h2>Evidence</h2>
      {eventId ? (
        <div className="split-mono-stack">
          <div>
            <span className="split-k">Event</span> <Mono>{eventId}</Mono>
          </div>
          <div>
            <span className="split-k">Decision</span>{' '}
            <Mono>{decisionId ?? '—'}</Mono>
          </div>
          <div>
            <span className="split-k">Session</span> <Mono>{sessionId}</Mono>
          </div>
          <div>
            <span className="split-k">Policy</span> <Mono>{policy ?? '—'}</Mono>
          </div>
          <div>
            <span className="split-k">Time</span>{' '}
            {timestamp ? new Date(timestamp).toLocaleString() : '—'}
          </div>
        </div>
      ) : (
        <p className="split-detail-muted">Evidence appears when you select an event.</p>
      )}
      <p className="split-secret-note">Secret contents are never shown.</p>
    </section>
  );
}
