'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useLiveTelemetry } from '@/hooks/use-live-telemetry';
import {
  buildActivityRows,
  buildIncidentForSelection,
  buildStatePath,
  displayAgentName,
  latestBlockEventId,
  type ActivityRow,
} from '@/lib/console-view'; // Split Board selectors
import type { TelemetryEvent } from '@/lib/telemetry';
import { DecisionBadge, Mono, SeverityBadge, StateBadge } from '@/lib/ui';

type Props = {
  sessionId?: string;
};

const markGlyph = { ok: '✓', warn: '⚠', block: '✕' } as const;

export function VeyraLiveConsole({ sessionId }: Props) {
  const live = useLiveTelemetry(sessionId ? { sessionId } : {});
  const { events, session, status, planeRoot, error, securityState } = live;

  const activity = useMemo(() => buildActivityRows(events), [events]);
  const statePath = useMemo(
    () => buildStatePath(events, securityState),
    [events, securityState],
  );

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [userLocked, setUserLocked] = useState(false);
  const [pulseId, setPulseId] = useState<string | null>(null);
  const prevBlockRef = useRef<string | null>(null);
  const listRef = useRef<HTMLUListElement | null>(null);

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

  // Keep selected row visible
  useEffect(() => {
    if (!selectedId || !listRef.current) return;
    const safe =
      typeof CSS !== 'undefined' && typeof CSS.escape === 'function'
        ? CSS.escape(selectedId)
        : selectedId.replace(/"/g, '\\"');
    const el = listRef.current.querySelector(`[data-row-id="${safe}"]`);
    el?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [selectedId]);

  const incident = useMemo(
    () => buildIncidentForSelection(events, selectedId),
    [events, selectedId],
  );

  const selectedEvent = useMemo(() => {
    if (!selectedId) return null;
    const id = selectedId.startsWith('ann-inject-')
      ? selectedId.slice('ann-inject-'.length)
      : selectedId;
    return events.find((e) => e.eventId === id) ?? null;
  }, [events, selectedId]);

  const selectedRow = activity.find((r) => r.id === selectedId) ?? null;

  const onSelect = (row: ActivityRow) => {
    setSelectedId(row.id);
    setUserLocked(true);
  };

  return (
    <div className="split-board">
      <header className="split-top">
        <div>
          <p className="live-eyebrow">VEYRA</p>
          <h1 className="live-title">LIVE</h1>
        </div>
        <div className="live-status-pill">
          <span className={`live-dot live-dot-${status === 'error' ? 'err' : 'ok'}`} />
          <span>{status}</span>
          {securityState ? <StateBadge state={securityState} /> : null}
        </div>
      </header>

      {error ? <p className="live-transient">Transient: {error} (retrying…)</p> : null}
      {planeRoot ? (
        <p className="muted live-plane">
          Plane: <Mono>{planeRoot}</Mono>
          <span className="split-hint"> · click a row to inspect · Esc clears</span>
        </p>
      ) : null}

      <div className="split-frame">
        <aside className="split-stream">
          <div className="split-stream-head">Live Activity</div>
          {activity.length === 0 ? (
            <p className="muted split-empty">Waiting for agent events…</p>
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
          <div className="split-stream-foot">Auto-follow blocks · stream updates live</div>
        </aside>

        <aside className="split-detail">
          <DetailAgent session={session} />
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

function DetailAgent({
  session,
}: {
  session: {
    agentName: string;
    agentRuntime: string;
    agentId: string;
    sessionId: string;
    task: string;
    workingDirectory: string;
  } | null;
}) {
  return (
    <section className="split-detail-block">
      <h2>Agent</h2>
      {session ? (
        <>
          <div className="split-agent-name">
            {displayAgentName(session.agentName, session.agentRuntime)}
          </div>
          <div className="split-mono-stack">
            <div>
              <span className="split-k">Agent ID</span> <Mono>{session.agentId}</Mono>
            </div>
            <div>
              <span className="split-k">Session</span> <Mono>{session.sessionId}</Mono>
            </div>
            <div>
              <span className="split-k">Task</span> {session.task}
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
      <h2>Security State</h2>
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
      <h2>Security Incident</h2>
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
