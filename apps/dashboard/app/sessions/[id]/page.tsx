import Link from 'next/link';
import { notFound } from 'next/navigation';
import { openDashboardStore, shortId, formatTime } from '@/lib/store';
import {
  DecisionBadge,
  EmptyState,
  Mono,
  PageHeader,
  StateBadge,
} from '@/lib/ui';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

type Props = { params: Promise<{ id: string }> };

export default async function SessionTimelinePage({ params }: Props) {
  const { id } = await params;
  const opened = openDashboardStore();
  if (!opened) {
    return (
      <>
        <PageHeader title="Session" />
        <EmptyState>
          Security plane not initialized. Run <Mono>veyra init</Mono>.
        </EmptyState>
      </>
    );
  }

  const { store } = opened;
  try {
    const session = await store.sessions.findById(id);
    if (!session) {
      notFound();
    }

    const [agent, events, decisions, violations, stats] = await Promise.all([
      store.agents.findById(session.agentId),
      store.events.findBySession(session.id),
      store.decisions.findBySession(session.id),
      store.violations.findBySession(session.id),
      store.stats.getSessionStats(session.id),
    ]);

    const decisionByEvent = new Map(decisions.map((d) => [d.eventId, d]));

    return (
      <>
        <p style={{ margin: '0 0 0.75rem' }}>
          <Link href="/">← Overview</Link>
        </p>
        <PageHeader
          title={`Session ${shortId(session.id)}`}
          subtitle={session.taskDescription ?? 'No task description'}
        />

        <div className="stat-grid">
          <div className="stat">
            <div className="stat-label">Agent</div>
            <div className="stat-value" style={{ fontSize: '1.15rem' }}>
              {agent?.name ?? shortId(session.agentId)}
            </div>
          </div>
          <div className="stat">
            <div className="stat-label">State</div>
            <div style={{ marginTop: '0.45rem' }}>
              <StateBadge state={session.securityState} />
            </div>
          </div>
          <div className="stat">
            <div className="stat-label">Events</div>
            <div className="stat-value">{stats.events}</div>
          </div>
          <div className="stat">
            <div className="stat-label">Blocks</div>
            <div className="stat-value">{stats.blocks}</div>
          </div>
        </div>

        <section className="panel">
          <h2 style={{ margin: '0 0 0.75rem', fontSize: '1.05rem' }}>Event timeline</h2>
          {events.length === 0 ? (
            <EmptyState>No events in this session.</EmptyState>
          ) : (
            <div className="timeline">
              {events.map((e) => {
                const decision = decisionByEvent.get(e.id);
                return (
                  <div key={e.id} className="timeline-item">
                    <div className="timeline-time">{formatTime(e.timestamp)}</div>
                    <div className="timeline-body">
                      <div className="timeline-title">
                        <Mono>{e.type}</Mono>{' '}
                        <span>{e.action.name}</span>
                        {e.action.target ? (
                          <span className="muted"> · {e.action.target}</span>
                        ) : null}
                      </div>
                      {decision ? (
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                          <DecisionBadge decision={decision.decision} />
                          <span className="muted" style={{ fontSize: '0.85rem' }}>
                            {decision.ruleId}: {decision.reason}
                          </span>
                        </div>
                      ) : null}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {violations.length > 0 ? (
          <section className="panel" style={{ marginTop: '1rem' }}>
            <h2 style={{ margin: '0 0 0.75rem', fontSize: '1.05rem' }}>
              Violations in session
            </h2>
            <ul style={{ margin: 0, paddingLeft: '1.1rem' }}>
              {violations.map((v) => (
                <li key={v.id} style={{ marginBottom: '0.4rem' }}>
                  <Mono>{v.ruleId}</Mono> — {v.summary}
                </li>
              ))}
            </ul>
          </section>
        ) : null}
      </>
    );
  } finally {
    store.close();
  }
}
