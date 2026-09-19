import Link from 'next/link';
import { openDashboardStore, shortId, formatTime } from '@/lib/store';
import {
  DataTable,
  EmptyState,
  Mono,
  PageHeader,
  SeverityBadge,
  StateBadge,
} from '@/lib/ui';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export default async function OverviewPage() {
  const opened = openDashboardStore();
  if (!opened) {
    return (
      <>
        <PageHeader
          title="Overview"
          subtitle="Local security plane is not initialized."
        />
        <EmptyState>
          Run <Mono>veyra init</Mono> in the project root, then ingest events with{' '}
          <Mono>veyra watch</Mono> or <Mono>veyra attack</Mono>.
        </EmptyState>
      </>
    );
  }

  const { store, root } = opened;
  try {
    const [agents, sessions, violations, decisions] = await Promise.all([
      store.agents.list(),
      store.sessions.list(20),
      store.violations.listRecent(20),
      store.decisions.listRecent(20),
    ]);

    const active = sessions.filter((s) => s.status === 'ACTIVE' || s.status === 'QUARANTINED');
    const blocks = decisions.filter((d) => d.decision === 'BLOCK' || d.decision === 'QUARANTINE');

    return (
      <>
        <PageHeader
          title="Overview"
          subtitle={`Read-only view of agents, sessions, and enforcement from ${root}/.veyra`}
        />

        <div className="stat-grid">
          <div className="stat">
            <div className="stat-label">Agents</div>
            <div className="stat-value">{agents.length}</div>
          </div>
          <div className="stat">
            <div className="stat-label">Active sessions</div>
            <div className="stat-value">{active.length}</div>
          </div>
          <div className="stat">
            <div className="stat-label">Recent blocks</div>
            <div className="stat-value">{blocks.length}</div>
          </div>
          <div className="stat">
            <div className="stat-label">Violations</div>
            <div className="stat-value">{violations.length}</div>
          </div>
        </div>

        <section className="panel">
          <h2 style={{ margin: '0 0 0.75rem', fontSize: '1.05rem' }}>Recent sessions</h2>
          {sessions.length === 0 ? (
            <EmptyState>No sessions yet.</EmptyState>
          ) : (
            <DataTable
              headers={['Session', 'Agent', 'State', 'Started', '']}
              rows={await Promise.all(
                sessions.map(async (s) => {
                  const agent = await store.agents.findById(s.agentId);
                  return [
                    <Mono key="id">{shortId(s.id)}</Mono>,
                    agent?.name ?? shortId(s.agentId),
                    <StateBadge key="st" state={s.securityState} />,
                    formatTime(s.startedAt),
                    <Link key="l" href={`/sessions/${s.id}`}>
                      Timeline →
                    </Link>,
                  ];
                }),
              )}
            />
          )}
        </section>

        <section className="panel" style={{ marginTop: '1rem' }}>
          <h2 style={{ margin: '0 0 0.75rem', fontSize: '1.05rem' }}>Latest security events</h2>
          {violations.length === 0 ? (
            <EmptyState>
              No violations recorded. Try <Mono>veyra attack</Mono>.
            </EmptyState>
          ) : (
            <DataTable
              headers={['When', 'Rule', 'Severity', 'Summary', '']}
              rows={violations.slice(0, 8).map((v) => [
                formatTime(v.createdAt),
                <Mono key="r">{v.ruleId}</Mono>,
                <SeverityBadge key="sev" severity={v.severity} />,
                v.summary,
                <Link key="l" href={`/sessions/${v.sessionId}`}>
                  View →
                </Link>,
              ])}
            />
          )}
          <p style={{ marginTop: '0.85rem' }}>
            <Link href="/security">All security events →</Link>
          </p>
        </section>
      </>
    );
  } finally {
    store.close();
  }
}
