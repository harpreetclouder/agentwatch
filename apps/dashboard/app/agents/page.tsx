import Link from 'next/link';
import { openDashboardStore, shortId, formatTime } from '@/lib/store';
import { DataTable, EmptyState, Mono, PageHeader, StateBadge } from '@/lib/ui';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export default async function AgentsPage() {
  const opened = openDashboardStore();
  if (!opened) {
    return (
      <>
        <PageHeader title="Agents" />
        <EmptyState>
          Security plane not initialized. Run <Mono>veyra init</Mono>.
        </EmptyState>
      </>
    );
  }

  const { store } = opened;
  try {
    const agents = await store.agents.list();

    return (
      <>
        <PageHeader
          title="Agents"
          subtitle="Registered agent identities (Passport precursor)."
        />
        {agents.length === 0 ? (
          <EmptyState>No agents registered yet.</EmptyState>
        ) : (
          <section className="panel">
            <DataTable
              headers={['Name', 'Runtime', 'Model', 'Updated', 'Sessions']}
              rows={await Promise.all(
                agents.map(async (a) => {
                  const sessions = await store.sessions.listByAgent(a.id);
                  const latest = sessions[0];
                  return [
                    <span key="n">
                      <strong>{a.name}</strong>
                      <div className="muted" style={{ fontSize: '0.8rem' }}>
                        <Mono>{shortId(a.id)}</Mono>
                      </div>
                    </span>,
                    a.runtime,
                    a.model ?? '—',
                    formatTime(a.updatedAt),
                    latest ? (
                      <span key="s">
                        {sessions.length}{' '}
                        <Link href={`/sessions/${latest.id}`}>latest →</Link>
                        {latest ? (
                          <div style={{ marginTop: '0.25rem' }}>
                            <StateBadge state={latest.securityState} />
                          </div>
                        ) : null}
                      </span>
                    ) : (
                      '0'
                    ),
                  ];
                }),
              )}
            />
          </section>
        )}
      </>
    );
  } finally {
    store.close();
  }
}
