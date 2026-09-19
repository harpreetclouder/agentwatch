import Link from 'next/link';
import { openDashboardStore, shortId, formatTime } from '@/lib/store';
import {
  DataTable,
  DecisionBadge,
  EmptyState,
  Mono,
  PageHeader,
  SeverityBadge,
} from '@/lib/ui';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export default async function SecurityPage() {
  const opened = openDashboardStore();
  if (!opened) {
    return (
      <>
        <PageHeader title="Security events" />
        <EmptyState>
          Security plane not initialized. Run <Mono>jev init</Mono>.
        </EmptyState>
      </>
    );
  }

  const { store } = opened;
  try {
    const [violations, decisions] = await Promise.all([
      store.violations.listRecent(100),
      store.decisions.listRecent(100),
    ]);

    return (
      <>
        <PageHeader
          title="Security events"
          subtitle="Deterministic policy violations and non-ALLOW decisions."
        />

        <section className="panel">
          <h2 style={{ margin: '0 0 0.75rem', fontSize: '1.05rem' }}>Violations</h2>
          {violations.length === 0 ? (
            <EmptyState>No violations yet.</EmptyState>
          ) : (
            <DataTable
              headers={['When', 'Rule', 'Severity', 'Session', 'Summary']}
              rows={violations.map((v) => [
                formatTime(v.createdAt),
                <Mono key="r">{v.ruleId}</Mono>,
                <SeverityBadge key="sev" severity={v.severity} />,
                <Link key="s" href={`/sessions/${v.sessionId}`}>
                  <Mono>{shortId(v.sessionId)}</Mono>
                </Link>,
                v.summary,
              ])}
            />
          )}
        </section>

        <section className="panel" style={{ marginTop: '1rem' }}>
          <h2 style={{ margin: '0 0 0.75rem', fontSize: '1.05rem' }}>Decisions</h2>
          {decisions.length === 0 ? (
            <EmptyState>No WARN/BLOCK/QUARANTINE decisions yet.</EmptyState>
          ) : (
            <DataTable
              headers={['When', 'Decision', 'Rule', 'Reason', 'Session']}
              rows={decisions.map((d) => [
                formatTime(d.createdAt),
                <DecisionBadge key="d" decision={d.decision} />,
                <Mono key="r">{d.ruleId}</Mono>,
                d.reason,
                <Link key="s" href={`/sessions/${d.sessionId}`}>
                  <Mono>{shortId(d.sessionId)}</Mono>
                </Link>,
              ])}
            />
          )}
        </section>
      </>
    );
  } finally {
    store.close();
  }
}
