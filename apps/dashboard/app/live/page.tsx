import { openDashboardStore } from '@/lib/store';
import { EmptyState, Mono } from '@/lib/ui';
import { VeyraLiveConsole } from '@/components/veyra-live-console';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/**
 * Stage 5 — VEYRA LIVE security console.
 * Consumes real SQLite telemetry via SSE/poll (no fake data).
 */
export default async function LivePage() {
  const opened = openDashboardStore();
  if (!opened) {
    return (
      <div className="live-console">
        <header className="live-console-hero">
          <div>
            <p className="live-eyebrow">VEYRA</p>
            <h1 className="live-title">LIVE</h1>
          </div>
        </header>
        <EmptyState>
          Security plane not initialized. Run Claude in{' '}
          <Mono>examples/real-agent-demo</Mono> or <Mono>veyra init</Mono>.
          Product-demo temp workspaces are not visible here.
        </EmptyState>
      </div>
    );
  }

  opened.store.close();
  return <VeyraLiveConsole />;
}
