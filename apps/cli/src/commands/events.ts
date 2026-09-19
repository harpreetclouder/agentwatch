import { printBanner } from '../ui.js';
import { openLocalStore } from '../store.js';

function formatTime(iso: string): string {
  try {
    return new Date(iso).toISOString().slice(11, 19);
  } catch {
    return iso;
  }
}

export async function cmdEvents(args: string[]): Promise<number> {
  printBanner();

  const store = openLocalStore();
  if (!store) {
    console.log('No security plane found. Run `jev init` first.');
    console.log('');
    return 1;
  }

  try {
    const sessionIdFlag = args.find((a) => a.startsWith('--session='))?.slice('--session='.length);
    const session =
      (sessionIdFlag ? await store.sessions.findById(sessionIdFlag) : null) ??
      (await store.sessions.findLatestActive()) ??
      (await store.sessions.findLatest());

    if (!session) {
      console.log('No sessions yet.');
      console.log('');
      return 0;
    }

    const events = await store.events.findBySession(session.id);
    const decisions = await store.decisions.findBySession(session.id);
    const decisionByEvent = new Map(decisions.map((d) => [d.eventId, d]));

    console.log(`Session: ${session.id}`);
    console.log(`Events:  ${events.length}`);
    console.log('');

    if (events.length === 0) {
      console.log('(empty)');
      console.log('');
      return 0;
    }

    for (const event of events) {
      const decision = decisionByEvent.get(event.id);
      const mark =
        decision?.decision === 'BLOCK' || decision?.decision === 'QUARANTINE'
          ? '✕'
          : decision?.decision === 'WARN'
            ? '⚠'
            : '✓';
      const target = event.action.target ?? event.action.name;
      console.log(
        `${formatTime(event.timestamp)}  ${event.type.padEnd(12)} ${target.padEnd(28)} ${mark}`,
      );
    }

    console.log('');
    return 0;
  } finally {
    store.close();
  }
}
