import { printBanner } from '../ui.js';
import { openLocalStore } from '../store.js';

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

export async function cmdStatus(_args: string[]): Promise<number> {
  printBanner();

  const store = openLocalStore();
  if (!store) {
    console.log('Agent:   (none — not initialized)');
    console.log('Session: (none)');
    console.log('Task:    (none)');
    console.log('');
    console.log('Status:  UNINITIALIZED');
    console.log('');
    console.log('Hint: run `veyra init` to create the local security plane.');
    console.log('');
    return 0;
  }

  try {
    const session =
      (await store.sessions.findLatestActive()) ?? (await store.sessions.findLatest());
    if (!session) {
      console.log('Agent:   (none — not watching)');
      console.log('Session: (none)');
      console.log('Task:    (none)');
      console.log('');
      console.log('Status:  IDLE');
      console.log('');
      console.log('Events:    0');
      console.log('Warnings:  0');
      console.log('Blocks:    0');
      console.log('Critical:  0');
      console.log('');
      console.log('Hint: run `veyra attack` or `veyra watch`.');
      console.log('');
      return 0;
    }

    const agent = await store.agents.findById(session.agentId);
    const stats = await store.stats.getSessionStats(session.id);
    const state = (await store.securityState.get(session.id))?.state ?? session.securityState;

    console.log(`Agent:   ${agent?.name ?? session.agentId}`);
    console.log(`Session: ${shortId(session.id)}`);
    console.log(`Task:    ${session.taskDescription ?? '(none)'}`);
    console.log('');
    console.log(`Status:  ${session.status === 'ENDED' ? state : session.status === 'QUARANTINED' ? 'QUARANTINED' : state}`);
    console.log('');
    console.log(`Events:    ${stats.events}`);
    console.log(`Warnings:  ${stats.warnings}`);
    console.log(`Blocks:    ${stats.blocks}`);
    console.log(`Critical:  ${stats.critical}`);
    console.log('');
    return 0;
  } finally {
    store.close();
  }
}
