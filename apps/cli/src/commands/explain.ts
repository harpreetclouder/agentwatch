import { existsSync, readFileSync } from 'node:fs';
import { formatExplainReport, type SecurityReport } from '@veyra/attack-engine';
import { printBanner } from '../ui.js';
import { lastReportPath } from './attack.js';
import { openLocalStore } from '../store.js';

function shortId(id: string): string {
  return id.length > 12 ? id.slice(0, 12) : id;
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toISOString().slice(11, 19);
  } catch {
    return iso;
  }
}

/**
 * Human-readable security incident timeline for a live session,
 * or fallback to last attack report when no session id given.
 */
export async function cmdExplain(args: string[]): Promise<number> {
  printBanner();

  const sessionArg = args.find((a) => !a.startsWith('-'));
  const store = openLocalStore();

  if (sessionArg && store) {
    try {
      const sessions = await store.sessions.list(50);
      const session =
        (await store.sessions.findById(sessionArg)) ??
        sessions.find((s) => s.id.startsWith(sessionArg)) ??
        null;

      if (!session) {
        console.log(`No session matching "${sessionArg}".`);
        console.log('Use: veyra status   or   veyra explain <session-id>');
        console.log('');
        return 1;
      }

      const agent = await store.agents.findById(session.agentId);
      const events = await store.events.findBySession(session.id);
      const decisions = await store.decisions.findBySession(session.id);
      const state =
        (await store.securityState.get(session.id))?.state ?? session.securityState;

      const decisionByEvent = new Map(decisions.map((d) => [d.eventId, d]));

      console.log('VEYRA SECURITY INCIDENT');
      console.log('');
      console.log(`Session:     ${session.id}`);
      console.log(`Agent:       ${agent?.name ?? session.agentId}`);
      console.log(`Task:        ${session.taskDescription ?? '—'}`);
      console.log(`Final state: ${state}`);
      console.log('');
      console.log('Timeline:');
      console.log('');

      for (const event of events) {
        const d = decisionByEvent.get(event.id);
        const outcome = d?.decision ?? 'ALLOW';
        const target = event.action.target ? ` ${event.action.target}` : '';
        const line = `${formatTime(event.timestamp)}  ${event.type.toUpperCase()} ${event.action.name}${target}`;
        console.log(line);
        console.log(`            ${outcome}${d ? ` (${d.ruleId})` : ''}`);
        if (d?.reason) {
          console.log(`            ${d.reason}`);
        }
        console.log('');
      }

      const blocks = decisions.filter(
        (d) => d.decision === 'BLOCK' || d.decision === 'QUARANTINE',
      );
      if (blocks[0]) {
        console.log('Enforcement:');
        console.log(`  Policy:   ${blocks[0].ruleId}`);
        console.log(`  Decision: ${blocks[0].decision}`);
        console.log('  BLOCKED BEFORE TOOL EXECUTION');
        console.log('');
      }

      console.log(`Events: ${events.length} · Decisions: ${decisions.length}`);
      console.log(`Short:  veyra explain ${shortId(session.id)}`);
      console.log('');
      return 0;
    } finally {
      store.close();
    }
  }

  if (store) {
    store.close();
  }

  // Fallback: last attack simulation report
  const path = lastReportPath();
  if (!existsSync(path)) {
    console.log('No session id and no attack report found.');
    console.log('');
    console.log('Usage:');
    console.log('  veyra explain <session-id>');
    console.log('  veyra attack --mode=simulation && veyra explain');
    console.log('');
    return 1;
  }

  try {
    const report = JSON.parse(readFileSync(path, 'utf8')) as SecurityReport;
    console.log(formatExplainReport(report));
    return 0;
  } catch {
    console.error('Failed to read last security report.');
    return 1;
  }
}
