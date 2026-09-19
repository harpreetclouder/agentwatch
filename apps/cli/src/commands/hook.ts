import { readFileSync } from 'node:fs';
import { createId } from '@jev/shared';
import { createClaudeCodeAdapter } from '@jev/adapter-claude-code';
import { createCodexAdapter } from '@jev/adapter-codex';
import type { AgentAdapter } from '@jev/adapter-core';
import type { AgentContext } from '@jev/agent-events';
import { isEnforcementFrozen } from '@jev/policy-engine';
import { Watchdog } from '@jev/watchdog';
import { ensureLocalStore } from '../store.js';

function flagValue(args: string[], name: string): string | undefined {
  const prefixed = args.find((a) => a.startsWith(`${name}=`));
  if (prefixed) {
    return prefixed.slice(name.length + 1);
  }
  const idx = args.indexOf(name);
  if (idx >= 0 && args[idx + 1] && !args[idx + 1]!.startsWith('-')) {
    return args[idx + 1];
  }
  return undefined;
}

function readStdinSync(): string {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

function isPreToolUse(raw: unknown): boolean {
  if (!raw || typeof raw !== 'object') {
    return false;
  }
  const rec = raw as Record<string, unknown>;
  const name = rec['hook_event_name'] ?? rec['hookEventName'] ?? rec['event'];
  return name === 'PreToolUse' || name === 'pre_tool_use';
}

function denyPayload(reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  });
}

/**
 * Invoked by agent hooks with one JSON event on stdin.
 * Observes via Watchdog; denies PreToolUse when policy BLOCK/QUARANTINE.
 * Quiet on success — stdout only used for structured deny.
 */
export async function cmdHook(args: string[]): Promise<number> {
  const requested = (flagValue(args, '--adapter') ?? 'claude-code').toLowerCase();
  const adapter: AgentAdapter =
    requested === 'codex' ? createCodexAdapter() : createClaudeCodeAdapter();

  const rawText = readStdinSync().trim();
  if (!rawText) {
    return 0;
  }

  let raw: unknown;
  try {
    raw = JSON.parse(rawText) as unknown;
  } catch {
    return 0;
  }

  const { store } = ensureLocalStore();
  try {
    const now = new Date().toISOString();
    let session = await store.sessions.findLatestActive();
    let agentId: string;
    let sessionId: string;

    if (session && (session.status === 'ACTIVE' || session.status === 'QUARANTINED')) {
      agentId = session.agentId;
      sessionId = session.id;
    } else {
      agentId = createId('agent');
      sessionId = createId('sess');
      await store.agents.upsert({
        id: agentId,
        name: adapter.name === 'codex' ? 'Codex' : 'Claude Code',
        runtime: adapter.name,
        model: null,
        createdAt: now,
        updatedAt: now,
      });
      await store.sessions.create({
        id: sessionId,
        agentId,
        taskId: null,
        taskDescription: 'live-bridge',
        workingDirectory: process.cwd(),
        environment: 'local',
        status: 'ACTIVE',
        securityState: 'NORMAL',
        startedAt: now,
        endedAt: null,
      });
      await store.securityState.set(sessionId, 'NORMAL', 'live bridge');
      session = await store.sessions.findById(sessionId);
    }

    const agentContext: AgentContext = {
      agentId,
      sessionId,
      workingDirectory: process.cwd(),
      environment: 'local',
      securityState:
        (await store.securityState.get(sessionId))?.state ?? session?.securityState ?? 'NORMAL',
    };

    const watchdog = new Watchdog({ store, enableSemantic: false });
    let blocked = isEnforcementFrozen(agentContext.securityState);
    let blockReason =
      'Session is QUARANTINED. Operator must run `jev resume` before actions proceed.';

    const agentSession = await adapter.start({
      sessionId,
      agentId,
      workingDirectory: process.cwd(),
      onEvent: async (event) => {
        const obs = await watchdog.observe(event, agentContext);
        if (obs.blocked) {
          blocked = true;
          if (obs.primaryPolicy?.reason) {
            blockReason = obs.primaryPolicy.reason;
          }
        }
      },
    });

    await agentSession.ingest(raw);
    await agentSession.stop();

    if (session) {
      await store.sessions.update({
        ...session,
        securityState: agentContext.securityState,
        status:
          agentContext.securityState === 'QUARANTINED' ? 'QUARANTINED' : session.status,
      });
    }

    if (blocked && isPreToolUse(raw)) {
      process.stdout.write(`${denyPayload(blockReason)}\n`);
    }

    return 0;
  } finally {
    store.close();
  }
}
