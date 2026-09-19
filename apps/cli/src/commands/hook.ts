import { readFileSync } from 'node:fs';
import { createId } from '@veyra/shared';
import { createClaudeCodeAdapter } from '@veyra/adapter-claude-code';
import { createCodexAdapter } from '@veyra/adapter-codex';
import type { AgentAdapter } from '@veyra/adapter-core';
import type { AgentContext } from '@veyra/agent-events';
import { isEnforcementFrozen } from '@veyra/policy-engine';
import { Watchdog } from '@veyra/watchdog';
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

/**
 * Claude Code PreToolUse deny contract (hookSpecificOutput).
 * Verified against Claude Code hook docs / existing install path.
 */
export function denyPayload(reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  });
}

function writeDeny(reason: string): void {
  process.stdout.write(`${denyPayload(reason)}\n`);
}

/**
 * Invoked by agent hooks with one JSON event on stdin.
 * Observes via Watchdog; denies PreToolUse when policy BLOCK/QUARANTINE.
 * Security-sensitive PreToolUse: fail closed on parse / decision failure.
 */
export async function cmdHook(args: string[]): Promise<number> {
  const requested = (flagValue(args, '--adapter') ?? 'claude-code').toLowerCase();
  const adapter: AgentAdapter =
    requested === 'codex' ? createCodexAdapter() : createClaudeCodeAdapter();

  const rawText = readStdinSync().trim();
  if (!rawText) {
    // Empty stdin — nothing to evaluate (informational)
    return 0;
  }

  let raw: unknown;
  try {
    raw = JSON.parse(rawText) as unknown;
  } catch {
    // Malformed security event on PreToolUse must fail closed.
    // Without parse we cannot know the event type — deny to be safe.
    writeDeny('VEYRA fail-closed: malformed hook JSON; denying tool use.');
    return 0;
  }

  // If we can detect PreToolUse, fail closed on any evaluation error.
  const preTool = isPreToolUse(raw);

  try {
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
          (await store.securityState.get(sessionId))?.state ??
          session?.securityState ??
          'NORMAL',
      };

      const watchdog = new Watchdog({ store, enableSemantic: false });
      let blocked = isEnforcementFrozen(agentContext.securityState);
      let blockReason =
        'Session is QUARANTINED. Operator must run `veyra resume` before actions proceed.';
      let observed = false;

      const agentSession = await adapter.start({
        sessionId,
        agentId,
        workingDirectory: process.cwd(),
        onEvent: async (event) => {
          observed = true;
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

      if (preTool && blocked) {
        writeDeny(blockReason);
      } else if (preTool && !observed) {
        // Unrecognized PreToolUse shape — fail closed
        writeDeny(
          'VEYRA fail-closed: could not normalize PreToolUse into AgentEvent; denying tool use.',
        );
      }

      return 0;
    } finally {
      store.close();
    }
  } catch (err) {
    if (preTool) {
      const message = err instanceof Error ? err.message : String(err);
      writeDeny(`VEYRA fail-closed: security evaluation error (${message}); denying tool use.`);
      return 0;
    }
    throw err;
  }
}
