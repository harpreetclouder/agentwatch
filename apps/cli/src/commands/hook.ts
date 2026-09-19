import { readFileSync } from 'node:fs';
import { createId } from '@veyra/shared';
import { createClaudeCodeAdapter } from '@veyra/adapter-claude-code';
import { createCodexAdapter } from '@veyra/adapter-codex';
import type { AgentAdapter } from '@veyra/adapter-core';
import type { AgentContext } from '@veyra/agent-events';
import { isEnforcementFrozen, type SecurityDecision } from '@veyra/policy-engine';
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

function extractHookCwd(raw: unknown, fallback: string): string {
  if (!raw || typeof raw !== 'object') {
    return fallback;
  }
  const cwd = (raw as Record<string, unknown>)['cwd'];
  return typeof cwd === 'string' && cwd.length > 0 ? cwd : fallback;
}

/**
 * Claude Code PreToolUse deny contract (verified against code.claude.com/docs/en/hooks):
 * exit 0 + stdout JSON:
 * {
 *   "hookSpecificOutput": {
 *     "hookEventName": "PreToolUse",
 *     "permissionDecision": "deny",
 *     "permissionDecisionReason": "..."
 *   }
 * }
 * Empty stdout = allow (normal permission flow). Exit 2 also blocks but is less portable.
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

export type ClaudeDenyPayload = {
  hookEventName: string;
  permissionDecision: string;
  permissionDecisionReason: string;
};

/** Parse Claude deny JSON from hook stdout (first JSON object). */
export function parseDenyPayload(stdout: string): ClaudeDenyPayload | null {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return null;
  }
  try {
    const parsed = JSON.parse(trimmed) as {
      hookSpecificOutput?: {
        hookEventName?: string;
        permissionDecision?: string;
        permissionDecisionReason?: string;
      };
    };
    const out = parsed.hookSpecificOutput;
    if (!out?.permissionDecision) {
      return null;
    }
    return {
      hookEventName: out.hookEventName ?? 'PreToolUse',
      permissionDecision: out.permissionDecision,
      permissionDecisionReason: out.permissionDecisionReason ?? '',
    };
  } catch {
    return null;
  }
}

/**
 * Structured reason so operators/tests can assert policy without parsing free text.
 * Shown to Claude as permissionDecisionReason.
 */
export function formatDenyReason(decision: SecurityDecision): string {
  return (
    `[VEYRA] policy=${decision.ruleId} decision=${decision.decision} ` +
    `severity=${decision.severity} | ${decision.reason}`
  );
}

function writeDeny(reason: string): void {
  process.stdout.write(`${denyPayload(reason)}\n`);
}

/**
 * Invoked by agent hooks with one JSON event on stdin.
 *
 * Fail-closed (PreToolUse / security-sensitive):
 * - malformed JSON → DENY
 * - normalize failure → DENY
 * - evaluation / store errors → DENY
 * - BLOCK / QUARANTINE / frozen session → DENY
 *
 * Fail-open (informational):
 * - empty stdin → exit 0, no output
 * - UserPromptSubmit / PostToolUse errors do not emit PreToolUse deny
 * - allowed PreToolUse → empty stdout (Claude continues normal permission flow)
 */
export async function cmdHook(args: string[]): Promise<number> {
  const requested = (flagValue(args, '--adapter') ?? 'claude-code').toLowerCase();
  const adapter: AgentAdapter =
    requested === 'codex' ? createCodexAdapter() : createClaudeCodeAdapter();

  const rawText = readStdinSync().trim();
  if (!rawText) {
    // Empty stdin — nothing to evaluate (informational / bridge probe)
    return 0;
  }

  let raw: unknown;
  try {
    raw = JSON.parse(rawText) as unknown;
  } catch {
    writeDeny('VEYRA fail-closed: malformed hook JSON; denying tool use.');
    return 0;
  }

  const preTool = isPreToolUse(raw);
  const workingDirectory = extractHookCwd(raw, process.cwd());

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
          workingDirectory,
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
        workingDirectory,
        environment: 'local',
        securityState:
          (await store.securityState.get(sessionId))?.state ??
          session?.securityState ??
          'NORMAL',
      };

      const watchdog = new Watchdog({ store, enableSemantic: false });
      let blocked = isEnforcementFrozen(agentContext.securityState);
      let blockReason =
        '[VEYRA] policy=SESSION_QUARANTINED decision=QUARANTINE severity=CRITICAL | ' +
        'Session is QUARANTINED. Operator must run `veyra resume` before actions proceed.';
      let observed = false;

      const agentSession = await adapter.start({
        sessionId,
        agentId,
        workingDirectory,
        onEvent: async (event) => {
          observed = true;
          const obs = await watchdog.observe(event, agentContext);
          if (obs.blocked && obs.primaryPolicy) {
            blocked = true;
            blockReason = formatDenyReason(obs.primaryPolicy);
          } else if (obs.blocked) {
            blocked = true;
          }
        },
      });

      await agentSession.ingest(raw);
      await agentSession.stop();

      if (session) {
        await store.sessions.update({
          ...session,
          workingDirectory,
          securityState: agentContext.securityState,
          status:
            agentContext.securityState === 'QUARANTINED' ? 'QUARANTINED' : session.status,
        });
      }

      if (preTool && blocked) {
        writeDeny(blockReason);
      } else if (preTool && !observed) {
        // Unknown / unnormalizable PreToolUse — safe default is DENY
        writeDeny(
          '[VEYRA] policy=FAIL_CLOSED decision=DENY severity=HIGH | ' +
            'could not normalize PreToolUse into AgentEvent; denying tool use.',
        );
      }

      return 0;
    } finally {
      store.close();
    }
  } catch (err) {
    if (preTool) {
      const message = err instanceof Error ? err.message : String(err);
      writeDeny(
        `[VEYRA] policy=FAIL_CLOSED decision=DENY severity=HIGH | ` +
          `security evaluation error (${message}); denying tool use.`,
      );
      return 0;
    }
    throw err;
  }
}
