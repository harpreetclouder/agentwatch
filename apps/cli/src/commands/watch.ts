import { createInterface } from 'node:readline';
import { createId } from '@jev/shared';
import { createClaudeCodeAdapter } from '@jev/adapter-claude-code';
import { createCodexAdapter } from '@jev/adapter-codex';
import type { AgentAdapter } from '@jev/adapter-core';
import type { AgentContext } from '@jev/agent-events';
import { Watchdog, describeSemanticProvider } from '@jev/watchdog';
import { printBanner } from '../ui.js';
import { ensureLocalStore } from '../store.js';

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

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

async function resolveAdapter(args: string[]): Promise<{
  adapter: AgentAdapter;
  detected: boolean;
  reason: string;
}> {
  const requested = (flagValue(args, '--adapter') ?? 'auto').toLowerCase();

  const claude = createClaudeCodeAdapter();
  const codex = createCodexAdapter();

  if (requested === 'claude-code' || requested === 'claude') {
    return {
      adapter: claude,
      detected: await claude.detect(),
      reason: 'explicit --adapter=claude-code',
    };
  }

  if (requested === 'codex') {
    return {
      adapter: codex,
      detected: await codex.detect(),
      reason: 'explicit --adapter=codex',
    };
  }

  // auto: prefer detected, else Claude Code (primary MVP adapter)
  if (await claude.detect()) {
    return { adapter: claude, detected: true, reason: 'auto-detected claude-code' };
  }
  if (await codex.detect()) {
    return { adapter: codex, detected: true, reason: 'auto-detected codex' };
  }

  return {
    adapter: claude,
    detected: false,
    reason: 'auto fallback to claude-code',
  };
}

/**
 * Arm Watchdog with Claude Code or Codex adapter.
 * Use `--stdin` to ingest JSONL events. Use `--adapter=codex|claude-code|auto`.
 */
export async function cmdWatch(args: string[]): Promise<number> {
  printBanner();

  const stdinMode = hasFlag(args, '--stdin');
  const { store, rootDir } = ensureLocalStore();
  const { adapter, detected, reason } = await resolveAdapter(args);

  try {
    const now = new Date().toISOString();
    const session = await store.sessions.findLatestActive();
    let agentId: string;
    let sessionId: string;

    if (session && session.status === 'ACTIVE') {
      agentId = session.agentId;
      sessionId = session.id;
      const agent = await store.agents.findById(agentId);
      console.log('Resuming ACTIVE watchdog session.');
      console.log('');
      console.log(`  Agent:   ${agent?.name ?? agentId}`);
      console.log(`  Session: ${sessionId.slice(0, 12)}`);
    } else {
      agentId = createId('agent');
      sessionId = createId('sess');

      await store.agents.upsert({
        id: agentId,
        name: detected
          ? adapter.name === 'codex'
            ? 'Codex'
            : 'Claude Code'
          : 'Watch Target',
        runtime: adapter.name,
        model: null,
        createdAt: now,
        updatedAt: now,
      });

      await store.sessions.create({
        id: sessionId,
        agentId,
        taskId: null,
        taskDescription: null,
        workingDirectory: process.cwd(),
        environment: 'local',
        status: 'ACTIVE',
        securityState: 'NORMAL',
        startedAt: now,
        endedAt: null,
      });

      await store.securityState.set(sessionId, 'NORMAL', 'watch started');
      console.log('JEV WATCHDOG armed.');
      console.log('');
      console.log(`  Session: ${sessionId.slice(0, 12)}`);
    }

    console.log(`  Plane:   ${rootDir}`);
    console.log(
      `  Adapter: ${adapter.name}${detected ? ' (detected)' : ' (not detected — still usable)'}`,
    );
    console.log(`  Select:  ${reason}`);
    console.log(`  Semantic:${describeSemanticProvider()}`);
    console.log('');

    if (!stdinMode) {
      console.log('Observing for agent events...');
      console.log('');
      console.log('Feed JSONL events:');
      console.log(
        '  pnpm --filter @jev/cli start watch -- --stdin --adapter=claude-code < examples/claude-code-hooks.jsonl',
      );
    console.log(
      '  pnpm --filter @jev/cli start watch -- --stdin --adapter=codex < examples/codex-events.jsonl',
    );
    console.log('');
    console.log('Or install live hooks: jev bridge install');
    console.log('Or exercise trajectories: jev attack');
      console.log('');
      return 0;
    }

    const agentContext: AgentContext = {
      agentId,
      sessionId,
      workingDirectory: process.cwd(),
      environment: 'local',
      securityState:
        (await store.securityState.get(sessionId))?.state ?? 'NORMAL',
    };

    const watchdog = new Watchdog({ store });
    let ingested = 0;
    let blocked = 0;
    let ignored = 0;

    const agentSession = await adapter.start({
      sessionId,
      agentId,
      workingDirectory: process.cwd(),
      onEvent: async (event) => {
        const obs = await watchdog.observe(event, agentContext);
        ingested += 1;
        const target = event.action.target ?? event.action.name;
        const mark = obs.blocked ? '✕' : obs.primaryPolicy?.decision === 'WARN' ? '⚠' : '✓';
        const signal =
          obs.signals[0] !== undefined ? `  signal=${obs.signals[0].type}` : '';
        const rule = obs.primaryPolicy
          ? `  ${obs.primaryPolicy.decision}/${obs.primaryPolicy.ruleId}`
          : '';
        console.log(
          `${mark} ${event.type.padEnd(12)} ${String(target).slice(0, 40)}${rule}${signal}`,
        );
        if (obs.semantic) {
          const cat = obs.semantic.category ? `/${obs.semantic.category}` : '';
          console.log(
            `  ↳ advisory ${obs.semantic.risk}${cat}: ${obs.semantic.explanation.slice(0, 120)}`,
          );
        }
        if (obs.blocked) {
          blocked += 1;
        }
      },
    });

    console.log('Reading JSONL from stdin (Ctrl-D to stop)...');
    console.log('');

    const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

    for await (const line of rl) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      let raw: unknown;
      try {
        raw = JSON.parse(trimmed) as unknown;
      } catch {
        console.log(`⚠ skip invalid JSON: ${trimmed.slice(0, 60)}`);
        ignored += 1;
        continue;
      }

      const event = await agentSession.ingest(raw);
      if (!event) {
        ignored += 1;
      }
    }

    await agentSession.stop();

    const sessionRow = await store.sessions.findById(sessionId);
    if (sessionRow) {
      await store.sessions.update({
        ...sessionRow,
        securityState: agentContext.securityState,
        status:
          agentContext.securityState === 'QUARANTINED' ? 'QUARANTINED' : sessionRow.status,
      });
    }

    console.log('');
    console.log(`Done. ingested=${ingested} blocked=${blocked} ignored=${ignored}`);
    console.log(`State: ${agentContext.securityState}`);
    console.log('');
    return 0;
  } finally {
    store.close();
  }
}
