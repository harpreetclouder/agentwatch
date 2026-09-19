import { createId } from '@veyra/shared';
import type { AgentContext } from '@veyra/agent-events';
import type { VeyraStore } from '@veyra/storage';
import { Watchdog } from '@veyra/watchdog';
import { createAttackLab } from './lab.js';
import { listAttacks } from './attacks/index.js';
import type { AttackContext, AttackRunSummary, AttackResult } from './types.js';
import { buildSecurityReport } from './report.js';
import type { SecurityReport } from './types.js';

function resetAgentContext(ctx: AgentContext): void {
  ctx.securityState = 'NORMAL';
  ctx.environment = 'local';
  delete ctx.allowedPaths;
  delete ctx.deniedPaths;
  delete ctx.allowedCommands;
  delete ctx.deniedCommands;
  delete ctx.allowedNetworks;
  ctx.task = {
    id: 'task_auth',
    description: 'Fix authentication bug',
  };
}

export type RunAttacksOptions = {
  store: VeyraStore;
  agentName?: string;
  attackIds?: string[];
};

export type RunAttacksResult = {
  summary: AttackRunSummary;
  report: SecurityReport;
  results: AttackResult[];
};

/**
 * Execute controlled attack simulations through Watchdog + policy engine.
 * Uses an isolated lab with fake secrets — no external exfiltration.
 */
export async function runAttacks(options: RunAttacksOptions): Promise<RunAttacksResult> {
  const startedAt = new Date().toISOString();
  const startedMs = Date.now();
  const agentName = options.agentName ?? 'Claude Code';
  const agentId = createId('agent');
  const sessionId = createId('sess');
  const now = startedAt;

  const lab = createAttackLab();

  try {
    await options.store.agents.upsert({
      id: agentId,
      name: agentName,
      runtime: 'simulated',
      model: 'attack-lab',
      createdAt: now,
      updatedAt: now,
    });

    await options.store.sessions.create({
      id: sessionId,
      agentId,
      taskId: 'task_auth',
      taskDescription: 'Fix authentication bug',
      workingDirectory: lab.root,
      environment: 'local',
      status: 'ACTIVE',
      securityState: 'NORMAL',
      startedAt: now,
      endedAt: null,
    });

    await options.store.securityState.set(sessionId, 'NORMAL', 'attack lab start');

    const agentContext: AgentContext = {
      agentId,
      sessionId,
      workingDirectory: lab.root,
      environment: 'local',
      securityState: 'NORMAL',
      task: {
        id: 'task_auth',
        description: 'Fix authentication bug',
      },
    };

    const selected = options.attackIds
      ? listAttacks().filter((a) => options.attackIds!.includes(a.id))
      : listAttacks();

    const results: AttackResult[] = [];
    for (const attack of selected) {
      resetAgentContext(agentContext);
      const isolatedWatchdog = new Watchdog({
        store: options.store,
        enableSemantic: false,
      });
      const isolatedContext: AttackContext = {
        agentId,
        agentName,
        sessionId,
        workingDirectory: lab.root,
        store: options.store,
        agentContext,
        labRoot: lab.root,
        watchdog: isolatedWatchdog,
      };
      const result = await attack.execute(isolatedContext);
      results.push(result);
    }

    const finishedAt = new Date().toISOString();
    const containedCount = results.filter((r) => r.contained).length;

    const session = await options.store.sessions.findById(sessionId);
    if (session) {
      await options.store.sessions.update({
        ...session,
        status: agentContext.securityState === 'QUARANTINED' ? 'QUARANTINED' : 'ENDED',
        endedAt: finishedAt,
        securityState: agentContext.securityState,
      });
    }

    const summary: AttackRunSummary = {
      sessionId,
      agentName,
      results,
      containedCount,
      totalCount: results.length,
      durationMs: Date.now() - startedMs,
      startedAt,
      finishedAt,
    };

    const report = await buildSecurityReport(options.store, summary);

    return { summary, report, results };
  } finally {
    lab.cleanup();
  }
}
