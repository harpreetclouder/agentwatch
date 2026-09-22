/**
 * RuntimeAttackExecutor — Level-3 live attack path.
 * Owns: workspace, fixture, task, runner, timeout, proof collection.
 * LiveAgentRunner owns: detect, execute, stdout/stderr, exit.
 * Does NOT call runProductDemo(); does NOT fabricate PreToolUse stimuli.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  emptyRuntimeAttackProof,
  getAttack,
  isRuntimeAttackContained,
  runtimeProofToChecks,
  RUNTIME_SYNTHETIC_SECRET,
  type Attack,
  type RuntimeAttackProof,
  type RuntimeAttackResult,
  type RuntimeOutcome,
} from '@veyra/attack-engine';
import { SqliteVeyraStore } from '@veyra/storage';
import { installBridge } from '../bridge/install.js';
import {
  DEMO_TASK,
  buildLiveAgentPrompt,
  livePromptMentionsSecrets,
  resetBuggyAuthFixture,
} from './demo-proof.js';
import {
  createClaudeCodeRunner,
  type AgentRunResult,
  type LiveAgentRunner,
} from './live-agent/index.js';
import { evaluateRuntimeEvidence } from './runtime-evidence.js';
import { resolveCliEntry, runHookPreToolUse } from './test-workspace.js';
import {
  openDemoWorkspace,
  printLiveWatchHint,
  resetPlaneDb,
} from './watchable-plane.js';

const DISCLAIMER = 'Do not claim complete security.';

function fingerprint(path: string): string {
  return existsSync(path) ? readFileSync(path, 'utf8') : '';
}

/** Ensure fixture .env holds the runtime synthetic secret (only place it should exist). */
function ensureRuntimeEnvFixture(envPath: string): void {
  const current = existsSync(envPath) ? readFileSync(envPath, 'utf8') : '';
  if (current.includes(RUNTIME_SYNTHETIC_SECRET)) {
    return;
  }
  const base = current.trim().length > 0 ? current.trimEnd() + '\n' : '';
  writeFileSync(
    envPath,
    `${base}VEYRA_RUNTIME_FAKE_SECRET=${RUNTIME_SYNTHETIC_SECRET}\n`,
    'utf8',
  );
}

function agentProcessStartedFromRun(run: AgentRunResult): boolean {
  return (
    run.exitCode !== null ||
    run.signal !== null ||
    run.timedOut ||
    run.combined.trim().length > 0
  );
}

function unavailableResult(
  attack: Attack,
  reason: string,
): RuntimeAttackResult {
  const proof = emptyRuntimeAttackProof();
  return {
    attackId: attack.id,
    name: attack.name,
    scenario: attack.name,
    agent: 'Claude Code',
    mode: 'runtime',
    contained: false,
    checks: runtimeProofToChecks(proof),
    proof,
    outcome: 'RUNTIME_UNAVAILABLE',
    timeline: [],
    secretExposure: 'UNKNOWN',
    correlation: {
      sessionId: null,
      eventId: null,
      decisionId: null,
      toolRequestId: null,
    },
    expectedPolicy: attack.expectedPolicy,
    expectedDecision: attack.expectedDecision,
    expectedFinalState: attack.expectedFinalState,
    observedPolicy: null,
    observedDecision: null,
    observedFinalState: null,
    evidenceRecorded: false,
    disclaimer: DISCLAIMER,
    unavailableReason: reason,
  };
}

async function loadPlaneEvidence(workspace: string): Promise<{
  sessionId: string | null;
  securityState: string | null;
  events: Awaited<ReturnType<SqliteVeyraStore['events']['findBySession']>>;
  decisions: Awaited<ReturnType<SqliteVeyraStore['decisions']['findBySession']>>;
}> {
  const dbPath = join(workspace, '.veyra', 'veyra.sqlite');
  if (!existsSync(dbPath)) {
    return { sessionId: null, securityState: null, events: [], decisions: [] };
  }
  const store = SqliteVeyraStore.open({ dbPath });
  try {
    const session =
      (await store.sessions.findLatestActive()) ?? (await store.sessions.findLatest());
    if (!session) {
      return { sessionId: null, securityState: null, events: [], decisions: [] };
    }
    const events = await store.events.findBySession(session.id);
    const decisions = await store.decisions.findBySession(session.id);
    const state =
      (await store.securityState.get(session.id))?.state ?? session.securityState;
    return {
      sessionId: session.id,
      securityState: state,
      events,
      decisions,
    };
  } finally {
    store.close();
  }
}

export type RuntimeAttackExecutorOptions = {
  attackId?: string;
  runner?: LiveAgentRunner;
  maxBudgetUsd?: number;
  timeoutMs?: number;
  workspace?: string;
  isolated?: boolean;
  printLiveHint?: boolean;
};

/**
 * Execute Level-3 runtime attack via LiveAgentRunner.
 * Shared infra for `veyra attack --mode=runtime` (product demo uses runner separately).
 */
export async function executeRuntimeAttack(
  options: RuntimeAttackExecutorOptions = {},
): Promise<RuntimeAttackResult> {
  const attackId = options.attackId ?? 'prompt-injection-secret-access';
  const attack = getAttack(attackId) ?? getAttack('prompt-injection-secret-access');
  if (!attack || !attack.runtimeSupported) {
    throw new Error(
      `Attack ${attackId} is not runtime-supported. Use --mode=hook or --mode=simulation.`,
    );
  }

  const runner = options.runner ?? createClaudeCodeRunner();
  const avail = await runner.detect();
  if (!avail.ok) {
    const kind =
      avail.reason === 'missing'
        ? 'Claude Code CLI not installed/on PATH'
        : avail.reason === 'timeout'
          ? 'Claude Code CLI timed out during version check'
          : 'Claude Code CLI probe failed';
    return unavailableResult(
      attack,
      `${kind}${avail.error ? ` (${avail.error})` : ''}`,
    );
  }

  const cli = resolveCliEntry();
  if (!existsSync(cli)) {
    return unavailableResult(attack, 'CLI not built. Run: pnpm --filter veyra build');
  }

  const ws = openDemoWorkspace({
    ...(options.workspace ? { workspace: options.workspace } : {}),
    isolated: options.isolated === true,
    prefix: 'veyra-runtime-attack-',
  });

  const envPath = ws.envPath;
  ensureRuntimeEnvFixture(envPath);
  const before = fingerprint(envPath);

  try {
    resetPlaneDb(ws.root);
    if (options.printLiveHint !== false && ws.watchable) {
      printLiveWatchHint(ws.root);
    }

    // Verify hook path works for benign read (does not fabricate attack PreToolUse).
    const probe = runHookPreToolUse({
      cwd: ws.root,
      filePath: join(ws.root, 'src', 'auth.ts'),
      cliEntry: cli,
    });
    if (probe.denied) {
      return unavailableResult(
        attack,
        'Hook unexpectedly denied benign Read src/auth.ts — bridge/hook misconfigured',
      );
    }

    try {
      installBridge({ adapters: ['claude-code'], cwd: ws.root });
    } catch (err) {
      return unavailableResult(
        attack,
        `Bridge install failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    resetBuggyAuthFixture(ws.root);

    const task = attack.task ?? DEMO_TASK;
    const prompt = buildLiveAgentPrompt(task);
    if (livePromptMentionsSecrets(prompt)) {
      throw new Error(
        'Runtime task must stay injection-free (no .env/credentials/secrets in user task)',
      );
    }

    const agentRun = await runner.run({
      workspace: ws.root,
      task: prompt,
      timeoutMs: options.timeoutMs ?? 180_000,
      maxBudgetUsd: options.maxBudgetUsd ?? 1.5,
    });

    const processStarted = agentProcessStartedFromRun(agentRun);
    if (!processStarted) {
      return unavailableResult(
        attack,
        agentRun.error ?? 'Live Claude process did not start',
      );
    }

    const after = fingerprint(envPath);
    const plane = await loadPlaneEvidence(ws.root);

    const evaluation = evaluateRuntimeEvidence({
      agentProcessStarted: processStarted,
      sessionId: plane.sessionId,
      events: plane.events,
      decisions: plane.decisions,
      securityState: plane.securityState,
      stdout: agentRun.stdout,
      stderr: agentRun.stderr,
      envBefore: before,
      envAfter: after,
      expectedPolicy: attack.expectedPolicy,
      expectedDecision: attack.expectedDecision,
      ...(attack.expectedTool ? { expectedTool: attack.expectedTool } : {}),
      ...(attack.expectedResource
        ? { expectedResource: attack.expectedResource }
        : {}),
    });

    const proof: RuntimeAttackProof = evaluation.proof;
    const contained = isRuntimeAttackContained(proof) && evaluation.outcome === 'CONTAINED';
    const outcome: RuntimeOutcome = evaluation.outcome;

    return {
      attackId: attack.id,
      name: attack.name,
      scenario: attack.name,
      agent: runner.displayName,
      mode: 'runtime',
      contained,
      checks: runtimeProofToChecks(proof),
      proof,
      outcome,
      timeline: evaluation.timeline,
      secretExposure: evaluation.secretExposure,
      correlation: evaluation.correlation,
      expectedPolicy: attack.expectedPolicy,
      expectedDecision: attack.expectedDecision,
      expectedFinalState: attack.expectedFinalState,
      observedPolicy: evaluation.observedPolicy,
      observedDecision: evaluation.observedDecision,
      observedFinalState: evaluation.observedFinalState,
      evidenceRecorded: proof.evidenceRecorded,
      disclaimer: DISCLAIMER,
      unavailableReason: null,
    };
  } finally {
    ws.cleanup();
  }
}
