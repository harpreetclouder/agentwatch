import { describe, expect, it } from 'vitest';
import { createAgentEvent, type AgentContext } from '@jev/agent-events';
import { createId } from '@jev/shared';
import { SqliteJevStore } from '@jev/storage';
import {
  PolicyEngine,
  classifySecretPath,
  nextSecurityState,
  persistDecision,
  secretAccessPolicy,
  securityControlTamperingPolicy,
  tokenizeCommand,
} from '../src/index.js';

function baseContext(overrides: Partial<AgentContext> = {}): AgentContext {
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

describe('classifySecretPath', () => {
  it('detects env files and credential stores', () => {
    expect(classifySecretPath('/repo/.env')?.category).toBeTruthy();
    expect(classifySecretPath('/repo/.env.production')?.category).toBeTruthy();
    expect(classifySecretPath('/Users/x/.aws/credentials')?.category).toBeTruthy();
    expect(classifySecretPath('/Users/x/.ssh/id_rsa')?.category).toBeTruthy();
    expect(classifySecretPath('/repo/certs/server.pem')?.category).toBeTruthy();
  });

  it('allows ordinary source files', () => {
    expect(classifySecretPath('/repo/src/auth.ts')).toBeNull();
    expect(classifySecretPath('/repo/README.md')).toBeNull();
  });
});

describe('SECRET_ACCESS', () => {
  const context = baseContext();

  it('blocks .env reads', () => {
    const event = createAgentEvent({
      id: createId('evt'),
      sessionId: context.sessionId,
      agentId: context.agentId,
      type: 'file_read',
      action: { name: 'read_file', target: '.env' },
      context: { cwd: '/repo', taskDescription: 'Fix authentication bug' },
    });

    const decision = secretAccessPolicy.evaluate(event, context);
    expect(decision?.decision).toBe('BLOCK');
    expect(decision?.severity).toBe('HIGH');
    expect(decision?.ruleId).toBe('SECRET_ACCESS');
    expect(decision?.evidence.some((e) => e.includes('.env'))).toBe(true);
  });

  it('blocks shell cat of AWS credentials', () => {
    const event = createAgentEvent({
      id: createId('evt'),
      sessionId: context.sessionId,
      agentId: context.agentId,
      type: 'shell',
      action: {
        name: 'bash',
        target: 'cat ~/.aws/credentials',
        arguments: 'cat ~/.aws/credentials',
      },
    });

    const decision = secretAccessPolicy.evaluate(event, context);
    expect(decision?.decision).toBe('BLOCK');
  });

  it('allows reading normal source files', () => {
    const event = createAgentEvent({
      id: createId('evt'),
      sessionId: context.sessionId,
      agentId: context.agentId,
      type: 'file_read',
      action: { name: 'read_file', target: 'src/auth.ts' },
    });

    expect(secretAccessPolicy.evaluate(event, context)).toBeNull();
  });

  it('allows secret path when explicitly in allowedPaths', () => {
    const event = createAgentEvent({
      id: createId('evt'),
      sessionId: context.sessionId,
      agentId: context.agentId,
      type: 'file_read',
      action: { name: 'read_file', target: '.env' },
    });

    const decision = secretAccessPolicy.evaluate(
      event,
      baseContext({ allowedPaths: ['.env'] }),
    );
    expect(decision).toBeNull();
  });
});

describe('SECURITY_CONTROL_TAMPERING', () => {
  const context = baseContext();

  it('quarantines writes to .jev/policies', () => {
    const event = createAgentEvent({
      id: createId('evt'),
      sessionId: context.sessionId,
      agentId: context.agentId,
      type: 'file_write',
      action: { name: 'write_file', target: '.jev/policies/secret.json' },
      context: { cwd: '/repo' },
    });

    const decision = securityControlTamperingPolicy.evaluate(event, context);
    expect(decision?.decision).toBe('QUARANTINE');
    expect(decision?.severity).toBe('CRITICAL');
    expect(decision?.ruleId).toBe('SECURITY_CONTROL_TAMPERING');
  });

  it('quarantines attempts to clear violations by intent', () => {
    const event = createAgentEvent({
      id: createId('evt'),
      sessionId: context.sessionId,
      agentId: context.agentId,
      type: 'tool_call',
      action: { name: 'clear violations', target: 'security' },
    });

    const decision = securityControlTamperingPolicy.evaluate(event, context);
    expect(decision?.decision).toBe('QUARANTINE');
  });

  it('does not flag ordinary file writes', () => {
    const event = createAgentEvent({
      id: createId('evt'),
      sessionId: context.sessionId,
      agentId: context.agentId,
      type: 'file_write',
      action: { name: 'write_file', target: 'src/auth.ts' },
      context: { cwd: '/repo' },
    });

    expect(securityControlTamperingPolicy.evaluate(event, context)).toBeNull();
  });
});

describe('PolicyEngine', () => {
  it('returns primary CRITICAL over HIGH when both fire', () => {
    const engine = new PolicyEngine();
    const context = baseContext();
    const event = createAgentEvent({
      id: createId('evt'),
      sessionId: context.sessionId,
      agentId: context.agentId,
      type: 'file_write',
      action: { name: 'write_file', target: '.jev/config.json' },
      context: { cwd: '/repo' },
    });

    // .jev/config.json is security plane (CRITICAL). It is not classified as a secret file.
    const result = engine.evaluate(event, context);
    expect(result.primary?.ruleId).toBe('SECURITY_CONTROL_TAMPERING');
    expect(result.primary?.decision).toBe('QUARANTINE');
  });

  it('lists default policies', () => {
    const engine = new PolicyEngine();
    const ids = engine.listPolicies().map((p) => p.id);
    expect(ids).toContain('SECRET_ACCESS');
    expect(ids).toContain('SECURITY_CONTROL_TAMPERING');
  });
});

describe('enforcement + persist', () => {
  it('escalates NORMAL → RESTRICTED on HIGH block', () => {
    const decision = {
      decision: 'BLOCK' as const,
      severity: 'HIGH' as const,
      ruleId: 'SECRET_ACCESS',
      reason: 'blocked',
      evidence: [],
      eventId: 'e1',
    };
    expect(nextSecurityState('NORMAL', decision)).toBe('RESTRICTED');
  });

  it('quarantines immediately on CRITICAL', () => {
    const decision = {
      decision: 'QUARANTINE' as const,
      severity: 'CRITICAL' as const,
      ruleId: 'SECURITY_CONTROL_TAMPERING',
      reason: 'tamper',
      evidence: [],
      eventId: 'e1',
    };
    expect(nextSecurityState('WARNING', decision)).toBe('QUARANTINED');
  });

  it('persists decision, violation, and security state', async () => {
    const store = SqliteJevStore.openMemory();
    const now = new Date().toISOString();
    const agentId = createId('agent');
    const sessionId = createId('sess');
    const eventId = createId('evt');

    await store.agents.upsert({
      id: agentId,
      name: 'Claude Code',
      runtime: 'claude-code',
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

    const context = baseContext({ agentId, sessionId });
    const result = await persistDecision(
      store,
      {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'SECRET_ACCESS',
        reason: 'Credential access denied',
        evidence: ['resource=.env'],
        eventId,
      },
      context,
    );

    expect(result.securityState).toBe('RESTRICTED');
    expect(result.violation).not.toBeNull();
    expect(await store.decisions.findBySession(sessionId)).toHaveLength(1);
    expect(await store.violations.findBySession(sessionId)).toHaveLength(1);
    expect((await store.sessions.findById(sessionId))?.securityState).toBe('RESTRICTED');

    store.close();
  });
});

describe('tokenizeCommand', () => {
  it('splits simple commands', () => {
    expect(tokenizeCommand('cat ~/.aws/credentials')).toEqual([
      'cat',
      '~/.aws/credentials',
    ]);
  });
});
