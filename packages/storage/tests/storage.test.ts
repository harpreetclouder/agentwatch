import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createAgentEvent } from '@jev/agent-events';
import { createId } from '@jev/shared';
import {
  initSecurityPlane,
  resolveJevDbPath,
  SqliteJevStore,
} from '../src/index.js';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

function tempCwd(): string {
  const dir = mkdtempSync(join(tmpdir(), 'jev-storage-'));
  tempDirs.push(dir);
  return dir;
}

describe('SqliteJevStore', () => {
  it('migrates and persists agent, session, event, decision, violation', async () => {
    const store = SqliteJevStore.openMemory();

    const now = new Date().toISOString();
    const agentId = createId('agent');
    const sessionId = createId('sess');
    const eventId = createId('evt');
    const decisionId = createId('dec');
    const violationId = createId('viol');

    await store.agents.upsert({
      id: agentId,
      name: 'Claude Code',
      runtime: 'claude-code',
      model: 'claude-sonnet',
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

    await store.securityState.set(sessionId, 'NORMAL', 'session start');

    const event = createAgentEvent({
      id: eventId,
      sessionId,
      agentId,
      type: 'file_read',
      action: { name: 'read_file', target: '.env' },
      context: {
        taskId: 'task_auth',
        taskDescription: 'Fix authentication bug',
        cwd: '/repo',
      },
      timestamp: now,
    });

    await store.events.append(event);

    await store.decisions.append({
      id: decisionId,
      sessionId,
      eventId,
      decision: 'BLOCK',
      severity: 'HIGH',
      ruleId: 'SECRET_ACCESS',
      reason: 'Credential access outside task scope',
      evidence: ['resource=.env', 'task=fix-authentication'],
      createdAt: now,
    });

    await store.violations.append({
      id: violationId,
      sessionId,
      decisionId,
      eventId,
      ruleId: 'SECRET_ACCESS',
      severity: 'HIGH',
      summary: 'Blocked read of .env',
      createdAt: now,
    });

    expect(await store.agents.findById(agentId)).toMatchObject({ name: 'Claude Code' });
    expect(await store.sessions.findLatestActive()).toMatchObject({ id: sessionId });
    expect(await store.events.findBySession(sessionId)).toHaveLength(1);

    const loaded = await store.events.findById(eventId);
    expect(loaded?.action.target).toBe('.env');

    const sessionDecisions = await store.decisions.findBySession(sessionId);
    expect(sessionDecisions[0]?.ruleId).toBe('SECRET_ACCESS');
    expect(await store.violations.findBySession(sessionId)).toHaveLength(1);
    expect(await store.securityState.get(sessionId)).toMatchObject({ state: 'NORMAL' });

    const stats = await store.stats.getSessionStats(sessionId);
    expect(stats).toEqual({
      sessionId,
      events: 1,
      warnings: 0,
      blocks: 1,
      critical: 0,
    });

    expect(await store.sessions.list()).toHaveLength(1);
    expect(await store.decisions.listRecent()).toHaveLength(1);
    expect(await store.violations.listRecent()).toHaveLength(1);

    store.close();
  });

  it('rejects events for unknown sessions (FK)', async () => {
    const store = SqliteJevStore.openMemory();
    const event = createAgentEvent({
      id: createId('evt'),
      sessionId: 'missing',
      agentId: 'missing',
      type: 'shell',
      action: { name: 'exec', target: 'ls' },
    });

    await expect(store.events.append(event)).rejects.toThrow();
    store.close();
  });

  it('updates security state progressively', async () => {
    const store = SqliteJevStore.openMemory();
    const now = new Date().toISOString();
    const agentId = createId('agent');
    const sessionId = createId('sess');

    await store.agents.upsert({
      id: agentId,
      name: 'Codex',
      runtime: 'codex',
      model: null,
      createdAt: now,
      updatedAt: now,
    });
    await store.sessions.create({
      id: sessionId,
      agentId,
      taskId: null,
      taskDescription: null,
      workingDirectory: '/tmp',
      environment: 'development',
      status: 'ACTIVE',
      securityState: 'NORMAL',
      startedAt: now,
      endedAt: null,
    });

    await store.securityState.set(sessionId, 'WARNING', 'scope drift');
    await store.securityState.set(sessionId, 'QUARANTINED', 'control-plane tampering');

    expect(await store.securityState.get(sessionId)).toMatchObject({
      state: 'QUARANTINED',
      reason: 'control-plane tampering',
    });

    store.close();
  });
});

describe('security plane', () => {
  it('initializes .jev layout and resolves db path', () => {
    const cwd = tempCwd();
    const first = initSecurityPlane(cwd);
    expect(first.created).toBe(true);
    expect(resolveJevDbPath(cwd)).toBe(first.dbPath);

    const second = initSecurityPlane(cwd);
    expect(second.created).toBe(false);

    const store = SqliteJevStore.open({ dbPath: first.dbPath });
    store.close();
  });

  it('prefers workspace root over nested package cwd', () => {
    const root = tempCwd();
    writeFileSync(join(root, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
    const nested = join(root, 'apps', 'cli');
    mkdirSync(nested, { recursive: true });

    const plane = initSecurityPlane(nested);
    expect(plane.rootDir).toBe(join(root, '.jev'));
    expect(resolveJevDbPath(nested)).toBe(plane.dbPath);
  });
});
