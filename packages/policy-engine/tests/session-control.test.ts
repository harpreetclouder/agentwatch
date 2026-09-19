import { describe, expect, it } from 'vitest';
import { createId } from '@veyra/shared';
import { SqliteVeyraStore } from '@veyra/storage';
import {
  isEnforcementFrozen,
  quarantineSession,
  resumeSession,
} from '../src/index.js';

describe('session control', () => {
  it('quarantines and resumes a session (operator only)', async () => {
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
      status: 'ACTIVE',
      securityState: 'NORMAL',
      startedAt: now,
      endedAt: null,
    });
    await store.securityState.set(sessionId, 'NORMAL', 'start');

    const q = await quarantineSession(store, {
      sessionId,
      reason: 'manual test quarantine',
    });
    expect(q.securityState).toBe('QUARANTINED');
    expect(q.previousState).toBe('NORMAL');
    expect(isEnforcementFrozen(q.securityState)).toBe(true);
    expect((await store.sessions.findById(sessionId))?.status).toBe('QUARANTINED');

    const r = await resumeSession(store, { sessionId, reason: 'operator clear' });
    expect(r.securityState).toBe('NORMAL');
    expect(r.previousState).toBe('QUARANTINED');
    expect(isEnforcementFrozen(r.securityState)).toBe(false);
    expect((await store.sessions.findById(sessionId))?.status).toBe('ACTIVE');

    store.close();
  });

  it('rejects resume on NORMAL sessions', async () => {
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
      status: 'ACTIVE',
      securityState: 'NORMAL',
      startedAt: now,
      endedAt: null,
    });
    await store.securityState.set(sessionId, 'NORMAL');

    await expect(resumeSession(store, { sessionId })).rejects.toThrow(/resume only applies/i);
    store.close();
  });
});
