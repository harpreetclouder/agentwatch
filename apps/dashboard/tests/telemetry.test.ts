import { describe, expect, it } from 'vitest';
import type { AgentEvent } from '@veyra/agent-events';
import type { SecurityDecisionRecord, SessionRecord } from '@veyra/storage';
import {
  listTelemetryAfter,
  sanitizeActionTarget,
  toTelemetryEvent,
  type TelemetryEvent,
} from '../lib/telemetry';
import {
  buildActivityRows,
  buildIncident,
  buildIncidentForSelection,
  buildStatePath,
  displayAgentName,
  displayTask,
  latestBlockEventId,
} from '../lib/console-view';
import {
  filterRecentEvents,
  isSessionFresh,
  LIVE_IDLE_GAP_MS,
  LIVE_RECENT_WINDOW_MS,
} from '../lib/live-session';

function evt(
  partial: Partial<TelemetryEvent> & Pick<TelemetryEvent, 'eventId' | 'action'>,
): TelemetryEvent {
  return {
    sessionId: 'sess_1',
    agentId: 'agent_1',
    timestamp: '2026-09-19T12:00:00.000Z',
    type: 'file_read',
    decision: null,
    decisionId: null,
    policy: null,
    severity: null,
    reason: null,
    securityState: 'NORMAL',
    ...partial,
  };
}

function session(partial: Partial<SessionRecord> = {}): SessionRecord {
  return {
    id: 'sess_1',
    agentId: 'agent_1',
    taskId: null,
    taskDescription: 'demo',
    workingDirectory: '/tmp/demo',
    environment: 'local',
    status: 'ACTIVE',
    securityState: 'NORMAL',
    startedAt: '2026-09-19T12:00:00.000Z',
    endedAt: null,
    ...partial,
  };
}

describe('telemetry sanitize', () => {
  it('keeps path basename only for .env targets', () => {
    expect(sanitizeActionTarget('/Users/me/proj/.env')).toBe('.env');
    expect(sanitizeActionTarget('src/auth.ts')).toBe('src/auth.ts');
  });

  it('never includes arguments, results, or secret-looking payloads in DTO', () => {
    const event = {
      id: 'evt_1',
      schemaVersion: '0.1.0',
      sessionId: 'sess_1',
      agentId: 'agent_1',
      timestamp: '2026-09-19T12:00:00.000Z',
      type: 'tool_call',
      action: {
        name: 'Read',
        target: '/tmp/demo/.env',
        arguments: { path: '/tmp/demo/.env' },
      },
      result: { success: false, error: 'DEMO_API_KEY=veyra_fake_key' },
      context: { cwd: '/tmp', taskDescription: 'password=supersecret' },
    } as AgentEvent;

    const decision: SecurityDecisionRecord = {
      id: 'dec_1',
      sessionId: 'sess_1',
      eventId: 'evt_1',
      decision: 'BLOCK',
      severity: 'HIGH',
      ruleId: 'SECRET_ACCESS',
      reason: 'Blocked .env',
      evidence: ['DEMO_API_KEY=veyra_fake_key'],
      createdAt: '2026-09-19T12:00:01.000Z',
    };

    const dto = toTelemetryEvent({
      event,
      decision,
      securityState: 'RESTRICTED',
    });

    const serialized = JSON.stringify(dto);
    expect(serialized).not.toMatch(/veyra_fake_key/);
    expect(serialized).not.toMatch(/supersecret/);
    expect(serialized).not.toMatch(/arguments/);
    expect(serialized).not.toMatch(/evidence/);
    expect(dto.decisionId).toBe('dec_1');
    expect(dto.policy).toBe('SECRET_ACCESS');
    expect(dto.action.target).toBe('.env');
  });

  it('replays from start when after cursor is unknown (session wipe)', () => {
    const event = {
      id: 'evt_new',
      schemaVersion: '0.1.0',
      sessionId: 'sess_2',
      agentId: 'agent_1',
      timestamp: '2026-09-19T12:00:00.000Z',
      type: 'file_read',
      action: { name: 'read_file', target: 'src/auth.ts' },
    } as AgentEvent;

    const out = listTelemetryAfter([event], [], 'NORMAL', 'evt_from_old_session');
    expect(out).toHaveLength(1);
    expect(out[0]?.eventId).toBe('evt_new');
  });
});

describe('console view derivation', () => {
  it('builds activity with injection annotation and blocked .env', () => {
    const events = [
      evt({
        eventId: 'e1',
        action: { name: 'read_file', target: 'src/auth.ts' },
        securityState: 'NORMAL',
      }),
      evt({
        eventId: 'e2',
        action: { name: 'read_file', target: 'README.md' },
        securityState: 'NORMAL',
      }),
      evt({
        eventId: 'e3',
        action: { name: 'read_file', target: '.env' },
        decision: 'BLOCK',
        decisionId: 'dec_env',
        policy: 'SECRET_ACCESS',
        severity: 'HIGH',
        reason: 'Agent attempted to access a secret-bearing resource outside its authority.',
        securityState: 'RESTRICTED',
      }),
    ];

    const rows = buildActivityRows(events);
    expect(rows.some((r) => r.label === 'Read auth' && r.mark === 'ok')).toBe(true);
    expect(rows.some((r) => r.label === 'Read README' && r.mark === 'ok')).toBe(true);
    expect(rows.some((r) => r.label === 'injection' && r.mark === 'warn')).toBe(true);
    expect(rows.some((r) => r.mark === 'block' && r.label === '.env BLOCKED')).toBe(true);
    expect(rows.some((r) => r.mark === 'lock' && r.label === 'SECRET_ACCESS')).toBe(true);

    const incident = buildIncident(events);
    expect(incident?.policy).toBe('SECRET_ACCESS');
    expect(incident?.severity).toBe('HIGH');
    expect(incident?.trajectory).toEqual(['PROMPT_INJECTION', 'SECRET_ACCESS']);
    expect(incident?.enforcement).toContain('PreToolUse DENY');
    expect(JSON.stringify(incident)).not.toMatch(/veyra_fake/);

    expect(buildStatePath(events, 'RESTRICTED')).toEqual(['NORMAL', 'RESTRICTED']);
    expect(displayAgentName('claude-bridge', 'claude-code')).toBe('Claude Code');
    expect(displayTask('live-bridge')).toBe('Claude Code PreToolUse (bridge)');
    expect(displayTask('Fix the authentication bug in src/auth.ts.')).toBe(
      'Fix the authentication bug in src/auth.ts.',
    );
  });

  it('focuses selected block for split-board detail', () => {
    const events = [
      evt({
        eventId: 'e1',
        action: { name: 'read_file', target: 'README.md' },
      }),
      evt({
        eventId: 'e2',
        action: { name: 'read_file', target: '.env' },
        decision: 'BLOCK',
        decisionId: 'dec_a',
        policy: 'SECRET_ACCESS',
        severity: 'HIGH',
        securityState: 'RESTRICTED',
      }),
      evt({
        eventId: 'e3',
        action: { name: 'edit_file', target: 'src/auth.ts' },
        decision: 'BLOCK',
        decisionId: 'dec_b',
        policy: 'SECRET_ACCESS',
        severity: 'HIGH',
        securityState: 'RESTRICTED',
      }),
    ];
    const focused = buildIncidentForSelection(events, 'e2');
    expect(focused?.eventId).toBe('e2');
    expect(focused?.decisionId).toBe('dec_a');
    expect(latestBlockEventId(events)).toBe('e3');
    expect(buildIncidentForSelection(events, 'ann-policy-e2')?.eventId).toBe('e2');
  });
});

describe('live tail freshness', () => {
  it('treats stale ACTIVE/QUARANTINED sessions as not fresh (idle)', () => {
    const now = Date.parse('2026-09-20T12:00:00.000Z');
    const staleTs = new Date(now - LIVE_IDLE_GAP_MS - 1_000).toISOString();
    expect(
      isSessionFresh(
        session({
          status: 'QUARANTINED',
          securityState: 'QUARANTINED',
          startedAt: staleTs,
        }),
        staleTs,
        now,
      ),
    ).toBe(false);
  });

  it('treats recent events as fresh live', () => {
    const now = Date.parse('2026-09-20T12:00:00.000Z');
    const recent = new Date(now - 5_000).toISOString();
    expect(isSessionFresh(session({ startedAt: recent }), recent, now)).toBe(true);
  });

  it('never treats ENDED sessions as fresh', () => {
    const now = Date.parse('2026-09-20T12:00:00.000Z');
    const recent = new Date(now - 1_000).toISOString();
    expect(
      isSessionFresh(
        session({ status: 'ENDED', endedAt: recent, startedAt: recent }),
        recent,
        now,
      ),
    ).toBe(false);
  });

  it('seeds only the recent window for live tail', () => {
    const now = Date.parse('2026-09-20T12:00:00.000Z');
    const old = new Date(now - LIVE_RECENT_WINDOW_MS - 60_000).toISOString();
    const mid = new Date(now - 60_000).toISOString();
    const events = [
      evt({ eventId: 'old', timestamp: old, action: { name: 'read_file', target: 'a.ts' } }),
      evt({ eventId: 'mid', timestamp: mid, action: { name: 'read_file', target: 'b.ts' } }),
    ];
    const seeded = filterRecentEvents(events, now);
    expect(seeded.map((e) => e.eventId)).toEqual(['mid']);
  });
});
