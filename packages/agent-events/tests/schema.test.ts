import { describe, expect, it } from 'vitest';
import {
  AGENT_EVENT_SCHEMA_VERSION,
  createAgentEvent,
  parseAgentEvent,
  parseAgentEventOrThrow,
} from '../src/index.js';

describe('AgentEvent schema', () => {
  it('parses a valid file_read event', () => {
    const result = parseAgentEvent({
      id: 'evt_1',
      schemaVersion: AGENT_EVENT_SCHEMA_VERSION,
      sessionId: 'sess_1',
      agentId: 'agent_1',
      timestamp: '2026-09-18T18:41:00.000Z',
      type: 'file_read',
      action: {
        name: 'read_file',
        target: 'src/auth.ts',
      },
      context: {
        taskId: 'task_auth',
        taskDescription: 'Fix authentication bug',
        cwd: '/repo',
      },
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.type).toBe('file_read');
      expect(result.data.action.target).toBe('src/auth.ts');
    }
  });

  it('rejects unknown event types', () => {
    const result = parseAgentEvent({
      id: 'evt_2',
      schemaVersion: AGENT_EVENT_SCHEMA_VERSION,
      sessionId: 'sess_1',
      agentId: 'agent_1',
      timestamp: '2026-09-18T18:41:00.000Z',
      type: 'teleport',
      action: { name: 'noop' },
    });

    expect(result.success).toBe(false);
  });

  it('rejects missing required fields', () => {
    const result = parseAgentEvent({
      id: 'evt_3',
      type: 'shell',
    });

    expect(result.success).toBe(false);
  });

  it('rejects non-datetime timestamps', () => {
    const result = parseAgentEvent({
      id: 'evt_4',
      schemaVersion: AGENT_EVENT_SCHEMA_VERSION,
      sessionId: 'sess_1',
      agentId: 'agent_1',
      timestamp: 'yesterday',
      type: 'shell',
      action: { name: 'run', target: 'ls' },
    });

    expect(result.success).toBe(false);
  });

  it('createAgentEvent applies defaults and validates', () => {
    const event = createAgentEvent({
      id: 'evt_5',
      sessionId: 'sess_1',
      agentId: 'agent_1',
      type: 'security_event',
      action: { name: 'policy_violation', target: '.env' },
      context: { taskDescription: 'Fix authentication bug' },
    });

    expect(event.schemaVersion).toBe(AGENT_EVENT_SCHEMA_VERSION);
    expect(event.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(event.type).toBe('security_event');
  });

  it('parseAgentEventOrThrow throws on malformed input', () => {
    expect(() => parseAgentEventOrThrow({ id: 'bad' })).toThrow();
  });

  it('accepts optional result and metadata', () => {
    const event = createAgentEvent({
      id: 'evt_6',
      sessionId: 'sess_1',
      agentId: 'agent_1',
      type: 'shell',
      action: { name: 'exec', target: 'npm test', arguments: { cwd: '.' } },
      result: { success: true, exitCode: 0 },
      metadata: { adapter: 'claude-code' },
    });

    expect(event.result?.exitCode).toBe(0);
    expect(event.metadata?.['adapter']).toBe('claude-code');
  });
});
