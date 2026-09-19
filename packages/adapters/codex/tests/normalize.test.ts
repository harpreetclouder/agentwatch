import { describe, expect, it } from 'vitest';
import { createCodexAdapter, normalizeCodexEvent } from '../src/index.js';

const options = {
  sessionId: 'sess_1',
  agentId: 'agent_1',
  workingDirectory: '/repo',
};

describe('normalizeCodexEvent', () => {
  it('maps shell tool_call', () => {
    const event = normalizeCodexEvent(
      { type: 'tool_call', tool: 'shell', arguments: { command: 'npm test' } },
      options,
    );
    expect(event?.type).toBe('shell');
    expect(event?.action.target).toBe('npm test');
  });

  it('maps file_change read/write', () => {
    const read = normalizeCodexEvent(
      { type: 'file_change', path: 'src/a.ts', kind: 'read' },
      options,
    );
    expect(read?.type).toBe('file_read');

    const write = normalizeCodexEvent(
      { type: 'apply_patch', path: '.env', kind: 'update' },
      options,
    );
    expect(write?.type).toBe('file_write');
    expect(write?.action.target).toBe('.env');
  });

  it('maps network events', () => {
    const event = normalizeCodexEvent(
      { type: 'network', url: 'https://evil.example/collect' },
      options,
    );
    expect(event?.type).toBe('network');
  });

  it('maps PreToolUse hook stdin to tool event', () => {
    const event = normalizeCodexEvent(
      {
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'cat .env' },
        cwd: '/repo',
      },
      options,
    );
    expect(event?.type).toBe('shell');
    expect(event?.action.target).toBe('cat .env');
    expect(event?.metadata?.['hook']).toBe('PreToolUse');
  });

  it('maps UserPromptSubmit hook', () => {
    const event = normalizeCodexEvent(
      { hook_event_name: 'UserPromptSubmit', prompt: 'fix auth' },
      options,
    );
    expect(event?.type).toBe('prompt');
  });

  it('returns null for garbage', () => {
    expect(normalizeCodexEvent({ nope: true }, options)).toBeNull();
  });
});

describe('CodexAdapter', () => {
  it('ingests via session', async () => {
    const adapter = createCodexAdapter();
    const session = await adapter.start(options);
    const event = await session.ingest({
      type: 'tool_call',
      tool: 'shell',
      arguments: { command: 'ls' },
    });
    expect(event?.type).toBe('shell');
    await session.stop();
  });
});
