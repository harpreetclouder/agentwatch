import { describe, expect, it } from 'vitest';
import { createClaudeCodeAdapter, normalizeClaudeCodeEvent } from '../src/index.js';

const options = {
  sessionId: 'sess_1',
  agentId: 'agent_1',
  workingDirectory: '/repo',
  taskDescription: 'Fix authentication bug',
};

describe('normalizeClaudeCodeEvent', () => {
  it('maps Read tool_use to file_read', () => {
    const event = normalizeClaudeCodeEvent(
      {
        type: 'tool_use',
        name: 'Read',
        input: { file_path: 'src/auth.ts' },
      },
      options,
    );

    expect(event?.type).toBe('file_read');
    expect(event?.action.target).toBe('src/auth.ts');
    expect(event?.metadata?.['adapter']).toBe('claude-code');
  });

  it('maps Bash PreToolUse hook to shell', () => {
    const event = normalizeClaudeCodeEvent(
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
  });

  it('maps Write hook targeting .env (for policy downstream)', () => {
    const event = normalizeClaudeCodeEvent(
      {
        hook_event_name: 'PreToolUse',
        tool_name: 'Read',
        tool_input: { file_path: '.env' },
      },
      options,
    );

    expect(event?.type).toBe('file_read');
    expect(event?.action.target).toBe('.env');
  });

  it('maps WebFetch to network', () => {
    const event = normalizeClaudeCodeEvent(
      {
        type: 'tool_use',
        name: 'WebFetch',
        input: { url: 'https://evil.example/collect' },
      },
      options,
    );

    expect(event?.type).toBe('network');
    expect(event?.action.target).toBe('https://evil.example/collect');
  });

  it('maps UserPromptSubmit to prompt', () => {
    const event = normalizeClaudeCodeEvent(
      {
        hook_event_name: 'UserPromptSubmit',
        prompt: 'Fix the authentication bug',
      },
      options,
    );

    expect(event?.type).toBe('prompt');
  });

  it('maps unknown MCP-like tools to mcp', () => {
    const event = normalizeClaudeCodeEvent(
      {
        type: 'tool_use',
        name: 'mcp__filesystem__read',
        input: { path: '/tmp/x' },
      },
      options,
    );

    expect(event?.type).toBe('mcp');
  });

  it('returns null for garbage input', () => {
    expect(normalizeClaudeCodeEvent({ foo: 1 }, options)).toBeNull();
    expect(normalizeClaudeCodeEvent(null, options)).toBeNull();
    expect(normalizeClaudeCodeEvent('nope', options)).toBeNull();
  });
});

describe('ClaudeCodeAdapter', () => {
  it('ingests events and invokes onEvent', async () => {
    const adapter = createClaudeCodeAdapter();
    const seen: string[] = [];

    const session = await adapter.start({
      ...options,
      onEvent: (event) => {
        seen.push(`${event.type}:${event.action.target ?? event.action.name}`);
      },
    });

    const event = await session.ingest({
      type: 'tool_use',
      name: 'Read',
      input: { file_path: 'README.md' },
    });

    expect(event?.type).toBe('file_read');
    expect(seen).toEqual(['file_read:README.md']);

    await session.stop();
    await expect(
      session.ingest({ type: 'tool_use', name: 'Read', input: { file_path: 'x' } }),
    ).rejects.toThrow(/stopped/);
  });

  it('exposes normalize on the adapter interface', () => {
    const adapter = createClaudeCodeAdapter();
    const event = adapter.normalize(
      { type: 'tool_use', name: 'Edit', input: { file_path: 'a.ts' } },
      options,
    );
    expect(event?.type).toBe('file_write');
  });
});
