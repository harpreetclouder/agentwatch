import type { AgentEvent, AgentEventType } from '@veyra/agent-events';
import { createAgentEvent } from '@veyra/agent-events';
import { createId } from '@veyra/shared';
import type { AdapterOptions } from '@veyra/adapter-core';
import {
  CodexCommandSchema,
  CodexFileChangeSchema,
  CodexHookEventSchema,
  CodexItemSchema,
  CodexMessageSchema,
  CodexNetworkSchema,
  CodexToolCallSchema,
} from './raw-schema.js';

function eventBase(
  options: AdapterOptions,
  type: AgentEventType,
  action: AgentEvent['action'],
  extra?: {
    timestamp?: string | undefined;
    metadata?: Record<string, unknown> | undefined;
    result?: AgentEvent['result'] | undefined;
  },
): AgentEvent {
  return createAgentEvent({
    id: createId('evt'),
    sessionId: options.sessionId,
    agentId: options.agentId,
    type,
    action,
    context: {
      cwd: options.workingDirectory,
      ...(options.taskDescription
        ? { taskDescription: options.taskDescription }
        : {}),
    },
    ...(extra?.timestamp != null ? { timestamp: extra.timestamp } : {}),
    metadata: { adapter: 'codex', ...(extra?.metadata ?? {}) },
    ...(extra?.result != null ? { result: extra.result } : {}),
  });
}

function tsExtra(timestamp: string | undefined): { timestamp: string } | undefined {
  return timestamp != null ? { timestamp } : undefined;
}

function mapToolName(
  tool: string,
  args: Record<string, unknown> | undefined,
  options: AdapterOptions,
  timestamp?: string,
): AgentEvent {
  const lower = tool.toLowerCase();
  const path =
    (typeof args?.['path'] === 'string' && args['path']) ||
    (typeof args?.['file_path'] === 'string' && args['file_path']) ||
    undefined;
  const command =
    (typeof args?.['command'] === 'string' && args['command']) ||
    (typeof args?.['cmd'] === 'string' && args['cmd']) ||
    undefined;
  const url = typeof args?.['url'] === 'string' ? args['url'] : undefined;
  const extra = timestamp !== undefined ? { timestamp } : undefined;

  if (lower === 'shell' || lower === 'bash' || lower === 'exec' || lower === 'local_shell') {
    return eventBase(
      options,
      'shell',
      { name: tool, ...(command ? { target: command } : {}), arguments: args },
      extra,
    );
  }

  if (lower.includes('read') || lower === 'cat' || lower === 'view') {
    return eventBase(
      options,
      'file_read',
      { name: tool, ...(path ? { target: path } : {}), arguments: args },
      extra,
    );
  }

  if (
    lower.includes('write') ||
    lower.includes('edit') ||
    lower === 'apply_patch' ||
    lower.includes('patch')
  ) {
    return eventBase(
      options,
      'file_write',
      { name: tool, ...(path ? { target: path } : {}), arguments: args },
      extra,
    );
  }

  if (lower.includes('fetch') || lower.includes('http') || lower === 'web_search') {
    return eventBase(
      options,
      'network',
      { name: tool, ...(url ? { target: url } : {}), arguments: args },
      extra,
    );
  }

  if (lower.startsWith('mcp') || lower.includes('__')) {
    return eventBase(
      options,
      'mcp',
      {
        name: tool,
        ...(path ?? url ?? command ? { target: path ?? url ?? command } : {}),
        arguments: args,
      },
      extra,
    );
  }

  return eventBase(
    options,
    'tool_call',
    {
      name: tool,
      ...(path ?? command ?? url ? { target: path ?? command ?? url } : {}),
      arguments: args,
    },
    extra,
  );
}

/**
 * Normalize Codex / OpenAI Codex CLI style payloads into AgentEvents.
 */
export function normalizeCodexEvent(
  rawEvent: unknown,
  options: AdapterOptions,
): AgentEvent | null {
  const hook = CodexHookEventSchema.safeParse(rawEvent);
  if (hook.success) {
    const data = hook.data;
    if (data.hook_event_name === 'UserPromptSubmit') {
      const text = data.prompt ?? data.message;
      if (!text) {
        return null;
      }
      return eventBase(options, 'prompt', { name: 'UserPromptSubmit', arguments: { text } }, {
        ...(data.timestamp !== undefined ? { timestamp: data.timestamp } : {}),
        metadata: { hook: data.hook_event_name },
      });
    }

    if (
      (data.hook_event_name === 'PreToolUse' || data.hook_event_name === 'PostToolUse') &&
      data.tool_name
    ) {
      const mapped = mapToolName(
        data.tool_name,
        data.tool_input,
        {
          ...options,
          workingDirectory: data.cwd ?? options.workingDirectory,
        },
        data.timestamp,
      );
      return {
        ...mapped,
        metadata: {
          ...(mapped.metadata ?? {}),
          hook: data.hook_event_name,
          ...(data.session_id !== undefined ? { vendorSessionId: data.session_id } : {}),
        },
      };
    }

    return null;
  }

  const toolCall = CodexToolCallSchema.safeParse(rawEvent);
  if (toolCall.success) {
    return mapToolName(
      toolCall.data.tool,
      toolCall.data.arguments,
      options,
      toolCall.data.timestamp,
    );
  }

  const command = CodexCommandSchema.safeParse(rawEvent);
  if (command.success) {
    return eventBase(
      options,
      'shell',
      { name: 'shell', target: command.data.command },
      tsExtra(command.data.timestamp),
    );
  }

  const file = CodexFileChangeSchema.safeParse(rawEvent);
  if (file.success) {
    const kind = file.data.kind ?? (file.data.type === 'file_read' ? 'read' : 'update');
    const type = kind === 'read' ? 'file_read' : 'file_write';
    return eventBase(
      options,
      type,
      { name: file.data.type, target: file.data.path },
      tsExtra(file.data.timestamp),
    );
  }

  const network = CodexNetworkSchema.safeParse(rawEvent);
  if (network.success) {
    return eventBase(
      options,
      'network',
      {
        name: network.data.method ?? 'http',
        target: network.data.url,
      },
      tsExtra(network.data.timestamp),
    );
  }

  const item = CodexItemSchema.safeParse(rawEvent);
  if (item.success) {
    const inner = item.data.item;
    const ts = tsExtra(item.data.timestamp);
    if (inner.command) {
      return eventBase(
        options,
        'shell',
        { name: inner.type, target: inner.command },
        ts,
      );
    }
    if (inner.path) {
      const isRead = inner.type.toLowerCase().includes('read');
      return eventBase(
        options,
        isRead ? 'file_read' : 'file_write',
        { name: inner.type, target: inner.path },
        ts,
      );
    }
    if (inner.tool) {
      return mapToolName(inner.tool, inner.arguments, options, item.data.timestamp);
    }
  }

  const message = CodexMessageSchema.safeParse(rawEvent);
  if (message.success) {
    const text = message.data.text ?? message.data.content;
    if (!text) {
      return null;
    }
    const type =
      message.data.type === 'user' || message.data.type === 'prompt'
        ? 'prompt'
        : 'response';
    return eventBase(
      options,
      type,
      { name: message.data.type, arguments: { text } },
      tsExtra(message.data.timestamp),
    );
  }

  return null;
}
