import type { AgentEvent, AgentEventType } from '@veyra/agent-events';
import { createAgentEvent } from '@veyra/agent-events';
import { createId } from '@veyra/shared';
import type { AdapterOptions } from '@veyra/adapter-core';
import {
  ClaudeHookEventSchema,
  ClaudeMessageSchema,
  ClaudeToolResultSchema,
  ClaudeToolUseSchema,
  type ClaudeToolInputSchema,
} from './raw-schema.js';
import type { z } from 'zod';

type ToolInput = z.infer<typeof ClaudeToolInputSchema>;

type ToolMapping = {
  type: AgentEventType;
  actionName: string;
  target?: (input: ToolInput) => string | undefined;
};

const TOOL_MAP: Record<string, ToolMapping> = {
  Read: {
    type: 'file_read',
    actionName: 'read_file',
    target: (i) => i.file_path ?? i.path,
  },
  Write: {
    type: 'file_write',
    actionName: 'write_file',
    target: (i) => i.file_path ?? i.path,
  },
  Edit: {
    type: 'file_write',
    actionName: 'edit_file',
    target: (i) => i.file_path ?? i.path,
  },
  MultiEdit: {
    type: 'file_write',
    actionName: 'multi_edit',
    target: (i) => i.file_path ?? i.path,
  },
  Bash: {
    type: 'shell',
    actionName: 'bash',
    target: (i) => i.command,
  },
  Shell: {
    type: 'shell',
    actionName: 'shell',
    target: (i) => i.command,
  },
  WebFetch: {
    type: 'network',
    actionName: 'web_fetch',
    target: (i) => i.url,
  },
  WebSearch: {
    type: 'network',
    actionName: 'web_search',
    target: (i) => i.url ?? (typeof i.pattern === 'string' ? i.pattern : undefined),
  },
  Glob: {
    type: 'file_read',
    actionName: 'glob',
    target: (i) => i.pattern ?? i.path,
  },
  Grep: {
    type: 'file_read',
    actionName: 'grep',
    target: (i) => i.path ?? i.pattern,
  },
};

function mapTool(
  toolName: string,
  input: ToolInput | undefined,
  options: AdapterOptions,
  timestamp?: string,
  metadata?: Record<string, unknown>,
): AgentEvent {
  const mapping = TOOL_MAP[toolName];
  const safeInput = input ?? {};

  if (mapping) {
    const target = mapping.target?.(safeInput);
    return createAgentEvent({
      id: createId('evt'),
      sessionId: options.sessionId,
      agentId: options.agentId,
      type: mapping.type,
      action: {
        name: mapping.actionName,
        ...(target !== undefined ? { target } : {}),
        arguments: safeInput,
      },
      context: {
        cwd: options.workingDirectory,
        ...(options.taskDescription
          ? { taskDescription: options.taskDescription }
          : {}),
      },
      ...(timestamp ? { timestamp } : {}),
      metadata: {
        adapter: 'claude-code',
        tool_name: toolName,
        ...metadata,
      },
    });
  }

  // MCP or unknown tools
  const isMcp = toolName.includes('__') || toolName.toLowerCase().startsWith('mcp');
  return createAgentEvent({
    id: createId('evt'),
    sessionId: options.sessionId,
    agentId: options.agentId,
    type: isMcp ? 'mcp' : 'tool_call',
    action: {
      name: toolName,
      target: safeInput.file_path ?? safeInput.path ?? safeInput.command ?? safeInput.url,
      arguments: safeInput,
    },
    context: {
      cwd: options.workingDirectory,
      ...(options.taskDescription ? { taskDescription: options.taskDescription } : {}),
    },
    ...(timestamp ? { timestamp } : {}),
    metadata: {
      adapter: 'claude-code',
      tool_name: toolName,
      ...metadata,
    },
  });
}

/**
 * Translate Claude Code native payloads into universal AgentEvents.
 * Returns null for non-actionable / unrecognized shapes (fail soft on noise).
 */
export function normalizeClaudeCodeEvent(
  rawEvent: unknown,
  options: AdapterOptions,
): AgentEvent | null {
  const hook = ClaudeHookEventSchema.safeParse(rawEvent);
  if (hook.success) {
    const data = hook.data;

    if (data.hook_event_name === 'UserPromptSubmit') {
      const text = data.prompt ?? data.message ?? '';
      if (!text) {
        return null;
      }
      return createAgentEvent({
        id: createId('evt'),
        sessionId: options.sessionId,
        agentId: options.agentId,
        type: 'prompt',
        action: { name: 'user_prompt', arguments: { text } },
        context: {
          cwd: data.cwd ?? options.workingDirectory,
          ...(options.taskDescription
            ? { taskDescription: options.taskDescription }
            : {}),
        },
        metadata: { adapter: 'claude-code', hook: data.hook_event_name },
      });
    }

    if (
      (data.hook_event_name === 'PreToolUse' || data.hook_event_name === 'PostToolUse') &&
      data.tool_name
    ) {
      const event = mapTool(data.tool_name, data.tool_input, options, undefined, {
        hook: data.hook_event_name,
      });

      if (data.hook_event_name === 'PostToolUse' && data.tool_response !== undefined) {
        return createAgentEvent({
          id: event.id,
          sessionId: event.sessionId,
          agentId: event.agentId,
          type: event.type,
          action: event.action,
          ...(event.context !== undefined ? { context: event.context } : {}),
          result: {
            success: true,
          },
          ...(event.metadata !== undefined ? { metadata: event.metadata } : {}),
          timestamp: event.timestamp,
        });
      }

      return event;
    }

    return null;
  }

  const toolUse = ClaudeToolUseSchema.safeParse(rawEvent);
  if (toolUse.success) {
    return mapTool(
      toolUse.data.name,
      toolUse.data.input,
      options,
      toolUse.data.timestamp,
    );
  }

  const toolResult = ClaudeToolResultSchema.safeParse(rawEvent);
  if (toolResult.success) {
    return createAgentEvent({
      id: createId('evt'),
      sessionId: options.sessionId,
      agentId: options.agentId,
      type: 'tool_result',
      action: {
        name: toolResult.data.name ?? 'tool_result',
        arguments: { tool_use_id: toolResult.data.tool_use_id },
      },
      result: {
        success: toolResult.data.is_error !== true,
        ...(toolResult.data.is_error ? { error: 'tool_error' } : {}),
      },
      context: { cwd: options.workingDirectory },
      ...(toolResult.data.timestamp ? { timestamp: toolResult.data.timestamp } : {}),
      metadata: { adapter: 'claude-code' },
    });
  }

  const message = ClaudeMessageSchema.safeParse(rawEvent);
  if (message.success) {
    const text =
      message.data.text ??
      (typeof message.data.content === 'string' ? message.data.content : undefined);
    if (!text) {
      return null;
    }
    const type =
      message.data.type === 'user' || message.data.type === 'prompt'
        ? 'prompt'
        : 'response';
    return createAgentEvent({
      id: createId('evt'),
      sessionId: options.sessionId,
      agentId: options.agentId,
      type,
      action: { name: message.data.type, arguments: { text } },
      context: { cwd: options.workingDirectory },
      ...(message.data.timestamp ? { timestamp: message.data.timestamp } : {}),
      metadata: { adapter: 'claude-code' },
    });
  }

  return null;
}
