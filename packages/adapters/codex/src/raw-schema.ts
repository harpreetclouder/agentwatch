import { z } from 'zod';

export const CodexToolCallSchema = z.object({
  type: z.literal('tool_call'),
  tool: z.string(),
  arguments: z.record(z.unknown()).optional(),
  id: z.string().optional(),
  timestamp: z.string().optional(),
});

export const CodexCommandSchema = z.object({
  type: z.enum(['command_execution', 'shell', 'exec']),
  command: z.string(),
  cwd: z.string().optional(),
  timestamp: z.string().optional(),
});

export const CodexFileChangeSchema = z.object({
  type: z.enum(['file_change', 'file_read', 'file_write', 'apply_patch']),
  path: z.string(),
  kind: z.enum(['read', 'create', 'update', 'delete']).optional(),
  timestamp: z.string().optional(),
});

export const CodexItemSchema = z.object({
  type: z.string(),
  item: z
    .object({
      type: z.string(),
      command: z.string().optional(),
      path: z.string().optional(),
      tool: z.string().optional(),
      arguments: z.record(z.unknown()).optional(),
    })
    .passthrough(),
  timestamp: z.string().optional(),
});

export const CodexMessageSchema = z.object({
  type: z.enum(['user', 'assistant', 'message', 'prompt', 'response']),
  text: z.string().optional(),
  content: z.string().optional(),
  timestamp: z.string().optional(),
});

export const CodexNetworkSchema = z.object({
  type: z.literal('network'),
  url: z.string(),
  method: z.string().optional(),
  timestamp: z.string().optional(),
});

/** Live Codex / Claude-compatible hook stdin payload. */
export const CodexHookEventSchema = z.object({
  hook_event_name: z.string(),
  tool_name: z.string().optional(),
  tool_input: z.record(z.unknown()).optional(),
  session_id: z.string().optional(),
  cwd: z.string().optional(),
  prompt: z.string().optional(),
  message: z.string().optional(),
  timestamp: z.string().optional(),
});

export type CodexHookEvent = z.infer<typeof CodexHookEventSchema>;
