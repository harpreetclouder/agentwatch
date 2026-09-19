import { z } from 'zod';

/**
 * Claude Code hook / transcript shapes we accept.
 * Never trust raw input — validate, then normalize.
 */

export const ClaudeToolInputSchema = z
  .object({
    file_path: z.string().optional(),
    path: z.string().optional(),
    command: z.string().optional(),
    content: z.string().optional(),
    url: z.string().optional(),
    pattern: z.string().optional(),
    old_string: z.string().optional(),
    new_string: z.string().optional(),
  })
  .passthrough();

/** PreToolUse / PostToolUse hook payload (Claude Code hooks). */
export const ClaudeHookEventSchema = z.object({
  hook_event_name: z.enum([
    'PreToolUse',
    'PostToolUse',
    'Notification',
    'Stop',
    'SubagentStop',
    'PreCompact',
    'UserPromptSubmit',
  ]),
  tool_name: z.string().optional(),
  tool_input: ClaudeToolInputSchema.optional(),
  tool_response: z.unknown().optional(),
  session_id: z.string().optional(),
  cwd: z.string().optional(),
  prompt: z.string().optional(),
  message: z.string().optional(),
});

/** Simplified tool_use record (transcript / bridge). */
export const ClaudeToolUseSchema = z.object({
  type: z.literal('tool_use'),
  id: z.string().optional(),
  name: z.string(),
  input: ClaudeToolInputSchema.optional(),
  timestamp: z.string().optional(),
});

export const ClaudeToolResultSchema = z.object({
  type: z.literal('tool_result'),
  tool_use_id: z.string().optional(),
  name: z.string().optional(),
  content: z.unknown().optional(),
  is_error: z.boolean().optional(),
  timestamp: z.string().optional(),
});

export const ClaudeMessageSchema = z.object({
  type: z.enum(['user', 'assistant', 'system', 'prompt', 'response']),
  content: z.union([z.string(), z.array(z.unknown())]).optional(),
  text: z.string().optional(),
  timestamp: z.string().optional(),
});

export const ClaudeRawEventSchema = z.union([
  ClaudeHookEventSchema,
  ClaudeToolUseSchema,
  ClaudeToolResultSchema,
  ClaudeMessageSchema,
]);

export type ClaudeHookEvent = z.infer<typeof ClaudeHookEventSchema>;
export type ClaudeToolUse = z.infer<typeof ClaudeToolUseSchema>;
export type ClaudeToolResult = z.infer<typeof ClaudeToolResultSchema>;
export type ClaudeMessage = z.infer<typeof ClaudeMessageSchema>;
