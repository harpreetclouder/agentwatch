import { z } from 'zod';

/** Current AgentEvent schema version. Bump intentionally when breaking. */
export const AGENT_EVENT_SCHEMA_VERSION = '0.1.0' as const;

export const AgentEventTypeSchema = z.enum([
  'prompt',
  'response',
  'tool_call',
  'tool_result',
  'file_read',
  'file_write',
  'shell',
  'network',
  'mcp',
  'delegation',
  'policy_decision',
  'security_event',
]);

export type AgentEventType = z.infer<typeof AgentEventTypeSchema>;

export const AgentEventActionSchema = z.object({
  name: z.string().min(1),
  target: z.string().optional(),
  arguments: z.unknown().optional(),
});

export type AgentEventAction = z.infer<typeof AgentEventActionSchema>;

export const AgentEventContextSchema = z.object({
  taskId: z.string().optional(),
  taskDescription: z.string().optional(),
  cwd: z.string().optional(),
  parentEventId: z.string().optional(),
});

export type AgentEventContext = z.infer<typeof AgentEventContextSchema>;

export const AgentEventResultSchema = z.object({
  success: z.boolean().optional(),
  exitCode: z.number().int().optional(),
  error: z.string().optional(),
});

export type AgentEventResult = z.infer<typeof AgentEventResultSchema>;

/**
 * Universal AgentEvent — every agent action normalizes into this shape.
 * Never trust raw adapter input; always validate with Zod.
 */
export const AgentEventSchema = z.object({
  id: z.string().min(1),
  schemaVersion: z.string().min(1),
  sessionId: z.string().min(1),
  agentId: z.string().min(1),
  timestamp: z.string().datetime({ offset: true }),
  type: AgentEventTypeSchema,
  action: AgentEventActionSchema,
  context: AgentEventContextSchema.optional(),
  result: AgentEventResultSchema.optional(),
  metadata: z.record(z.unknown()).optional(),
});

export type AgentEvent = z.infer<typeof AgentEventSchema>;

export type ParseAgentEventSuccess = {
  success: true;
  data: AgentEvent;
};

export type ParseAgentEventFailure = {
  success: false;
  error: z.ZodError;
};

export type ParseAgentEventResult = ParseAgentEventSuccess | ParseAgentEventFailure;

/**
 * Strict validation of unknown input into AgentEvent.
 * Prefer this over casting adapter payloads.
 */
export function parseAgentEvent(input: unknown): ParseAgentEventResult {
  const result = AgentEventSchema.safeParse(input);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, error: result.error };
}

/**
 * Throws ZodError when input is invalid.
 */
export function parseAgentEventOrThrow(input: unknown): AgentEvent {
  return AgentEventSchema.parse(input);
}

export type CreateAgentEventInput = {
  id: string;
  sessionId: string;
  agentId: string;
  type: AgentEventType;
  action: AgentEventAction;
  timestamp?: string;
  schemaVersion?: string;
  context?: AgentEventContext;
  result?: AgentEventResult;
  metadata?: Record<string, unknown>;
};

/**
 * Build a validated AgentEvent with defaults for schemaVersion and timestamp.
 */
export function createAgentEvent(input: CreateAgentEventInput): AgentEvent {
  const event: AgentEvent = {
    id: input.id,
    schemaVersion: input.schemaVersion ?? AGENT_EVENT_SCHEMA_VERSION,
    sessionId: input.sessionId,
    agentId: input.agentId,
    timestamp: input.timestamp ?? new Date().toISOString(),
    type: input.type,
    action: input.action,
    ...(input.context !== undefined ? { context: input.context } : {}),
    ...(input.result !== undefined ? { result: input.result } : {}),
    ...(input.metadata !== undefined ? { metadata: input.metadata } : {}),
  };

  return parseAgentEventOrThrow(event);
}
