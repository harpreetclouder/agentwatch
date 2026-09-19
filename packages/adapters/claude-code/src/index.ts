export type { AdapterOptions, AgentAdapter, AgentSession } from '@jev/adapter-core';

export {
  ClaudeCodeAdapter,
  ClaudeCodeSession,
  createClaudeCodeAdapter,
} from './adapter.js';

export { normalizeClaudeCodeEvent } from './normalize.js';
export { detectClaudeCode } from './detect.js';

export {
  ClaudeRawEventSchema,
  ClaudeHookEventSchema,
  ClaudeToolUseSchema,
  ClaudeToolResultSchema,
  ClaudeMessageSchema,
} from './raw-schema.js';
