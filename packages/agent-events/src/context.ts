import type { Environment, SecurityState } from '@veyra/shared';

/**
 * Precursor to the future Agent Visa model.
 * Mutable session authority snapshot — not yet a signed Visa.
 */
export type { SecurityState } from '@veyra/shared';
export type AgentEnvironment = Environment;

export interface AgentTask {
  id: string;
  description: string;
}

/**
 * MVP resource authority entry (Visa precursor).
 * Prefer typed scopes over ad-hoc string checks in new policies.
 */
export interface ContextResourceScope {
  type: 'FILE' | 'DIRECTORY' | 'SHELL' | 'NETWORK' | 'MCP' | 'PRODUCTION';
  pattern: string;
  operations: Array<'read' | 'write' | 'execute' | 'connect' | '*'>;
  effect: 'allow' | 'deny';
}

export interface AgentContext {
  agentId: string;
  sessionId: string;
  task?: AgentTask;
  workingDirectory: string;
  allowedPaths?: string[];
  deniedPaths?: string[];
  allowedCommands?: string[];
  deniedCommands?: string[];
  allowedNetworks?: string[];
  deniedNetworks?: string[];
  /** Explicit resource scopes (Visa precursor). */
  resourceScopes?: ContextResourceScope[];
  environment: AgentEnvironment;
  securityState: SecurityState;
}
