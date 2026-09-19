import type { Environment, SecurityState } from '@jev/shared';

/**
 * Precursor to the future Agent Visa model.
 * Mutable session authority snapshot — not yet a signed Visa.
 */
export type { SecurityState } from '@jev/shared';
export type AgentEnvironment = Environment;

export interface AgentTask {
  id: string;
  description: string;
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
  environment: AgentEnvironment;
  securityState: SecurityState;
}
