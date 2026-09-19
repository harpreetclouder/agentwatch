import type { AgentEvent, AgentContext } from '@jev/agent-events';

/**
 * Vendor-neutral adapter contract.
 * Security logic must NOT live here — only detection + normalization.
 */
export interface AdapterOptions {
  sessionId: string;
  agentId: string;
  workingDirectory: string;
  taskDescription?: string;
  /** Optional callback after each normalized event (e.g. Watchdog.observe). */
  onEvent?: (event: AgentEvent) => void | Promise<void>;
}

export interface AgentSession {
  sessionId: string;
  agentId: string;
  adapterName: string;
  /** Ingest one raw vendor event → normalized AgentEvent (or null if ignored). */
  ingest(rawEvent: unknown): Promise<AgentEvent | null>;
  stop(): Promise<void>;
}

export interface AgentAdapter {
  name: string;
  detect(): Promise<boolean>;
  start(options: AdapterOptions): Promise<AgentSession>;
  /**
   * Pure normalization. Never trust raw input — validate inside.
   * Returns null when the payload is not an actionable agent event.
   */
  normalize(rawEvent: unknown, options: AdapterOptions): AgentEvent | null;
}

export type { AgentEvent, AgentContext };
