import type { AgentEvent } from '@veyra/agent-events';
import type { SecurityState } from '@veyra/shared';
import type {
  AgentRecord,
  SecurityDecisionRecord,
  SecurityStateRecord,
  SessionRecord,
  SessionStats,
  ViolationRecord,
} from './types.js';

export interface AgentRepository {
  upsert(agent: AgentRecord): Promise<void>;
  findById(id: string): Promise<AgentRecord | null>;
  list(): Promise<AgentRecord[]>;
}

export interface SessionRepository {
  create(session: SessionRecord): Promise<void>;
  update(session: SessionRecord): Promise<void>;
  findById(id: string): Promise<SessionRecord | null>;
  findLatestActive(): Promise<SessionRecord | null>;
  findLatest(): Promise<SessionRecord | null>;
  list(limit?: number): Promise<SessionRecord[]>;
  listByAgent(agentId: string): Promise<SessionRecord[]>;
}

export interface EventRepository {
  append(event: AgentEvent): Promise<void>;
  findById(id: string): Promise<AgentEvent | null>;
  findBySession(sessionId: string): Promise<AgentEvent[]>;
  countBySession(sessionId: string): Promise<number>;
}

export interface SecurityDecisionRepository {
  append(decision: SecurityDecisionRecord): Promise<void>;
  findById(id: string): Promise<SecurityDecisionRecord | null>;
  findBySession(sessionId: string): Promise<SecurityDecisionRecord[]>;
  listRecent(limit?: number): Promise<SecurityDecisionRecord[]>;
  countBySession(sessionId: string): Promise<{
    warnings: number;
    blocks: number;
    critical: number;
  }>;
}

export interface ViolationRepository {
  append(violation: ViolationRecord): Promise<void>;
  findBySession(sessionId: string): Promise<ViolationRecord[]>;
  listRecent(limit?: number): Promise<ViolationRecord[]>;
}

export interface SecurityStateRepository {
  get(sessionId: string): Promise<SecurityStateRecord | null>;
  set(sessionId: string, state: SecurityState, reason?: string): Promise<void>;
}

export interface StatsRepository {
  getSessionStats(sessionId: string): Promise<SessionStats>;
}

/**
 * Unit of work for the local MVP store.
 * Business logic depends on this interface — not on SQLite.
 */
export interface VeyraStore {
  agents: AgentRepository;
  sessions: SessionRepository;
  events: EventRepository;
  decisions: SecurityDecisionRepository;
  violations: ViolationRepository;
  securityState: SecurityStateRepository;
  stats: StatsRepository;
  close(): void;
}
