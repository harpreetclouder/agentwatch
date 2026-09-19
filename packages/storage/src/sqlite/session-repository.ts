import type { DatabaseSync } from 'node:sqlite';
import type { Environment, SecurityState } from '@jev/shared';
import type { SessionRecord, SessionStatus } from '../types.js';
import type { SessionRepository } from '../repositories.js';

type SessionRow = {
  id: string;
  agent_id: string;
  task_id: string | null;
  task_description: string | null;
  working_directory: string;
  environment: string;
  status: string;
  security_state: string;
  started_at: string;
  ended_at: string | null;
};

function mapSession(row: SessionRow): SessionRecord {
  return {
    id: row.id,
    agentId: row.agent_id,
    taskId: row.task_id,
    taskDescription: row.task_description,
    workingDirectory: row.working_directory,
    environment: row.environment as Environment,
    status: row.status as SessionStatus,
    securityState: row.security_state as SecurityState,
    startedAt: row.started_at,
    endedAt: row.ended_at,
  };
}

export class SqliteSessionRepository implements SessionRepository {
  constructor(private readonly db: DatabaseSync) {}

  async create(session: SessionRecord): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO sessions (
           id, agent_id, task_id, task_description, working_directory,
           environment, status, security_state, started_at, ended_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        session.id,
        session.agentId,
        session.taskId,
        session.taskDescription,
        session.workingDirectory,
        session.environment,
        session.status,
        session.securityState,
        session.startedAt,
        session.endedAt,
      );
  }

  async update(session: SessionRecord): Promise<void> {
    this.db
      .prepare(
        `UPDATE sessions SET
           agent_id = ?,
           task_id = ?,
           task_description = ?,
           working_directory = ?,
           environment = ?,
           status = ?,
           security_state = ?,
           started_at = ?,
           ended_at = ?
         WHERE id = ?`,
      )
      .run(
        session.agentId,
        session.taskId,
        session.taskDescription,
        session.workingDirectory,
        session.environment,
        session.status,
        session.securityState,
        session.startedAt,
        session.endedAt,
        session.id,
      );
  }

  async findById(id: string): Promise<SessionRecord | null> {
    const row = this.db
      .prepare(
        `SELECT id, agent_id, task_id, task_description, working_directory,
                environment, status, security_state, started_at, ended_at
         FROM sessions WHERE id = ?`,
      )
      .get(id) as SessionRow | undefined;
    return row ? mapSession(row) : null;
  }

  async findLatestActive(): Promise<SessionRecord | null> {
    const row = this.db
      .prepare(
        `SELECT id, agent_id, task_id, task_description, working_directory,
                environment, status, security_state, started_at, ended_at
         FROM sessions
         WHERE status IN ('ACTIVE', 'QUARANTINED')
         ORDER BY started_at DESC
         LIMIT 1`,
      )
      .get() as SessionRow | undefined;
    return row ? mapSession(row) : null;
  }

  async findLatest(): Promise<SessionRecord | null> {
    const row = this.db
      .prepare(
        `SELECT id, agent_id, task_id, task_description, working_directory,
                environment, status, security_state, started_at, ended_at
         FROM sessions
         ORDER BY started_at DESC
         LIMIT 1`,
      )
      .get() as SessionRow | undefined;
    return row ? mapSession(row) : null;
  }

  async list(limit: number = 100): Promise<SessionRecord[]> {
    const rows = this.db
      .prepare(
        `SELECT id, agent_id, task_id, task_description, working_directory,
                environment, status, security_state, started_at, ended_at
         FROM sessions
         ORDER BY started_at DESC
         LIMIT ?`,
      )
      .all(limit) as SessionRow[];
    return rows.map(mapSession);
  }

  async listByAgent(agentId: string): Promise<SessionRecord[]> {
    const rows = this.db
      .prepare(
        `SELECT id, agent_id, task_id, task_description, working_directory,
                environment, status, security_state, started_at, ended_at
         FROM sessions WHERE agent_id = ?
         ORDER BY started_at DESC`,
      )
      .all(agentId) as SessionRow[];
    return rows.map(mapSession);
  }
}
