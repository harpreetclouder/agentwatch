import type { DatabaseSync } from 'node:sqlite';
import type { AgentRecord } from '../types.js';
import type { AgentRepository } from '../repositories.js';

type AgentRow = {
  id: string;
  name: string;
  runtime: string;
  model: string | null;
  created_at: string;
  updated_at: string;
};

function mapAgent(row: AgentRow): AgentRecord {
  return {
    id: row.id,
    name: row.name,
    runtime: row.runtime,
    model: row.model,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class SqliteAgentRepository implements AgentRepository {
  constructor(private readonly db: DatabaseSync) {}

  async upsert(agent: AgentRecord): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO agents (id, name, runtime, model, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           name = excluded.name,
           runtime = excluded.runtime,
           model = excluded.model,
           updated_at = excluded.updated_at`,
      )
      .run(
        agent.id,
        agent.name,
        agent.runtime,
        agent.model,
        agent.createdAt,
        agent.updatedAt,
      );
  }

  async findById(id: string): Promise<AgentRecord | null> {
    const row = this.db
      .prepare(
        `SELECT id, name, runtime, model, created_at, updated_at
         FROM agents WHERE id = ?`,
      )
      .get(id) as AgentRow | undefined;
    return row ? mapAgent(row) : null;
  }

  async list(): Promise<AgentRecord[]> {
    const rows = this.db
      .prepare(
        `SELECT id, name, runtime, model, created_at, updated_at
         FROM agents ORDER BY created_at ASC`,
      )
      .all() as AgentRow[];
    return rows.map(mapAgent);
  }
}
