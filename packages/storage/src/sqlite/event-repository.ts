import type { DatabaseSync } from 'node:sqlite';
import type { AgentEvent } from '@jev/agent-events';
import { parseAgentEventOrThrow } from '@jev/agent-events';
import type { EventRepository } from '../repositories.js';

type EventRow = {
  id: string;
  schema_version: string;
  session_id: string;
  agent_id: string;
  timestamp: string;
  type: string;
  action_name: string;
  action_target: string | null;
  action_arguments: string | null;
  context_json: string | null;
  result_json: string | null;
  metadata_json: string | null;
};

function toJson(value: unknown): string | null {
  if (value === undefined) {
    return null;
  }
  return JSON.stringify(value);
}

function fromJson(value: string | null): unknown {
  if (value === null) {
    return undefined;
  }
  return JSON.parse(value) as unknown;
}

function mapEvent(row: EventRow): AgentEvent {
  const actionArguments = fromJson(row.action_arguments);
  const context = fromJson(row.context_json);
  const result = fromJson(row.result_json);
  const metadata = fromJson(row.metadata_json);

  return parseAgentEventOrThrow({
    id: row.id,
    schemaVersion: row.schema_version,
    sessionId: row.session_id,
    agentId: row.agent_id,
    timestamp: row.timestamp,
    type: row.type,
    action: {
      name: row.action_name,
      ...(row.action_target !== null ? { target: row.action_target } : {}),
      ...(actionArguments !== undefined ? { arguments: actionArguments } : {}),
    },
    ...(context !== undefined ? { context } : {}),
    ...(result !== undefined ? { result } : {}),
    ...(metadata !== undefined ? { metadata } : {}),
  });
}

export class SqliteEventRepository implements EventRepository {
  constructor(private readonly db: DatabaseSync) {}

  async append(event: AgentEvent): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO events (
           id, schema_version, session_id, agent_id, timestamp, type,
           action_name, action_target, action_arguments,
           context_json, result_json, metadata_json
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.id,
        event.schemaVersion,
        event.sessionId,
        event.agentId,
        event.timestamp,
        event.type,
        event.action.name,
        event.action.target ?? null,
        toJson(event.action.arguments),
        toJson(event.context),
        toJson(event.result),
        toJson(event.metadata),
      );
  }

  async findById(id: string): Promise<AgentEvent | null> {
    const row = this.db
      .prepare(
        `SELECT id, schema_version, session_id, agent_id, timestamp, type,
                action_name, action_target, action_arguments,
                context_json, result_json, metadata_json
         FROM events WHERE id = ?`,
      )
      .get(id) as EventRow | undefined;
    return row ? mapEvent(row) : null;
  }

  async findBySession(sessionId: string): Promise<AgentEvent[]> {
    const rows = this.db
      .prepare(
        `SELECT id, schema_version, session_id, agent_id, timestamp, type,
                action_name, action_target, action_arguments,
                context_json, result_json, metadata_json
         FROM events WHERE session_id = ?
         ORDER BY timestamp ASC, id ASC`,
      )
      .all(sessionId) as EventRow[];
    return rows.map(mapEvent);
  }

  async countBySession(sessionId: string): Promise<number> {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS count FROM events WHERE session_id = ?`)
      .get(sessionId) as { count: number | bigint };
    return Number(row.count);
  }
}
