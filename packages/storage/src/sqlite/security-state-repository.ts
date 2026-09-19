import type { DatabaseSync } from 'node:sqlite';
import type { SecurityState } from '@veyra/shared';
import type { SecurityStateRecord } from '../types.js';
import type { SecurityStateRepository } from '../repositories.js';

type StateRow = {
  session_id: string;
  state: string;
  reason: string | null;
  updated_at: string;
};

function mapState(row: StateRow): SecurityStateRecord {
  return {
    sessionId: row.session_id,
    state: row.state as SecurityState,
    reason: row.reason,
    updatedAt: row.updated_at,
  };
}

export class SqliteSecurityStateRepository implements SecurityStateRepository {
  constructor(private readonly db: DatabaseSync) {}

  async get(sessionId: string): Promise<SecurityStateRecord | null> {
    const row = this.db
      .prepare(
        `SELECT session_id, state, reason, updated_at
         FROM security_state WHERE session_id = ?`,
      )
      .get(sessionId) as StateRow | undefined;
    return row ? mapState(row) : null;
  }

  async set(sessionId: string, state: SecurityState, reason?: string): Promise<void> {
    const updatedAt = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO security_state (session_id, state, reason, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(session_id) DO UPDATE SET
           state = excluded.state,
           reason = excluded.reason,
           updated_at = excluded.updated_at`,
      )
      .run(sessionId, state, reason ?? null, updatedAt);
  }
}
