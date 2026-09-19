import type { DatabaseSync } from 'node:sqlite';
import type { Severity } from '@jev/shared';
import type { ViolationRecord } from '../types.js';
import type { ViolationRepository } from '../repositories.js';

type ViolationRow = {
  id: string;
  session_id: string;
  decision_id: string;
  event_id: string;
  rule_id: string;
  severity: string;
  summary: string;
  created_at: string;
};

function mapViolation(row: ViolationRow): ViolationRecord {
  return {
    id: row.id,
    sessionId: row.session_id,
    decisionId: row.decision_id,
    eventId: row.event_id,
    ruleId: row.rule_id,
    severity: row.severity as Severity,
    summary: row.summary,
    createdAt: row.created_at,
  };
}

export class SqliteViolationRepository implements ViolationRepository {
  constructor(private readonly db: DatabaseSync) {}

  async append(violation: ViolationRecord): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO violations (
           id, session_id, decision_id, event_id, rule_id, severity, summary, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        violation.id,
        violation.sessionId,
        violation.decisionId,
        violation.eventId,
        violation.ruleId,
        violation.severity,
        violation.summary,
        violation.createdAt,
      );
  }

  async findBySession(sessionId: string): Promise<ViolationRecord[]> {
    const rows = this.db
      .prepare(
        `SELECT id, session_id, decision_id, event_id, rule_id, severity, summary, created_at
         FROM violations WHERE session_id = ?
         ORDER BY created_at ASC, id ASC`,
      )
      .all(sessionId) as ViolationRow[];
    return rows.map(mapViolation);
  }

  async listRecent(limit: number = 100): Promise<ViolationRecord[]> {
    const rows = this.db
      .prepare(
        `SELECT id, session_id, decision_id, event_id, rule_id, severity, summary, created_at
         FROM violations
         ORDER BY created_at DESC, id DESC
         LIMIT ?`,
      )
      .all(limit) as ViolationRow[];
    return rows.map(mapViolation);
  }
}
