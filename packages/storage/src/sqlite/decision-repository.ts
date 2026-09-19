import type { DatabaseSync } from 'node:sqlite';
import type { Severity } from '@veyra/shared';
import type { DecisionOutcome, SecurityDecisionRecord } from '../types.js';
import type { SecurityDecisionRepository } from '../repositories.js';

type DecisionRow = {
  id: string;
  session_id: string;
  event_id: string;
  decision: string;
  severity: string;
  rule_id: string;
  reason: string;
  evidence_json: string;
  created_at: string;
};

function mapDecision(row: DecisionRow): SecurityDecisionRecord {
  const evidence = JSON.parse(row.evidence_json) as unknown;
  if (!Array.isArray(evidence) || !evidence.every((item) => typeof item === 'string')) {
    throw new Error(`Corrupt evidence_json for decision ${row.id}`);
  }

  return {
    id: row.id,
    sessionId: row.session_id,
    eventId: row.event_id,
    decision: row.decision as DecisionOutcome,
    severity: row.severity as Severity,
    ruleId: row.rule_id,
    reason: row.reason,
    evidence,
    createdAt: row.created_at,
  };
}

export class SqliteSecurityDecisionRepository implements SecurityDecisionRepository {
  constructor(private readonly db: DatabaseSync) {}

  async append(decision: SecurityDecisionRecord): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO security_decisions (
           id, session_id, event_id, decision, severity, rule_id,
           reason, evidence_json, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        decision.id,
        decision.sessionId,
        decision.eventId,
        decision.decision,
        decision.severity,
        decision.ruleId,
        decision.reason,
        JSON.stringify(decision.evidence),
        decision.createdAt,
      );
  }

  async findById(id: string): Promise<SecurityDecisionRecord | null> {
    const row = this.db
      .prepare(
        `SELECT id, session_id, event_id, decision, severity, rule_id,
                reason, evidence_json, created_at
         FROM security_decisions WHERE id = ?`,
      )
      .get(id) as DecisionRow | undefined;
    return row ? mapDecision(row) : null;
  }

  async findBySession(sessionId: string): Promise<SecurityDecisionRecord[]> {
    const rows = this.db
      .prepare(
        `SELECT id, session_id, event_id, decision, severity, rule_id,
                reason, evidence_json, created_at
         FROM security_decisions WHERE session_id = ?
         ORDER BY created_at ASC, id ASC`,
      )
      .all(sessionId) as DecisionRow[];
    return rows.map(mapDecision);
  }

  async listRecent(limit: number = 100): Promise<SecurityDecisionRecord[]> {
    const rows = this.db
      .prepare(
        `SELECT id, session_id, event_id, decision, severity, rule_id,
                reason, evidence_json, created_at
         FROM security_decisions
         WHERE decision IN ('WARN', 'BLOCK', 'QUARANTINE')
         ORDER BY created_at DESC, id DESC
         LIMIT ?`,
      )
      .all(limit) as DecisionRow[];
    return rows.map(mapDecision);
  }

  async countBySession(sessionId: string): Promise<{
    warnings: number;
    blocks: number;
    critical: number;
  }> {
    const row = this.db
      .prepare(
        `SELECT
           SUM(CASE WHEN decision = 'WARN' THEN 1 ELSE 0 END) AS warnings,
           SUM(CASE WHEN decision IN ('BLOCK', 'QUARANTINE') THEN 1 ELSE 0 END) AS blocks,
           SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical
         FROM security_decisions
         WHERE session_id = ?`,
      )
      .get(sessionId) as {
      warnings: number | bigint | null;
      blocks: number | bigint | null;
      critical: number | bigint | null;
    };

    return {
      warnings: Number(row.warnings ?? 0),
      blocks: Number(row.blocks ?? 0),
      critical: Number(row.critical ?? 0),
    };
  }
}
