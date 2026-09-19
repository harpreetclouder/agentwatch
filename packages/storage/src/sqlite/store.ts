import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { migrate } from '../migrate.js';
import type { JevStore } from '../repositories.js';
import { SqliteAgentRepository } from './agent-repository.js';
import { SqliteSessionRepository } from './session-repository.js';
import { SqliteEventRepository } from './event-repository.js';
import { SqliteSecurityDecisionRepository } from './decision-repository.js';
import { SqliteViolationRepository } from './violation-repository.js';
import { SqliteSecurityStateRepository } from './security-state-repository.js';
import { SqliteStatsRepository } from './stats-repository.js';

export type OpenSqliteStoreOptions = {
  /** Absolute path to the SQLite database file. */
  dbPath: string;
};

export class SqliteJevStore implements JevStore {
  readonly agents: SqliteAgentRepository;
  readonly sessions: SqliteSessionRepository;
  readonly events: SqliteEventRepository;
  readonly decisions: SqliteSecurityDecisionRepository;
  readonly violations: SqliteViolationRepository;
  readonly securityState: SqliteSecurityStateRepository;
  readonly stats: SqliteStatsRepository;

  private constructor(private readonly db: DatabaseSync) {
    this.agents = new SqliteAgentRepository(db);
    this.sessions = new SqliteSessionRepository(db);
    this.events = new SqliteEventRepository(db);
    this.decisions = new SqliteSecurityDecisionRepository(db);
    this.violations = new SqliteViolationRepository(db);
    this.securityState = new SqliteSecurityStateRepository(db);
    this.stats = new SqliteStatsRepository(this.events, this.decisions);
  }

  static open(options: OpenSqliteStoreOptions): SqliteJevStore {
    mkdirSync(dirname(options.dbPath), { recursive: true });
    const db = new DatabaseSync(options.dbPath);
    db.exec('PRAGMA foreign_keys = ON;');
    migrate(db);
    return new SqliteJevStore(db);
  }

  /** In-memory store for tests. */
  static openMemory(): SqliteJevStore {
    const db = new DatabaseSync(':memory:');
    db.exec('PRAGMA foreign_keys = ON;');
    migrate(db);
    return new SqliteJevStore(db);
  }

  close(): void {
    this.db.close();
  }
}
