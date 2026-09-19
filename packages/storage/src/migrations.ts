export interface Migration {
  id: string;
  sql: string;
}

/**
 * PostgreSQL-compatible shapes where practical (TEXT ids, ISO timestamps).
 * SQLite is the MVP engine; column types remain portable.
 */
export const MIGRATIONS: readonly Migration[] = [
  {
    id: '001_initial',
    sql: `
CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY NOT NULL,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  runtime TEXT NOT NULL,
  model TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY NOT NULL,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  task_id TEXT,
  task_description TEXT,
  working_directory TEXT NOT NULL,
  environment TEXT NOT NULL,
  status TEXT NOT NULL,
  security_state TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY NOT NULL,
  schema_version TEXT NOT NULL,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  agent_id TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  type TEXT NOT NULL,
  action_name TEXT NOT NULL,
  action_target TEXT,
  action_arguments TEXT,
  context_json TEXT,
  result_json TEXT,
  metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE TABLE IF NOT EXISTS security_decisions (
  id TEXT PRIMARY KEY NOT NULL,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  event_id TEXT NOT NULL,
  decision TEXT NOT NULL,
  severity TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decisions_session ON security_decisions(session_id);
CREATE INDEX IF NOT EXISTS idx_decisions_event ON security_decisions(event_id);

CREATE TABLE IF NOT EXISTS violations (
  id TEXT PRIMARY KEY NOT NULL,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  decision_id TEXT NOT NULL REFERENCES security_decisions(id),
  event_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  summary TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_violations_session ON violations(session_id);

CREATE TABLE IF NOT EXISTS security_state (
  session_id TEXT PRIMARY KEY NOT NULL REFERENCES sessions(id),
  state TEXT NOT NULL,
  reason TEXT,
  updated_at TEXT NOT NULL
);
`,
  },
];
