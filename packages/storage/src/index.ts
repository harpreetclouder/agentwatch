export type {
  AgentRecord,
  SessionRecord,
  SessionStatus,
  DecisionOutcome,
  SecurityDecisionRecord,
  ViolationRecord,
  SecurityStateRecord,
  SessionStats,
} from './types.js';

export type {
  AgentRepository,
  SessionRepository,
  EventRepository,
  SecurityDecisionRepository,
  ViolationRepository,
  SecurityStateRepository,
  StatsRepository,
  VeyraStore,
} from './repositories.js';

export { MIGRATIONS } from './migrations.js';
export type { Migration } from './migrations.js';
export { migrate } from './migrate.js';

export { SqliteVeyraStore } from './sqlite/store.js';
export type { OpenSqliteStoreOptions } from './sqlite/store.js';

export {
  initSecurityPlane,
  resolveVeyraDbPath,
  resolveProjectRoot,
  VEYRA_DIR_NAME,
  VEYRA_DB_FILE,
  VEYRA_CONFIG_FILE,
} from './security-plane.js';
export type { VeyraLocalConfig, InitSecurityPlaneResult } from './security-plane.js';
