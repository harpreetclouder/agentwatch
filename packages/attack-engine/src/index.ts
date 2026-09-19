export type {
  Attack,
  AttackCategory,
  AttackCheck,
  AttackContext,
  AttackMode,
  AttackResult,
  AttackRunSummary,
  DecisionOutcome,
  RuntimeAttackResult,
  SecurityReport,
} from './types.js';

export { createAttackLab } from './lab.js';
export type { AttackLab } from './lab.js';

export { simulateEvent } from './simulator.js';
export type { SimulatedStepResult } from './simulator.js';

export { runAttacks } from './runner.js';
export type { RunAttacksOptions, RunAttacksResult } from './runner.js';

export { buildSecurityReport, formatExplainReport } from './report.js';

export {
  listAttacks,
  getAttack,
  promptInjectionSecretsAttack,
  PROMPT_INJECTION_SECRET_ALIASES,
} from './attacks/index.js';
