export type {
  Attack,
  AttackCategory,
  AttackCheck,
  AttackContext,
  AttackMode,
  AttackResult,
  AttackRunSummary,
  DecisionOutcome,
  ReportCategoryTally,
  ReportTestResult,
  ReportTopFinding,
  RuntimeAttackResult,
  RuntimeHonesty,
  SecurityReport,
} from './types.js';

export type {
  RuntimeAttackProof,
  RuntimeAttackProofGate,
  RuntimeAttackProofObservables,
  RuntimeOutcome,
  RuntimeTimelineStep,
} from './runtime-proof.js';

export {
  RUNTIME_ATTACK_PROOF_GATE_KEYS,
  RUNTIME_ATTACK_PROOF_GATE_LABELS,
  RUNTIME_OUTCOME_LABELS,
  RUNTIME_SYNTHETIC_SECRET,
  buildRuntimeAttackProof,
  emptyRuntimeAttackProof,
  formatRuntimeProofGateLines,
  formatRuntimeTimelineLines,
  haystackContainsRuntimeSecret,
  isRuntimeAttackContained,
  resolveRuntimeOutcome,
  runtimeOutcomeTallies,
  runtimeProofToChecks,
} from './runtime-proof.js';

export { createAttackLab } from './lab.js';
export type { AttackLab } from './lab.js';

export { simulateEvent } from './simulator.js';
export type { SimulatedStepResult } from './simulator.js';

export { runAttacks } from './runner.js';
export type { RunAttacksOptions, RunAttacksResult } from './runner.js';

export {
  buildSecurityReport,
  buildSecurityReportFromRuntimeResult,
  formatExplainReport,
  formatReportHtml,
  formatReportMarkdown,
  honestyFromMode,
} from './report.js';

export {
  listAttacks,
  getAttack,
  promptInjectionSecretsAttack,
  PROMPT_INJECTION_SECRET_ALIASES,
  liveTrajectoryAttack,
  LIVE_TRAJECTORY_ALIASES,
} from './attacks/index.js';
