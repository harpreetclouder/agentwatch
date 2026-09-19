export type {
  BehaviorSignal,
  TrajectoryRule,
  SemanticRisk,
  SemanticAssessment,
  SemanticAnalyzer,
  WatchdogObservation,
  WatchdogSessionSnapshot,
} from './types.js';

export { SessionHistory } from './history.js';
export { Watchdog } from './watchdog.js';
export type { WatchdogOptions } from './watchdog.js';

export {
  createDefaultTrajectoryRules,
  injectionThenSecretRule,
  credentialChainRule,
  secretThenNetworkRule,
} from './trajectories/rules.js';

export { MockSemanticAnalyzer } from './semantic/mock.js';
export { HttpLlmSemanticAnalyzer } from './semantic/http-llm.js';
export type { HttpLlmSemanticOptions } from './semantic/http-llm.js';
export {
  TypesafeJevSemanticAnalyzer,
  isTypesafeJevModel,
  DEFAULT_DECISIONS_URL,
} from './semantic/typesafe-jev.js';
export type { TypesafeJevSemanticOptions } from './semantic/typesafe-jev.js';
export {
  createSemanticAnalyzer,
  describeSemanticProvider,
  resolveSemanticConfig,
} from './semantic/factory.js';
export type {
  CreateSemanticAnalyzerOptions,
  ResolvedSemanticConfig,
  SemanticProviderKind,
} from './semantic/factory.js';

export { signalToDecision } from './signals.js';
