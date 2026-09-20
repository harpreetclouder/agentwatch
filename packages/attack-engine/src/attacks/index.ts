import type { Attack, AttackMode } from '../types.js';
import {
  promptInjectionSecretsAttack,
  PROMPT_INJECTION_SECRET_ALIASES,
} from './prompt-injection-secrets.js';
import {
  liveTrajectoryAttack,
  LIVE_TRAJECTORY_ALIASES,
} from './live-trajectory.js';
import { corpusAttacks } from './corpus.js';

/** Full attack corpus (simulation + hook/runtime-capable definitions). */
export function listAttacks(mode?: AttackMode): Attack[] {
  const all = [promptInjectionSecretsAttack, liveTrajectoryAttack, ...corpusAttacks];
  if (!mode) return all;
  if (mode === 'simulation') {
    return all.filter((a) => a.simulationSupported);
  }
  // hook + runtime share the runtimeSupported flag (distinct runners)
  return all.filter((a) => a.runtimeSupported);
}

export function getAttack(id: string): Attack | undefined {
  const all = listAttacks();
  const direct = all.find((attack) => attack.id === id);
  if (direct) return direct;
  if ((PROMPT_INJECTION_SECRET_ALIASES as readonly string[]).includes(id)) {
    return promptInjectionSecretsAttack;
  }
  if ((LIVE_TRAJECTORY_ALIASES as readonly string[]).includes(id)) {
    return liveTrajectoryAttack;
  }
  return undefined;
}

export {
  promptInjectionSecretsAttack,
  PROMPT_INJECTION_SECRET_ALIASES,
  liveTrajectoryAttack,
  LIVE_TRAJECTORY_ALIASES,
};
export {
  dangerousShellAttack,
  networkExfiltrationAttack,
  credentialStoreAttack,
  sensitiveFileAttack,
  productionAccessAttack,
  mcpPoisoningAttack,
  taskDeviationAttack,
  authorityEscalationAttack,
  controlPlaneTamperingAttack,
} from './corpus.js';
