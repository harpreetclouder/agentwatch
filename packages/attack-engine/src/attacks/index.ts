import type { Attack } from '../types.js';
import { promptInjectionSecretsAttack } from './prompt-injection-secrets.js';
import { corpusAttacks } from './corpus.js';

/** Full Stage 10 attack corpus (10 scenarios). */
export function listAttacks(): Attack[] {
  return [promptInjectionSecretsAttack, ...corpusAttacks];
}

export function getAttack(id: string): Attack | undefined {
  return listAttacks().find((attack) => attack.id === id);
}

export { promptInjectionSecretsAttack };
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
