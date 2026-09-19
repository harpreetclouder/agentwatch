/**
 * Future architecture stubs — not implemented for MVP Stage 1.
 * Passport answers WHO; Visa answers WHAT is allowed now.
 */

export interface AgentPassport {
  agentId: string;
  issuer: string;
  owner: string;
  runtime: string;
  model?: string;
  capabilities: string[];
  issuedAt: string;
  expiresAt?: string;
}

export interface Capability {
  name: string;
  operations: string[];
}

export interface ResourceScope {
  type: string;
  pattern: string;
  operations: string[];
  /** Optional allow/deny effect for MVP resource authorization. */
  effect?: 'allow' | 'deny';
}

export interface AgentVisa {
  visaId: string;
  agentId: string;
  taskId: string;
  capabilities: Capability[];
  resources: ResourceScope[];
  issuedAt: string;
  expiresAt: string;
  issuer: string;
  parentVisaId?: string;
}
