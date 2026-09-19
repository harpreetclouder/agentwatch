import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import {
  canonicalizePath,
  extractPathCandidates,
  isPathAllowed,
  pathSegments,
} from '../paths.js';
import { sanitizeEvidence } from '../redact.js';

const CREDENTIAL_DIR_MARKERS = new Set([
  '.aws',
  '.ssh',
  '.gnupg',
  '.kube',
  '.docker',
]);

const CREDENTIAL_BASENAMES = new Set([
  'credentials',
  'credentials.json',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
  'service-account.json',
  'serviceAccount.json',
]);

/**
 * Detect access to common credential store locations.
 */
export const credentialAccessPolicy: Policy = {
  id: 'CREDENTIAL_ACCESS',
  description: 'Detect access to cloud/SSH/kube credential store locations',
  severity: 'HIGH',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    if (!['file_read', 'file_write', 'shell', 'tool_call'].includes(event.type)) {
      return null;
    }

    const cwd = event.context?.cwd ?? context.workingDirectory;
    for (const candidate of extractPathCandidates(event)) {
      const resolved = canonicalizePath(candidate, cwd);
      const segments = pathSegments(resolved).map((s) => s.toLowerCase());
      const base = (segments[segments.length - 1] ?? '').toLowerCase();

      const inCredDir = segments.some((s) => CREDENTIAL_DIR_MARKERS.has(s));
      const credFile = CREDENTIAL_BASENAMES.has(base);

      if (!inCredDir && !credFile) {
        continue;
      }

      const looksLikeStore =
        inCredDir ||
        base === 'credentials' ||
        base.endsWith('service-account.json') ||
        base === 'serviceaccount.json';

      if (!looksLikeStore) {
        continue;
      }

      if (isPathAllowed(candidate, context.allowedPaths ?? [], cwd)) {
        return null;
      }

      return {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'CREDENTIAL_ACCESS',
        reason: 'Access to a credential store location is outside declared authority.',
        evidence: sanitizeEvidence([
          `resource=${candidate}`,
          `resolved=${resolved}`,
          `operation=read`,
          `matchedRule=credential-store`,
          `task=${context.task?.id ?? 'none'}`,
          `session=${context.sessionId}`,
        ]),
        eventId: event.id,
      };
    }

    return null;
  },
};
