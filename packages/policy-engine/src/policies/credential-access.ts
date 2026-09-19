import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { extractPathCandidates, resolvePath, pathSegments } from '../paths.js';

const CREDENTIAL_DIR_MARKERS = new Set([
  '.aws',
  '.ssh',
  '.gnupg',
  '.kube',
  '.docker',
  '.config',
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
  'token',
  'token.json',
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
      const resolved = resolvePath(candidate, cwd);
      const segments = pathSegments(resolved).map((s) => s.toLowerCase());
      const base = (segments[segments.length - 1] ?? '').toLowerCase();

      const inCredDir = segments.some((s) => CREDENTIAL_DIR_MARKERS.has(s));
      const credFile = CREDENTIAL_BASENAMES.has(base);

      if (!inCredDir && !credFile) {
        continue;
      }

      // Prefer home/config credential stores over random "token" filenames in src/
      const looksLikeStore =
        inCredDir ||
        resolved.includes(`${pathSep()}.aws${pathSep()}`) ||
        resolved.includes(`${pathSep()}.ssh${pathSep()}`) ||
        base === 'credentials' ||
        base.endsWith('service-account.json');

      if (!looksLikeStore) {
        continue;
      }

      if (isAllowed(context, resolved, candidate)) {
        return null;
      }

      return {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'CREDENTIAL_ACCESS',
        reason: 'Access to a credential store location is outside declared authority.',
        evidence: [
          `resource=${candidate}`,
          `resolved=${resolved}`,
          `task=${context.task?.id ?? 'none'}`,
          'credential_store_access',
        ],
        eventId: event.id,
      };
    }

    return null;
  },
};

function pathSep(): string {
  return '/';
}

function isAllowed(context: AgentContext, resolved: string, raw: string): boolean {
  const allowed = context.allowedPaths ?? [];
  if (allowed.length === 0) {
    return false;
  }
  const haystacks = [resolved, raw].map((s) => s.toLowerCase());
  return allowed.some((entry) => {
    const needle = entry.toLowerCase();
    return haystacks.some((h) => h === needle || h.endsWith(needle) || h.includes(needle));
  });
}
