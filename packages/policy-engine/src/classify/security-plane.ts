import { basenameOf, canonicalizePath, isPathInside, pathSegments } from '../paths.js';

const SECURITY_PLANE_BASENAMES = new Set([
  'security-state.json',
  'veyra.sqlite',
  'config.json',
]);

/**
 * Primary plane `.veyra`.
 * Legacy `.jev` is backward-compat only (leftover dirs from JEV→VEYRA rebrand);
 * active writers use `.veyra` exclusively. See docs/BACK_COMPAT_JEV.md.
 */
const SECURITY_PLANE_SEGMENTS = new Set(['.veyra', '.jev']);

function hasSecurityPlaneSegment(segments: string[]): boolean {
  return segments.some((s) => SECURITY_PLANE_SEGMENTS.has(s));
}

/**
 * Detect access/modification of the VEYRA security control plane.
 * Uses path segments / containment — never substring authorization.
 *
 * Scope: user-space hooks only — not OS filesystem isolation. An agent that
 * bypasses the hook bridge is outside this control; plane tampering still
 * escalates to CRITICAL + QUARANTINE when observed through the runtime path.
 */
export function classifySecurityPlanePath(
  pathValue: string,
  workingDirectory: string,
): { kind: string; resolved: string } | null {
  const resolved = canonicalizePath(pathValue, workingDirectory);
  const segments = pathSegments(resolved).map((s) => s.toLowerCase());
  const base = basenameOf(resolved).toLowerCase();
  const rawSegments = pathSegments(pathValue).map((s) => s.toLowerCase());

  if (hasSecurityPlaneSegment(segments) || hasSecurityPlaneSegment(rawSegments)) {
    if (SECURITY_PLANE_BASENAMES.has(base) && hasSecurityPlaneSegment(segments)) {
      return { kind: 'veyra_file', resolved };
    }
    return { kind: 'veyra_directory', resolved };
  }

  // Relative mentions of security-plane files under cwd/.veyra (or legacy .jev)
  const veyraRoot = canonicalizePath('.veyra', workingDirectory);
  const legacyRoot = canonicalizePath('.jev', workingDirectory);
  if (isPathInside(resolved, veyraRoot) || isPathInside(resolved, legacyRoot)) {
    return { kind: 'inside_veyra_root', resolved };
  }

  if (
    /security[-_]?state/i.test(base) ||
    /revocation/i.test(base) ||
    (/watchdog/i.test(base) && /config/i.test(base))
  ) {
    if (hasSecurityPlaneSegment(rawSegments) || hasSecurityPlaneSegment(segments)) {
      return { kind: 'security_config', resolved };
    }
  }

  return null;
}

export function isWriteLikeEvent(type: string, actionName: string): boolean {
  const name = actionName.toLowerCase();
  if (type === 'file_write') {
    return true;
  }
  if (type === 'shell') {
    return /^(rm|mv|cp|chmod|chown|unlink|truncate|dd|tee|sed|echo)/.test(name) ||
      /\b(rm|mv|cp|tee|sed\s+-i)\b/.test(name);
  }
  return name.includes('write') || name.includes('delete') || name.includes('unlink');
}
