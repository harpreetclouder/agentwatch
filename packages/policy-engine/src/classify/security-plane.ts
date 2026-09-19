import { basenameOf, isPathInside, pathSegments, resolvePath } from '../paths.js';

const SECURITY_PLANE_BASENAMES = new Set([
  'security-state.json',
  'veyra.sqlite',
  'config.json',
]);

const SECURITY_PLANE_SEGMENTS = new Set(['.veyra']);

/**
 * Detect access/modification of the Jev security control plane.
 */
export function classifySecurityPlanePath(
  pathValue: string,
  workingDirectory: string,
): { kind: string; resolved: string } | null {
  const resolved = resolvePath(pathValue, workingDirectory);
  const segments = pathSegments(resolved).map((s) => s.toLowerCase());
  const base = basenameOf(resolved).toLowerCase();

  if (segments.includes('.veyra')) {
    return { kind: 'jev_directory', resolved };
  }

  if (SECURITY_PLANE_BASENAMES.has(base) && segments.includes('.veyra')) {
    return { kind: 'jev_file', resolved };
  }

  // Relative mentions of security-plane files under cwd/.veyra
  const jevRoot = resolvePath('.veyra', workingDirectory);
  if (isPathInside(resolved, jevRoot)) {
    return { kind: 'inside_jev_root', resolved };
  }

  // Explicit relative targets like ".veyra/policies/..." before resolve edge cases
  const rawSegments = pathSegments(pathValue).map((s) => s.toLowerCase());
  if (rawSegments.some((s) => SECURITY_PLANE_SEGMENTS.has(s))) {
    return { kind: 'jev_path_reference', resolved };
  }

  if (
    /security[-_]?state/i.test(base) ||
    /revocation/i.test(base) ||
    (/watchdog/i.test(base) && /config/i.test(pathValue))
  ) {
    if (rawSegments.includes('.veyra') || pathValue.includes('.veyra')) {
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
