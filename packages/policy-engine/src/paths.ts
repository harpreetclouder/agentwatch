import { isAbsolute, normalize, resolve, sep, relative } from 'node:path';
import { realpathSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import type { AgentEvent } from '@veyra/agent-events';

/**
 * Expand ~ and normalize without executing anything.
 */
export function expandHome(input: string): string {
  if (input === '~') {
    return homedir();
  }
  if (input.startsWith('~/') || input.startsWith('~\\')) {
    return homedir() + input.slice(1);
  }
  return input;
}

/**
 * Resolve a path candidate against cwd without symlink follow (fast path).
 */
export function resolvePath(candidate: string, cwd: string): string {
  const expanded = expandHome(candidate.trim());
  const resolved = isAbsolute(expanded) ? normalize(expanded) : resolve(cwd, expanded);
  return normalize(resolved);
}

/**
 * Canonical absolute path: expand ~, resolve against base, normalize,
 * optionally follow symlinks when the path exists.
 * Does not execute shell; fails closed to normalized resolve on symlink errors.
 */
export function canonicalizePath(
  candidate: string,
  baseDir: string,
  options: { followSymlinks?: boolean } = {},
): string {
  const follow = options.followSymlinks !== false;
  const resolved = resolvePath(candidate, baseDir);
  if (!follow || !existsSync(resolved)) {
    return resolved;
  }
  try {
    return normalize(realpathSync(resolved));
  } catch {
    return resolved;
  }
}

export function basenameOf(pathValue: string): string {
  const normalized = normalize(pathValue);
  const parts = normalized.split(/[/\\]/).filter(Boolean);
  return parts[parts.length - 1] ?? normalized;
}

export function pathSegments(pathValue: string): string[] {
  return normalize(pathValue)
    .split(/[/\\]/)
    .filter((segment) => segment.length > 0 && segment !== '.');
}

/**
 * True when `child` is the same as `parent` or a descendant of `parent`.
 * Uses path.relative — never substring matching — so `/repo-other`
 * is not considered inside `/repo`.
 * Both sides are resolved to absolute normalized paths (and realpath when present)
 * so `/var` vs `/private/var` on macOS does not false-negative.
 */
export function isPathInside(child: string, parent: string): boolean {
  const normalizedChild = canonicalizePath(child, process.cwd());
  const normalizedParent = canonicalizePath(parent, process.cwd());
  if (normalizedChild === normalizedParent) {
    return true;
  }
  const rel = relative(normalizedParent, normalizedChild);
  if (!rel || rel === '') {
    return true;
  }
  if (rel.startsWith('..') || isAbsolute(rel)) {
    return false;
  }
  return true;
}

/**
 * Whether `candidate` is explicitly allowed by any entry in `allowed`.
 * Entries may be files or directories (directory ⇒ descendants allowed).
 * Globs ending in /** mean directory tree under the prefix.
 */
export function isPathAllowed(
  candidate: string,
  allowed: readonly string[],
  baseDir: string,
): boolean {
  if (allowed.length === 0) {
    return false;
  }
  const target = canonicalizePath(candidate, baseDir);
  for (const entry of allowed) {
    const pattern = entry.trim();
    if (!pattern) continue;
    if (pattern.endsWith('/**') || pattern.endsWith('\\**')) {
      const dir = canonicalizePath(pattern.slice(0, -3), baseDir);
      if (isPathInside(target, dir)) {
        return true;
      }
      continue;
    }
    const allowedResolved = canonicalizePath(pattern, baseDir);
    if (target === allowedResolved || isPathInside(target, allowedResolved)) {
      return true;
    }
  }
  return false;
}

/**
 * Whether `candidate` is explicitly denied.
 * Directory deny blocks the directory and all descendants.
 */
export function isPathDenied(
  candidate: string,
  denied: readonly string[],
  baseDir: string,
): boolean {
  if (denied.length === 0) {
    return false;
  }
  const target = canonicalizePath(candidate, baseDir);
  for (const entry of denied) {
    const pattern = entry.trim();
    if (!pattern) continue;
    if (pattern.endsWith('/**') || pattern.endsWith('\\**')) {
      const dir = canonicalizePath(pattern.slice(0, -3), baseDir);
      if (isPathInside(target, dir)) {
        return true;
      }
      continue;
    }
    const deniedResolved = canonicalizePath(pattern, baseDir);
    if (target === deniedResolved || isPathInside(target, deniedResolved)) {
      return true;
    }
  }
  return false;
}

export type ResourceMatchScope = {
  type: string;
  pattern: string;
  operations?: string[];
  effect?: 'allow' | 'deny';
};

/**
 * Match a file path against a FILE resource scope pattern.
 */
export function matchesResourceScope(
  candidate: string,
  scope: ResourceMatchScope,
  baseDir: string,
  operation?: string,
): boolean {
  if (scope.type.toUpperCase() !== 'FILE' && scope.type.toUpperCase() !== 'DIRECTORY') {
    return false;
  }
  if (
    operation &&
    scope.operations &&
    scope.operations.length > 0 &&
    !scope.operations.map((o) => o.toLowerCase()).includes(operation.toLowerCase())
  ) {
    return false;
  }
  const effect = scope.effect ?? 'allow';
  if (effect === 'deny') {
    return isPathDenied(candidate, [scope.pattern], baseDir);
  }
  return isPathAllowed(candidate, [scope.pattern], baseDir);
}

/**
 * Collect path-like strings from an event without shell execution.
 */
export function extractPathCandidates(event: AgentEvent): string[] {
  const out: string[] = [];

  if (typeof event.action.target === 'string' && event.action.target.length > 0) {
    out.push(event.action.target);
    if (/\s/.test(event.action.target)) {
      out.push(...tokenizeCommand(event.action.target));
    }
  }

  const args = event.action.arguments;
  if (typeof args === 'string') {
    out.push(...tokenizeCommand(args));
  } else if (Array.isArray(args)) {
    for (const item of args) {
      if (typeof item === 'string') {
        out.push(item);
      }
    }
  } else if (args && typeof args === 'object') {
    for (const value of Object.values(args as Record<string, unknown>)) {
      if (typeof value === 'string') {
        out.push(value);
        if (/\s/.test(value)) {
          out.push(...tokenizeCommand(value));
        }
      } else if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') {
            out.push(item);
          }
        }
      }
    }
  }

  return [...new Set(out.filter((s) => looksLikePath(s)))];
}

function looksLikePath(value: string): boolean {
  if (value.length === 0 || value.length > 1024) {
    return false;
  }
  if (value.includes('\0')) {
    return false;
  }
  if (value.startsWith('-') && !value.startsWith('./') && !value.startsWith('../')) {
    return false;
  }
  return (
    value.includes('/') ||
    value.includes('\\') ||
    value.startsWith('.') ||
    value.startsWith('~') ||
    /\.[a-z0-9]+$/i.test(value)
  );
}

/**
 * Lightweight argv tokenizer — not a full shell parser.
 */
export function tokenizeCommand(command: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;

  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i]!;
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
      continue;
    }
    current += ch;
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

/** @deprecated Prefer isPathInside — kept for callers that imported sep helpers. */
export function pathPrefix(parent: string): string {
  const normalizedParent = normalize(resolve(parent));
  return normalizedParent.endsWith(sep) ? normalizedParent : normalizedParent + sep;
}
