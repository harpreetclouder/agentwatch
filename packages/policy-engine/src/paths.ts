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

export type ResolveSafePathOptions = {
  followSymlinks?: boolean;
  /** When set, return null if the resolved path escapes this directory tree. */
  boundary?: string;
};

/**
 * Safe path resolution for authorization:
 * absolute normalization, relative resolve against working directory,
 * `..` collapse, optional symlink follow, optional boundary containment.
 * Returns null when a boundary is set and the result escapes it.
 */
export function resolveSafePath(
  candidate: string,
  workingDirectory: string,
  options: ResolveSafePathOptions = {},
): string | null {
  const canonOpts =
    options.followSymlinks === undefined ? {} : { followSymlinks: options.followSymlinks };
  const resolved = canonicalizePath(candidate, workingDirectory, canonOpts);
  if (!options.boundary) {
    return resolved;
  }
  const boundary = canonicalizePath(options.boundary, workingDirectory, canonOpts);
  if (!isPathInside(resolved, boundary)) {
    return null;
  }
  return resolved;
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
 * Local authority foundation (Visa precursor): FILE / DIRECTORY / SHELL / NETWORK / MCP.
 * Path scopes use canonicalizePath + isPathInside — never substring/prefix auth.
 * Non-path scopes use exact / host-suffix / command-bin matching only.
 */
export function matchesResourceScope(
  candidate: string,
  scope: ResourceMatchScope,
  baseDir: string,
  operation?: string,
): boolean {
  const type = scope.type.toUpperCase();
  if (
    operation &&
    scope.operations &&
    scope.operations.length > 0 &&
    !scope.operations.map((o) => o.toLowerCase()).includes(operation.toLowerCase())
  ) {
    return false;
  }

  if (type === 'FILE' || type === 'DIRECTORY') {
    const effect = scope.effect ?? 'allow';
    if (effect === 'deny') {
      return isPathDenied(candidate, [scope.pattern], baseDir);
    }
    return isPathAllowed(candidate, [scope.pattern], baseDir);
  }

  if (type === 'SHELL' || type === 'NETWORK' || type === 'MCP') {
    return matchesNonPathAuthority(candidate, scope.pattern, type);
  }

  return false;
}

/**
 * Exact / structured match for SHELL command bins, NETWORK hosts, and MCP tool names.
 * No raw substring authorization against arbitrary path-like strings.
 */
function matchesNonPathAuthority(
  candidate: string,
  pattern: string,
  type: 'SHELL' | 'NETWORK' | 'MCP',
): boolean {
  const raw = candidate.trim();
  const p = pattern.trim().toLowerCase();
  if (!raw || !p) {
    return false;
  }
  if (p === '*') {
    return true;
  }

  if (type === 'NETWORK') {
    const host = networkHostname(raw).toLowerCase();
    if (p.startsWith('*.')) {
      const bare = p.slice(2);
      return host === bare || host.endsWith(`.${bare}`);
    }
    return host === p || host.endsWith(`.${p}`);
  }

  if (type === 'SHELL') {
    const bin = (raw.split(/\s+/)[0] ?? raw).toLowerCase();
    if (p.endsWith('*') && !p.startsWith('*')) {
      return bin.startsWith(p.slice(0, -1));
    }
    return bin === p;
  }

  // MCP tool name
  const tool = raw.toLowerCase();
  if (p.endsWith('*') && !p.startsWith('*')) {
    return tool.startsWith(p.slice(0, -1));
  }
  return tool === p;
}

function networkHostname(target: string): string {
  const trimmed = target.trim();
  try {
    if (trimmed.includes('://')) {
      return new URL(trimmed).hostname;
    }
  } catch {
    // fall through
  }
  return trimmed.split('/')[0]?.split(':')[0] ?? trimmed;
}

/**
 * Argument keys that carry filesystem paths (Edit/Write/Read payloads).
 * Content fields (old_string / new_string / etc.) must NOT be scanned — they
 * often mention `.env` or `password` in comments and falsely trip SECRET_ACCESS.
 */
const PATH_ARG_KEYS = new Set([
  'file_path',
  'path',
  'filename',
  'target',
  'cwd',
  'directory',
  'dir',
  'working_directory',
  'workdir',
]);

/** Shell / argv fields — tokenize for embedded path tokens (e.g. `cat .env`). */
const COMMAND_ARG_KEYS = new Set(['command', 'cmd', 'script']);

/**
 * Collect path-like strings from an event without shell execution.
 * Never treats edit/write file *contents* as path candidates.
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
    for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
      const k = key.toLowerCase();
      if (typeof value === 'string') {
        if (PATH_ARG_KEYS.has(k)) {
          out.push(value);
        } else if (COMMAND_ARG_KEYS.has(k)) {
          out.push(...tokenizeCommand(value));
        }
        // Skip content / prose fields (old_string, new_string, content, …).
      } else if (Array.isArray(value) && PATH_ARG_KEYS.has(k)) {
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
  if (value.includes('\0') || value.includes('\n') || value.includes('\r')) {
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
