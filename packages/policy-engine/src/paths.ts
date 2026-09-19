import { isAbsolute, normalize, resolve, sep } from 'node:path';
import { homedir } from 'node:os';
import type { AgentEvent } from '@jev/agent-events';

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
 * Resolve a path candidate against cwd. Does not follow symlinks (MVP).
 */
export function resolvePath(candidate: string, cwd: string): string {
  const expanded = expandHome(candidate.trim());
  const resolved = isAbsolute(expanded) ? normalize(expanded) : resolve(cwd, expanded);
  return normalize(resolved);
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
  // Skip pure flags / options.
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
 * Enough for `cat .env` / `cat ~/.aws/credentials` style attacks.
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

export function isPathInside(child: string, parent: string): boolean {
  const normalizedChild = normalize(resolve(child));
  const normalizedParent = normalize(resolve(parent));
  if (normalizedChild === normalizedParent) {
    return true;
  }
  const prefix = normalizedParent.endsWith(sep)
    ? normalizedParent
    : normalizedParent + sep;
  return normalizedChild.startsWith(prefix);
}
