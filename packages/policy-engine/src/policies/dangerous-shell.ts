import type { AgentContext, AgentEvent } from '@jev/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { tokenizeCommand } from '../paths.js';

type DangerousMatch = {
  pattern: string;
  reason: string;
  severity: 'HIGH' | 'CRITICAL';
};

/**
 * Structured detection of clearly dangerous shell operations.
 * Not an over-broad regex blacklist — token/structure based.
 */
export const dangerousShellPolicy: Policy = {
  id: 'DANGEROUS_SHELL',
  description: 'Detect clearly dangerous shell operations',
  severity: 'HIGH',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    if (event.type !== 'shell' && event.type !== 'tool_call') {
      return null;
    }

    const command = collectCommand(event);
    if (!command) {
      return null;
    }

    if ((context.allowedCommands ?? []).some((c) => command.includes(c))) {
      return null;
    }

    const match = classifyDangerousCommand(command);
    if (!match) {
      return null;
    }

    return {
      decision: match.severity === 'CRITICAL' ? 'QUARANTINE' : 'BLOCK',
      severity: match.severity,
      ruleId: 'DANGEROUS_SHELL',
      reason: match.reason,
      evidence: [
        `command=${truncate(command, 200)}`,
        `pattern=${match.pattern}`,
        `task=${context.task?.id ?? 'none'}`,
      ],
      eventId: event.id,
    };
  },
};

function collectCommand(event: AgentEvent): string | null {
  const parts: string[] = [];
  if (typeof event.action.target === 'string') {
    parts.push(event.action.target);
  }
  const args = event.action.arguments;
  if (typeof args === 'string') {
    parts.push(args);
  } else if (args && typeof args === 'object' && 'command' in args) {
    const cmd = (args as { command?: unknown }).command;
    if (typeof cmd === 'string') {
      parts.push(cmd);
    }
  }
  const joined = parts.join(' ').trim();
  return joined.length > 0 ? joined : null;
}

function classifyDangerousCommand(command: string): DangerousMatch | null {
  const lower = command.toLowerCase();
  const tokens = tokenizeCommand(command).map((t) => t.toLowerCase());

  if (
    (/curl\b/.test(lower) || /wget\b/.test(lower)) &&
    (/\|\s*(ba)?sh\b/.test(lower) || /\|\s*zsh\b/.test(lower))
  ) {
    return {
      pattern: 'pipe_to_shell',
      reason: 'Piping remote content into a shell is blocked.',
      severity: 'CRITICAL',
    };
  }

  if (tokens[0] === 'rm' && (tokens.includes('-rf') || tokens.includes('-fr'))) {
    const targets = tokens.filter((t) => !t.startsWith('-') && t !== 'rm');
    const dangerousTarget = targets.some(
      (t) =>
        t === '/' ||
        t === '/*' ||
        t === '~' ||
        t === '/etc' ||
        t === '/var' ||
        t === '/usr' ||
        t === '/home',
    );
    if (dangerousTarget) {
      return {
        pattern: 'rm_rf_root',
        reason: 'Recursive delete of a critical filesystem path is blocked.',
        severity: 'CRITICAL',
      };
    }
  }

  if (tokens[0] === 'mkfs' || tokens[0]?.startsWith('mkfs.')) {
    return {
      pattern: 'mkfs',
      reason: 'Filesystem formatting commands are blocked.',
      severity: 'CRITICAL',
    };
  }

  if (tokens[0] === 'dd' && tokens.some((t) => t.startsWith('of=/dev/'))) {
    return {
      pattern: 'dd_device',
      reason: 'Writing directly to block devices is blocked.',
      severity: 'CRITICAL',
    };
  }

  if (
    tokens[0] === 'chmod' &&
    tokens.includes('777') &&
    (tokens.includes('-r') || tokens.includes('-R')) &&
    tokens.some((t) => t === '/' || t === '/*')
  ) {
    return {
      pattern: 'chmod_777_root',
      reason: 'World-writable chmod on system roots is blocked.',
      severity: 'HIGH',
    };
  }

  if (tokens[0] === 'sudo' || tokens[0] === 'su' || tokens[0] === 'doas') {
    return {
      pattern: 'privilege_binary',
      reason: 'Privilege-escalation shell binaries are blocked without authority.',
      severity: 'HIGH',
    };
  }

  if (lower.includes(':(){:|:&};:')) {
    return {
      pattern: 'fork_bomb',
      reason: 'Fork bomb patterns are blocked.',
      severity: 'CRITICAL',
    };
  }

  return null;
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}
