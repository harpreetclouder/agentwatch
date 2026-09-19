import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Policy, SecurityDecision } from '../types.js';
import { tokenizeCommand } from '../paths.js';
import { sanitizeEvidence } from '../redact.js';

type DangerousMatch = {
  pattern: string;
  reason: string;
  severity: 'HIGH' | 'CRITICAL';
};

/**
 * Structured detection of clearly dangerous shell operations.
 * Not a complete shell sandbox — MVP command-category policy.
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

    if ((context.allowedCommands ?? []).some((c) => commandMatchesAllow(command, c))) {
      return null;
    }

    if ((context.deniedCommands ?? []).some((c) => commandMatchesAllow(command, c))) {
      return {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'DANGEROUS_SHELL',
        reason: 'Command matches an explicitly denied command pattern.',
        evidence: sanitizeEvidence([
          `command=${truncate(command, 200)}`,
          `matchedRule=deniedCommands`,
        ]),
        eventId: event.id,
      };
    }

    const match = classifyDangerousCommand(command, context);
    if (!match) {
      return null;
    }

    return {
      decision: match.severity === 'CRITICAL' ? 'QUARANTINE' : 'BLOCK',
      severity: match.severity,
      ruleId: 'DANGEROUS_SHELL',
      reason: match.reason,
      evidence: sanitizeEvidence([
        `command=${truncate(command, 200)}`,
        `pattern=${match.pattern}`,
        `task=${context.task?.id ?? 'none'}`,
      ]),
      eventId: event.id,
    };
  },
};

function commandMatchesAllow(command: string, entry: string): boolean {
  const tokens = tokenizeCommand(command).map((t) => t.toLowerCase());
  const needle = entry.toLowerCase().trim();
  if (!needle) return false;
  if (tokens[0] === needle || tokens.includes(needle)) {
    return true;
  }
  return command.toLowerCase().startsWith(needle);
}

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

function classifyDangerousCommand(
  command: string,
  context: AgentContext,
): DangerousMatch | null {
  const lower = command.toLowerCase();
  const tokens = tokenizeCommand(command).map((t) => t.toLowerCase());
  const bin = tokens[0] ?? '';

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

  if (bin === 'curl' || bin === 'wget' || bin === 'nc' || bin === 'ncat') {
    const dest = tokens.find((t) => t.includes('://') || /\./.test(t)) ?? '';
    const host =
      dest.replace(/^https?:\/\//, '').split('/')[0]?.split(':')[0]?.toLowerCase() ?? '';
    const denied = context.deniedNetworks ?? [];
    if (
      host.startsWith('evil.') ||
      host.includes('exfil') ||
      denied.some((d) => host === d.toLowerCase() || host.endsWith(`.${d.toLowerCase()}`))
    ) {
      return {
        pattern: 'network_exfil_shell',
        reason: 'Shell network tool targeting a denied or exfiltration host.',
        severity: 'CRITICAL',
      };
    }
    const allowed = context.allowedNetworks ?? [];
    if (
      allowed.length > 0 &&
      host &&
      !allowed.some((a) => host === a.toLowerCase() || host.endsWith(`.${a.toLowerCase()}`))
    ) {
      return {
        pattern: 'network_unauthorized',
        reason: 'Shell network tool targeting a host outside allowedNetworks.',
        severity: 'HIGH',
      };
    }
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

  if (tokens[0] === 'sudo' || tokens[0] === 'su' || tokens[0] === 'doas') {
    return {
      pattern: 'privilege_binary',
      reason: 'Privilege-escalation shell binaries are blocked without authority.',
      severity: 'HIGH',
    };
  }

  if (
    (bin === 'bash' || bin === 'sh' || bin === 'zsh') &&
    tokens.includes('-c') &&
    (lower.includes('rm -rf') || lower.includes('curl ') || lower.includes('wget '))
  ) {
    return {
      pattern: 'shell_eval_dangerous',
      reason: 'Shell -c with dangerous nested payload is blocked.',
      severity: 'HIGH',
    };
  }

  if ((bin === 'python' || bin === 'python3' || bin === 'node') && tokens.includes('-c')) {
    if (lower.includes('socket') || lower.includes('urllib') || lower.includes('http')) {
      return {
        pattern: 'interpreter_network',
        reason: 'Inline interpreter network access without authority is blocked.',
        severity: 'HIGH',
      };
    }
  }

  if (bin === 'ssh' || bin === 'scp') {
    return {
      pattern: 'remote_shell_copy',
      reason: 'SSH/SCP without explicit authority is blocked.',
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
