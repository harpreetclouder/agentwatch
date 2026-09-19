import type { AgentContext, AgentEvent } from '@veyra/agent-events';
import type { Policy, SecurityDecision } from '../types.js';

/**
 * Detect unauthorized or unexpected MCP tool usage.
 */
export const mcpToolViolationPolicy: Policy = {
  id: 'MCP_TOOL_VIOLATION',
  description: 'Detect unauthorized or unexpected MCP tools',
  severity: 'HIGH',

  evaluate(event: AgentEvent, context: AgentContext): SecurityDecision | null {
    if (event.type !== 'mcp') {
      return null;
    }

    const toolName = event.action.name;
    const lower = toolName.toLowerCase();

    if (
      lower.includes('exfil') ||
      lower.includes('eval') ||
      lower.includes('poison') ||
      lower.includes('shell_exec')
    ) {
      return {
        decision: 'QUARANTINE',
        severity: 'CRITICAL',
        ruleId: 'MCP_TOOL_VIOLATION',
        reason: 'MCP tool name matches a known-dangerous / poisoning pattern.',
        evidence: [`tool=${toolName}`, 'mcp_poison_heuristic=true'],
        eventId: event.id,
      };
    }

    const denied = context.deniedCommands ?? [];
    if (denied.some((d) => lower.includes(d.toLowerCase()) || toolName === d)) {
      return {
        decision: 'BLOCK',
        severity: 'HIGH',
        ruleId: 'MCP_TOOL_VIOLATION',
        reason: 'MCP tool is explicitly denied for this agent session.',
        evidence: [`tool=${toolName}`, `deniedCommands=${denied.join(',')}`],
        eventId: event.id,
      };
    }

    const allowed = context.allowedCommands ?? [];
    if (allowed.length > 0) {
      const ok = allowed.some((a) => toolName === a || lower.includes(a.toLowerCase()));
      if (!ok) {
        return {
          decision: 'BLOCK',
          severity: 'HIGH',
          ruleId: 'MCP_TOOL_VIOLATION',
          reason: 'MCP tool is not in the allowed tool authority for this session.',
          evidence: [`tool=${toolName}`, `allowedCommands=${allowed.join(',')}`],
          eventId: event.id,
        };
      }
    }

    return null;
  },
};
