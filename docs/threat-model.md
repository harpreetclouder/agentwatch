# Threat model — VEYRA Watchdog (local MVP)

## Assets

| Asset | Why it matters |
|-------|----------------|
| Secrets / credentials (`.env`, `.aws`, `.ssh`) | Compromise → account takeover |
| Source code | IP + vulnerability disclosure |
| Security plane (`.veyra/`) | Tampering disables enforcement |
| Production resources / networks | Blast radius |
| Agent authority (session state) | Jailbreak → lasting privilege |

## Threats

- Prompt injection / malicious README instructions
- Credential & secret file access
- Data exfiltration via network / MCP
- Privilege escalation (`sudo`, destructive shell)
- Task hijacking / scope escape
- Security-control tampering (edit `.veyra`, clear quarantine)
- MCP tool abuse

## Trust boundaries

```
Human
  ↓
Agent runtime (Claude Code / Codex)
  ↓
VEYRA hook (user-space)     ← current enforcement point
  ↓
Watchdog + PolicyEngine
  ↓
Protected resources (files, shell, network requests visible to hooks)
```

## Where VEYRA has authority (today)

- Actions that flow through integrated agent hooks (`PreToolUse`, prompts, etc.)
- Deterministic allow/warn/block/quarantine decisions
- Persisted evidence in the local `.veyra` plane

## Where VEYRA does **not** have authority

- Agent processes that bypass hooks
- Compromised OS / privileged processes
- Kernel-level attacks
- Network traffic outside the agent tooling path
- Real sandboxing / syscall interposition

## Claim language

Correct: *VEYRA provides policy-based runtime enforcement for integrated agent actions.*

Incorrect: *VEYRA makes agents fully secure* / *100% secure*.
