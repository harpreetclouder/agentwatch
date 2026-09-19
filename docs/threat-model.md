# Threat model — VEYRA

Honest scope for the current product: **user-space runtime authority enforcement** for agents integrated through hooks (Claude Code / Codex).

VEYRA does **not** claim complete AI security.

---

## Assets

| Asset | Why it matters |
|-------|----------------|
| Secrets / credentials (`.env`, cloud keys, SSH material) | Account takeover, data breach |
| Source and config in the workspace | IP loss, vulnerability disclosure |
| Security plane (`.veyra/`) | Tampering weakens or disables enforcement |
| Agent session authority (security state) | Jailbreak → lasting over-privilege |
| Evidence / decisions in SQLite | Audit integrity |
| Production hosts / networks (when tools reach them) | Blast radius |

---

## Threats

| Threat | Example |
|--------|---------|
| Prompt injection | Malicious README steers agent to read `.env` |
| Credential / secret access | `Read` / `cat` of secret files |
| Exfiltration | Network or MCP tools posting secrets |
| Privilege escalation | `sudo`, destructive shell |
| Task / scope escape | Reads or writes outside declared authority |
| Security-plane tampering | Editing `.veyra` config / clearing quarantine |
| Hook bypass | Agent or process that never hits PreToolUse |
| Evidence evasion | Hiding actions outside the observability path |

---

## Trust boundaries

```
Human operator
      ↓
Agent runtime (Claude Code / Codex / …)
      ↓
VEYRA hook bridge (user-space)     ← primary enforcement boundary today
      ↓
veyra hook → Adapter → AgentEvent
      ↓
Watchdog + PolicyEngine
      ↓
Enforcement decision + local evidence (.veyra)
      ↓
Protected resources (only when the agent tool path is used)
```

**Inside the boundary:** tool requests that Claude Code / Codex deliver to VEYRA hooks.  
**Outside the boundary:** the OS, other processes, and any agent that does not use integrated hooks.

---

## Attack surfaces

1. **Repository content** — README, docs, comments (injection)  
2. **Tool arguments** — paths, shell commands, URLs, MCP tool names  
3. **Hook / bridge config** — `.claude/settings.json`, `.veyra/hooks/`  
4. **Security plane** — SQLite DB, config under `.veyra/`  
5. **Operator CLI** — `quarantine` / `resume` / misconfiguration  

---

## Enforcement boundary

| VEYRA can enforce (today) | VEYRA cannot enforce (today) |
|---------------------------|------------------------------|
| Hook-visible PreToolUse (and related) events | Agents that bypass hooks |
| Deterministic allow / warn / block / quarantine | Compromised OS / privileged bypass |
| Fail-closed deny on malformed PreToolUse | Kernel attacks |
| Local evidence for observed decisions | Malicious processes outside VEYRA |
| Session freeze after quarantine | Network traffic outside the agent tooling path |
| | True OS sandbox / syscall interposition |
| | Network gateway / identity Passport-Visa issuance |

---

## Limitations (explicit)

VEYRA currently provides **user-space enforcement through integrated agent hooks**.

It does **not** protect against:

- Compromised operating systems  
- Privileged bypass  
- Kernel attacks  
- Agents outside integrated hooks  
- Malicious processes outside VEYRA  

Do **not** claim complete AI security.

Correct product language:

> Policy-based runtime authority enforcement for integrated agent actions — block before execution when the action is visible to VEYRA.

---

## Residual risk

Even with correct hook integration:

- Models may attempt alternate tools or encodings that evade current classifiers  
- Operators may run agents without installing the bridge  
- Evidence is as trustworthy as the host filesystem  
- Advisory LLM analysis (optional) never grants authority and must not be treated as a hard control  

---

## Related docs

- Product overview: [`README.md`](../README.md)  
- Hook wire format: [`HOOK_PROTOCOL.md`](HOOK_PROTOCOL.md)  
- Operator runbook: [`OPERATOR.md`](OPERATOR.md)  
- Implementation status: [`REAL_ENFORCEMENT_PLAN.md`](REAL_ENFORCEMENT_PLAN.md)  
