# VEYRA WATCHDOG

Security control plane for autonomous AI agents.

```
See what your agent does.
Understand why.
Stop it when it crosses its authority.
```

**Core thesis:** a compromised agent should never turn a jailbreak into authority.

---

## What problem this solves

Generic LLM guardrails judge *text*. Agents take *actions* (read files, run shell, call MCP).

VEYRA sits on the agent hook path and decides **authority** independently of the model:

```
REAL AGENT → TOOL REQUEST → VEYRA HOOK → POLICY → BLOCK → TOOL NEVER EXECUTES → EVIDENCE
```

Not: “detected malicious behavior.”  
Yes: **blocked before execution.**

---

## Quick start

```bash
pnpm install
pnpm build
pnpm test

pnpm veyra init
pnpm veyra demo                          # hook-protocol demo: .env BLOCKED
pnpm veyra attack --simulation           # synthetic PolicyEngine/Watchdog corpus
pnpm veyra attack --runtime              # real PreToolUse: prompt-injection-secret-access
```

### Claude Code live enforcement

```bash
pnpm veyra bridge install                # merges hooks; backs up settings
# In a project (see examples/real-agent-demo):
# ask Claude Code to “fix auth” — Read(.env) should be denied
pnpm veyra explain <session-id>
pnpm veyra bridge status
pnpm veyra bridge uninstall
```

Demo fixture: [`examples/real-agent-demo/`](examples/real-agent-demo/) (synthetic `.env` only).

No API key required for deterministic enforcement. Optional advisory TypeSafe Jev via OpenRouter Decisions API (`OPENROUTER_API_KEY=sk-or-...`) — never grants authority.

---

## Security model (honest)

VEYRA currently operates at **user-space hook** level for integrated agents (Claude Code / Codex).

| Can enforce | Cannot protect against |
|-------------|----------------------|
| Hook-visible PreToolUse / prompts | Agent escaping hooks |
| Deterministic policies + quarantine | Compromised OS / privileged bypass |
| Local evidence in `.veyra/` | Kernel attacks, external malware |

Correct claim: *policy-based runtime enforcement for integrated agent actions.*  
See [`docs/threat-model.md`](docs/threat-model.md).

---

## Architecture

```
Agent → Adapter → AgentEvent → PolicyEngine → Watchdog → Enforcement → Evidence → CLI/Dashboard
```

| Concept | MVP |
|---------|-----|
| AgentContext + resource scopes | Implemented (Visa precursor) |
| Deterministic policies (10) | Implemented |
| Trajectory correlation | Implemented |
| Hook fail-closed (PreToolUse) | Implemented |
| Passport / Visa / Trust Network | Interfaces only — later |

---

## Commands

| Command | Purpose |
|---------|---------|
| `veyra init` | Local `.veyra/` plane |
| `veyra bridge install\|status\|uninstall` | Live hooks (merge-safe + backup) |
| `veyra hook` | Stdin hook processor (fail-closed PreToolUse) |
| `veyra demo` | Controlled block-before-execution demo |
| `veyra attack --mode=simulation\|runtime` | Attack lab |
| `veyra explain [session]` | Incident timeline / last report |
| `veyra watch` / `events` / `policy` / `status` | Observe |
| `veyra quarantine` / `resume` | Operator controls |

---

## Development

```bash
pnpm typecheck && pnpm lint && pnpm test && pnpm build
```

Stack: TypeScript, pnpm, Turborepo, Zod, Vitest, SQLite, Next.js dashboard (local read-only).

---

## License

Proprietary / TBD.
