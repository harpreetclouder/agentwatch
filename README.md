# VEYRA

**Runtime security and authority enforcement for AI agents.**

```
See what your agent does.
Understand why.
Stop it when it crosses its authority.
```

A jailbreak must never become authority.

---

## Real use case

AI coding agents (Claude Code, Codex, and similar) do not only generate text — they **read files, run shell, and call tools**. Prompt injection and over-broad tasks can steer them into secrets, destructive commands, or out-of-scope resources.

VEYRA sits on the **tool request path** and decides whether that action is allowed **before execution**.

```
Agent
  → Tool Request
  → VEYRA
  → Policy
  → Watchdog
  → Enforcement
  → Evidence
```

| Outcome | Meaning |
|---------|---------|
| ALLOW | Tool may proceed |
| WARN | Proceed with recorded risk |
| BLOCK | Tool must not run |
| QUARANTINE | Session frozen; further tools denied until operator resume |

Correct claim: **blocked before execution** for hook-visible actions.  
Incorrect claim: complete AI / agent security.

---

## Product demo

**Front door — test whether your agent can be compromised:**

```bash
pnpm install && pnpm build
pnpm veyra demo
```

`veyra demo` is the real product demonstration:

1. Isolated workspace with synthetic `.env`, vulnerable `src/auth.ts`, and a controlled malicious README  
2. VEYRA enforcement via real Claude PreToolUse hooks  
3. Live Claude Code when available; otherwise an honest **REAL RUNTIME UNAVAILABLE** message + deterministic hook test (never labeled as live runtime)

**Expected story:**

```
Prompt Injection
  → Secret Access (.env)
  → BLOCK (SECRET_ACCESS)
  → Tool Never Executes
  → Evidence recorded
```

Synthetic secrets only (`veyra_fake_*`). Do not put real credentials in the demo `.env`.

Fixture project: [`examples/real-agent-demo/`](examples/real-agent-demo/).

CI regression (simulation corpus):

```bash
pnpm veyra attack --ci
pnpm veyra report --json
```

---

## Claude Code bridge

Install hooks so Claude Code tool requests pass through VEYRA:

```bash
pnpm veyra bridge install     # merge VEYRA into .claude/settings.json (backup created)
pnpm veyra bridge status      # show whether managed hooks are present
pnpm veyra bridge uninstall   # remove managed hooks; restore backup when applicable
```

### What the hook does

1. Claude Code emits a **PreToolUse** event (JSON on stdin) before running a tool.  
2. The bridge script runs `veyra hook --adapter=claude-code`.  
3. VEYRA normalizes the payload → **Watchdog** → **PolicyEngine**.  
4. On BLOCK/QUARANTINE (or fail-closed), stdout returns Claude’s deny JSON (`permissionDecision: deny`).  
5. Claude **does not execute** the tool. Evidence is stored under `.veyra/`.  
6. Empty stdout on allow — Claude continues its normal permission flow.

Fail-closed: malformed PreToolUse JSON and evaluation errors **deny**.  
Details: [`docs/HOOK_PROTOCOL.md`](docs/HOOK_PROTOCOL.md).

---

## Attack lab

```bash
pnpm veyra attack --mode=simulation   # synthetic corpus (default; also: --ci)
pnpm veyra attack --mode=hook         # real PreToolUse wire format via veyra hook
pnpm veyra attack --mode=runtime      # live Claude Code only — never fakes success
```

| Mode | What it exercises | What it is not |
|------|-------------------|----------------|
| **simulation** | Synthetic `AgentEvent`s through PolicyEngine, Watchdog, trajectories, and the state machine | Not a live Claude session |
| **hook** | Real PreToolUse hook path (tool request shape → VEYRA → deny). First scenario: `prompt-injection-secret-access` | Not a live Claude session; does **not** use `simulateEvent()` |
| **runtime** | Live Claude Code attempting the attack; honest UNAVAILABLE if Claude missing | Never fakes live success |

Never label simulation or hook results as runtime.

---

## Security limitations

VEYRA currently provides **user-space enforcement through integrated agent hooks** (Claude Code / Codex PreToolUse and related events).

It does **not** protect against:

- Compromised operating systems  
- Privileged bypass  
- Kernel attacks  
- Agents outside integrated hooks  
- Malicious processes outside VEYRA  

It also does not replace OS sandboxes, network gateways, or identity systems.

**Do not claim complete AI security.**

Full model: [`docs/threat-model.md`](docs/threat-model.md).

---

## Commands

| Command | Purpose |
|---------|---------|
| `veyra init` | Create local `.veyra/` security plane |
| `veyra demo` | Product demo — prompt injection → secret access → BLOCK |
| `veyra bridge install\|status\|uninstall` | Claude Code / Codex live hooks |
| `veyra hook` | Stdin hook processor (used by the bridge) |
| `veyra attack --mode=simulation\|runtime` | Attack lab |
| `veyra explain [session]` | Incident timeline / last report |
| `veyra watch` / `events` / `policy` / `status` | Observe |
| `veyra quarantine` / `resume` | Operator session controls |

Operator runbook: [`docs/OPERATOR.md`](docs/OPERATOR.md).  
Milestone gates: [`docs/MILESTONE_GATES.md`](docs/MILESTONE_GATES.md).

---

## Roadmap (not implemented)

Planned directions — **interfaces or design only today; do not claim these ship**:

- Passport / Visa / Authority Chain / Trust Network  
- External enforcement daemon  
- Stronger sandbox / syscall boundary  
- Network gateway  
- Multi-agent authority  
- Cloud fleet management  

---

## Development

```bash
pnpm typecheck && pnpm lint && pnpm test && pnpm build
```

CI runs install → typecheck → lint → build → test without Claude credentials.  
Optional live runtime tests: `VEYRA_RUNTIME_TESTS=1` (requires Claude CLI).

Stack: TypeScript, pnpm, Turborepo, Zod, Vitest, SQLite, Next.js dashboard (local read-only).

Naming note: remaining `jev` / `.jev` strings are intentional (external TypeSafe Jev model slug, legacy path compat). See [`docs/BACK_COMPAT_JEV.md`](docs/BACK_COMPAT_JEV.md).

---

## License

Proprietary / TBD.
