# JEV WATCHDOG

Security control plane for autonomous AI agents.

```
See what your agent does.
Understand why.
Stop it when it crosses its authority.
```

**Core thesis:** a jailbreak should never become authority.

Agent intelligence ≠ agent authority. The agent may decide what it wants;
Jev independently decides what it is allowed to do.

---

## Positioning

Jev is **agent observability + authority + security enforcement** — not a prompt filter, LLM firewall, or AI safety classifier.

Developer-facing framing:

> Datadog for agent behavior, with security enforcement.

(Not a claim that Jev is Datadog or CrowdStrike.)

---

## Quick start (Stage 1)

```bash
pnpm install
pnpm build
pnpm test

# CLI (after build)
pnpm --filter @jev/cli start status
pnpm --filter @jev/cli start help
# or: pnpm jev status
```

`npx jev attack` is the product wedge. Stage 4 ships the local CLI equivalent:

```bash
pnpm --filter @jev/cli start attack
pnpm --filter @jev/cli start explain
```

No cloud account or API key required for deterministic security features.

Optional advisory LLM — TypeSafe [Jev Latest](https://openrouter.ai/~typesafe/jev-latest) via OpenRouter
**Decisions API** (`POST /api/alpha/decisions` — not chat completions).
Deterministic policies still enforce; the model never grants authority:

```bash
export OPENROUTER_API_KEY=sk-or-...
# defaults: ~typesafe/jev-latest @ https://openrouter.ai/api/alpha/decisions
pnpm --filter @jev/cli start policy
pnpm --filter @jev/cli start watch -- --stdin --adapter=claude-code < examples/claude-code-hooks.jsonl
```

Local dashboard (after `pnpm build`):

```bash
pnpm --filter @jev/dashboard start
# http://127.0.0.1:3100
```

---

## Architecture (target)

```
Agent
  → Adapter
  → Event Normalizer
  → Policy Engine
  → Watchdog
  → Enforcement
  → Evidence
  → Dashboard / CLI
```

Long-term product line:

```
Agent Passport  →  Agent Visa  →  Agent Watchdog / Police
        →  Agent Trust Network  →  Agent Authority Infrastructure
```

| Concept | Answers | MVP status |
|---------|---------|------------|
| **Passport** | Who is this agent? | Interface stub only |
| **Visa** | What is it authorized to do? | Interface stub + `AgentContext` precursor |
| **Watchdog** | Is it within authority? | Not implemented yet |
| **Authority chain** | Who granted it? | Designed, not built |
| **Trace / evidence** | What happened? | Event schema foundation |
| **Progressive enforcement** | What after a violation? | Not implemented yet |

---

## Repository layout (Stage 1)

```
jev/
├── apps/
│   ├── cli/                  # Developer CLI (jev)
│   └── dashboard/            # Local Next.js observability UI
├── packages/
│   ├── agent-events/         # Universal AgentEvent schema (Zod)
│   ├── shared/               # Shared primitives (severity, ids)
│   ├── storage/              # Repository interfaces + SQLite
│   ├── policy-engine/        # Deterministic security policies
│   ├── attack-engine/        # Controlled attack lab + reports
│   ├── watchdog/             # Session correlation + trajectories
│   └── adapters/
│       ├── core/             # AgentAdapter interface
│       ├── claude-code/      # Claude Code normalizer
│       └── codex/            # Codex normalizer
├── docs/
├── attacks/
└── examples/
```

Planned packages (not yet created): `security`.

---

## Commands (planned)

| Command | Purpose | Stage 1 |
|---------|---------|---------|
| `jev init` | Local `.jev/` security plane | implemented |
| `jev watch` | Observe agent activity | Claude + Codex adapters + `--stdin` JSONL |
| `jev bridge` | Install live Claude Code / Codex hooks | `install` / `uninstall` / `status` |
| `jev hook` | Process one hook event (stdin) | Used by installed bridge scripts |

| `jev attack` | Controlled attack lab | 10-scenario corpus; `--list` / `--id=` |
| `jev explain` | Evidence-based report | last attack report |
| `jev status` | Session / enforcement status | reads SQLite |
| `jev events` | List events | reads SQLite |
| `jev policy` | Inspect policies | lists active rules |
| `jev quarantine` / `resume` | Enforcement controls | operator quarantine / resume |

---

## Development

```bash
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

Stack: TypeScript, Node.js, pnpm, Turborepo, Zod, Vitest, ESLint, Prettier.

---

## Security boundary (honest)

Local MVP is a user-space control plane. A process with OS privileges can still bypass it. Production deployments should place enforcement outside the agent's trust boundary (separate process, sandbox, network gateway, or OS isolation).

We never claim “the agent is completely safe.” We claim **policy violations blocked** and **simulated attacks contained**.

---

## License

Proprietary / TBD.
