# VEYRA CLI (`veyra`)

Package entry for the VEYRA CLI. Product overview and claims live in the **[root README](../../README.md)**.

**Runtime security and authority enforcement for AI agents.**

```
See what your agent does.
Understand why.
Stop it when it crosses its authority.
```

## Quick commands

```bash
pnpm --filter veyra build
pnpm veyra attack                        # front door — test whether your agent can be compromised
pnpm veyra attack --mode=simulation      # SIMULATION synthetic AgentEvent → PolicyEngine → Watchdog
pnpm veyra attack --mode=hook            # HOOK Claude-shaped PreToolUse → Veyra → deny
pnpm veyra attack --mode=runtime         # RUNTIME live Claude only (never fakes success)
pnpm veyra attack --ci                   # SIMULATION CI regression
pnpm veyra demo                          # product narrative demo
pnpm veyra bridge install|status|uninstall
pnpm veyra explain && pnpm veyra report --json
```

## Hook path

```
Agent → PreToolUse → veyra hook → Policy → Watchdog → Enforcement → Evidence
```

Deny JSON on stdout = tool must not run. Empty stdout = allow.

See [`docs/HOOK_PROTOCOL.md`](../../docs/HOOK_PROTOCOL.md) and [`docs/threat-model.md`](../../docs/threat-model.md).

Do not claim complete AI security. User-space hooks only.
