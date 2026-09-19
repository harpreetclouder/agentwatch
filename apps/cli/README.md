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
pnpm veyra demo                          # product demo
pnpm veyra bridge install|status|uninstall
pnpm veyra attack --mode=simulation      # synthetic PolicyEngine / Watchdog
pnpm veyra attack --mode=runtime         # real PreToolUse path (not simulateEvent)
```

## Hook path

```
Agent → PreToolUse → veyra hook → Policy → Watchdog → Enforcement → Evidence
```

Deny JSON on stdout = tool must not run. Empty stdout = allow.

See [`docs/HOOK_PROTOCOL.md`](../../docs/HOOK_PROTOCOL.md) and [`docs/threat-model.md`](../../docs/threat-model.md).

Do not claim complete AI security. User-space hooks only.
