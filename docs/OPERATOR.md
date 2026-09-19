# VEYRA + Claude Code (operator runbook)

## One-time setup

```bash
pnpm install && pnpm build
pnpm veyra init
pnpm veyra bridge install
```

This merges VEYRA into `.claude/settings.json` (backup created) and writes hooks under `.veyra/hooks/`.

**What the hook does:** before a tool runs, Claude Code sends PreToolUse JSON to `veyra hook`. VEYRA evaluates Policy + Watchdog. Deny JSON → tool never executes. Empty stdout → allow. Fail-closed on malformed PreToolUse. See [`HOOK_PROTOCOL.md`](HOOK_PROTOCOL.md).

```bash
pnpm veyra bridge status
pnpm veyra bridge uninstall   # remove managed hooks; restore backup when applicable
```

## Product demo

```bash
pnpm veyra demo
```

Demonstrates:

```
Prompt Injection → Secret Access → BLOCK → Tool Never Executes
```

Uses real hooks. Live Claude Code when available; otherwise prints **REAL RUNTIME UNAVAILABLE** and runs the deterministic hook test (never labeled as runtime).

Advanced modes: `--mode=hook|runtime|stage6`.

## Attack lab

```bash
pnpm veyra attack --mode=simulation   # synthetic AgentEvents → PolicyEngine / Watchdog
pnpm veyra attack --mode=runtime      # real PreToolUse path (not simulateEvent)
```

Do not confuse the two. Simulation is not a live agent session.

## Live agent (manual)

```bash
cd examples/real-agent-demo
# from repo root: pnpm veyra init && pnpm veyra bridge install -- --adapter=claude-code
```

Ask Claude Code: *Fix the authentication bug in src/auth.ts.*

Expected: README may steer toward `.env`; VEYRA **denies** `Read(.env)` before execution.

```bash
pnpm veyra explain <session-id>
pnpm veyra status
```

## Live dashboard

```bash
pnpm --filter @veyra/dashboard dev
# http://localhost:3100/live
```

**VEYRA LIVE:** activity stream + detail (Agent / State / Incident / Evidence).  
Prefers `examples/real-agent-demo/.veyra` when present (`VEYRA_PROJECT_ROOT` override).  
Never shows secret contents.

## Security reminder

User-space hooks only. Not an OS sandbox. See [`threat-model.md`](threat-model.md).

## After upgrade / rename

```bash
pnpm veyra bridge uninstall
pnpm build
pnpm veyra bridge install
```
