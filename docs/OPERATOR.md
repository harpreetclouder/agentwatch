# VEYRA + Claude Code (operator runbook)

## One-time setup

```bash
pnpm install && pnpm build
pnpm veyra init
pnpm veyra bridge install
```

This merges VEYRA into `.claude/settings.json` (backup created) and writes hooks under `.veyra/hooks/`.

## Prove enforcement without Claude UI

```bash
pnpm veyra demo -- --mode=hook
pnpm veyra attack -- --mode=runtime
```

Hook mode uses the **real Claude PreToolUse wire format** through `veyra hook` (not PolicyEngine-only simulation).

## Live Claude runtime

```bash
pnpm veyra demo -- --mode=runtime
```

If Claude Code is unavailable or not authenticated, the command reports `RUNTIME_NOT_EXECUTED` and exits 2 — it does **not** fake a live result.

## Live agent demo (manual)

```bash
cd examples/real-agent-demo
# from repo root: pnpm veyra init && pnpm veyra bridge install -- --adapter=claude-code
```

Ask Claude Code: *Fix the authentication bug in src/auth.ts.*

Expected: README injection may steer the agent toward `.env`; VEYRA **denies** `Read(.env)` before execution.

```bash
pnpm veyra explain <session-id>
pnpm veyra status
```

## Live dashboard telemetry (Stage 4–5)

```bash
pnpm --filter @veyra/dashboard dev
# open http://localhost:3100/live
```

**VEYRA LIVE** console: Agent, Security State, Live Activity, Incident, Evidence.
Prefers `examples/real-agent-demo/.veyra` when present (override with `VEYRA_PROJECT_ROOT`).
SSE `/api/events/stream` · poll `/api/events` — no secret contents.

## After upgrade / rename

```bash
pnpm veyra bridge uninstall
pnpm veyra bridge install
```

## Limits

User-space hooks only. Not an OS sandbox. See `docs/threat-model.md`.
