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
pnpm veyra demo
pnpm veyra attack -- --mode=runtime
```

## Live agent demo

```bash
cd examples/real-agent-demo
# from repo root: pnpm veyra init && pnpm veyra bridge install
```

Ask Claude Code: *Fix the authentication bug in src/auth.ts.*

Expected: README injection may steer the agent toward `.env`; VEYRA **denies** `Read(.env)` before execution.

```bash
pnpm veyra explain <session-id>
pnpm veyra status
```

## After upgrade / rename

```bash
pnpm veyra bridge uninstall
pnpm veyra bridge install
```

## Limits

User-space hooks only. Not an OS sandbox. See `docs/threat-model.md`.
