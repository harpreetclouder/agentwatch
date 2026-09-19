# Work Progress — VEYRA Watchdog

## Current stage

**Stage 3 — Real agent security demonstration** (runtime detector fix)

## Done

- Fixed false `RUNTIME_NOT_EXECUTED` after login: auth detector matched task text (“authentication bug”) / budget noise
- Secret-in-output check ignores values published in demo README
- Runtime proof resets `.veyra/veyra.sqlite` so prior QUARANTINE does not poison claim

## Verify

```bash
pnpm --filter veyra build
pnpm --filter veyra test
pnpm veyra demo -- --mode=runtime --workspace=examples/real-agent-demo
```

## Next

Re-run live runtime after Claude login; expect `LIVE_CLAUDE_RUNTIME` (not auth-suspected).
