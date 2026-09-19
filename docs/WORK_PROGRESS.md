# Work Progress — VEYRA Watchdog

## Current stage

**Stage 5 — VEYRA LIVE Split Board** (interactive redesign)

## Done

- `/live` Split Board: light stream (selectable) + dark detail (Agent / State / Incident / Evidence)
- Click row to inspect; auto-focus + pulse on new BLOCK; Esc clears lock
- Real SQLite SSE/poll only; no secret contents
- Fix: runtime demo forces real `.env` PreToolUse if agent skips; claim ignores README text false-positives
- Fix: live feed always polls for catch-up (SSE alone missed events after sqlite wipe)
- Fix: detail Mono contrast (IDs were invisible light-on-light)
- Fix: stale `dist/` missed forced `.env` PreToolUse; rebuild required for `pnpm veyra start`
- Fix: `.env PostToolUse` false positive from shell `find -name ".env*"`
- Fix: LIVE activity empty while session/RESTRICTED shown — `after=` cursor desynced from React state (HMR/race); cursor now derived from loaded events only

## Verify

```bash
pnpm --filter @veyra/dashboard test
pnpm --filter @veyra/dashboard dev
# http://localhost:3100/live
```

## Next

Wait for explicit go-ahead.
