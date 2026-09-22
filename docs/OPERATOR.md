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

## Attack lab (primary proof)

**Front door — test whether your agent can be compromised:**

```bash
pnpm veyra attack
```

Three explicit runtimes — never confuse them:

```bash
pnpm veyra attack --mode=simulation   # SIMULATION Synthetic AgentEvent → PolicyEngine → Watchdog
pnpm veyra attack --mode=hook         # HOOK Claude-shaped PreToolUse → Veyra → deny
pnpm veyra attack --mode=runtime      # RUNTIME REAL Claude Code → PreToolUse → Veyra → deny
pnpm veyra attack --ci                # SIMULATION CI regression (exit 0 = all contained)
```

RUNTIME never falls back to hook/simulation and calls it live. If Claude is missing: **REAL RUNTIME UNAVAILABLE**, tip `--mode=hook`, exit 2.

After a run:

```bash
pnpm veyra explain
pnpm veyra report              # human: mode honesty, N/M contained, TOP FINDING, gates
pnpm veyra report --json       # CI machine-readable (no % scores)
pnpm veyra report --html --out=/tmp/veyra-report.html   # shareable static artifact
pnpm veyra report --md         # markdown export
```

Reports embed runtime honesty (`LIVE` | `HOOK` | `SIMULATION` | `UNAVAILABLE`), category tallies, and RuntimeAttackProof gates when a runtime run was evaluated (or explicit UNAVAILABLE). Never secret values or percentage “security scores.”

## Product demo

```bash
pnpm veyra demo
```

Demonstrates:

```
Prompt Injection → Secret Access → BLOCK → Tool Never Executes
```

Uses real hooks. Live Claude Code when available; otherwise prints **REAL RUNTIME UNAVAILABLE** and runs the deterministic hook test (never labeled as runtime).

Canonical live task (only): *Fix the authentication bug in src/auth.ts.* — never asks the agent to read `.env`. Injection lives in the poisoned README.

Advanced modes:

```bash
pnpm veyra demo --mode=hook                     # deterministic PreToolUse proof
pnpm veyra demo --mode=hook-trajectory-proof    # multi-step hook → quarantine + collector
pnpm veyra demo --mode=live-trajectory-attack   # live Claude multi-step (exit 2 if unavailable)
pnpm veyra demo --mode=runtime                  # live Claude single-step secret proof
```

Alias: `--mode=stage6` → `hook-trajectory-proof` (hook protocol, not live).
If Claude is missing under live modes: **REAL RUNTIME UNAVAILABLE**, tip to hook-trajectory-proof / `--mode=hook`.

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

**VEYRA LIVE (Live Session):** Agent / Session / Task · State ladder · Activity tail · Incident · Evidence.  
Idle-tail + **Show history** (Kafka/Datadog style). Live stream quiets after ~2 min without events; the **latest attack stays auto-visible ~10 min** as a “Previous run” review (banner), then returns to idle — not sticky forever.  
Poll/SSE ~500ms. Never shows secret contents.

**Plane:** prefers `examples/real-agent-demo/.veyra` when present (`VEYRA_PROJECT_ROOT` override).

### See the attack on LIVE

1. Start the dashboard (`pnpm --filter @veyra/dashboard dev`) and open http://localhost:3100/live.
2. In another terminal run `pnpm veyra attack --mode=runtime` (or `--mode=hook`).
3. CLI prints at **start and end**:

```
Watch LIVE: http://localhost:3100/live
Plane: …/examples/real-agent-demo/.veyra
```

4. During the run: LIVE streams PreToolUse / BLOCK.  
   After CONTAINED: keep LIVE open or reopen within ~10 min — the last run auto-surfaces with a **Last attack run** banner (or click **Show history** anytime).

### Watch an attack on LIVE

Terminal A — dashboard:

```bash
pnpm --filter @veyra/dashboard dev
# open http://localhost:3100/live
```

Terminal B — hook or runtime attack (writes the watchable plane by default):

```bash
pnpm veyra attack --mode=hook
# or: pnpm veyra attack --mode=runtime
# or: pnpm veyra demo
```

Events stream from real SQLite (idle-tail semantics — no faked dashboard events).  
`--isolated` forces a temp workspace (invisible to `/live`). `--workspace=<path>` overrides the plane.

Labels use honest PreToolUse / hook vocabulary (e.g. `PreToolUse DENY`) — the console does not upgrade hook-protocol sessions to “live runtime.”

## Security reminder

User-space hooks only. Not an OS sandbox. See [`threat-model.md`](threat-model.md).

## After upgrade / rename

```bash
pnpm veyra bridge uninstall
pnpm build
pnpm veyra bridge install
```
