# Milestone gates

Official product milestone checklist. Each gate must pass before the next stage.

```
STAGE 0
   ↓
BUILD CLEAN?
   ↓
YES
   ↓
STAGE 1
   ↓
SECURITY TESTS PASS?
   ↓
YES
   ↓
STAGE 2
   ↓
REAL HOOK WORKS?
   ↓
YES
   ↓
STAGE 3
   ↓
REAL .ENV BLOCKED?
   ↓
YES
   ↓
STAGE 4
   ↓
REAL-TIME EVENT STREAM?
   ↓
YES
   ↓
STAGE 5
   ↓
LIVE DASHBOARD?
   ↓
YES
   ↓
STAGE 6
   ↓
TRAJECTORY + QUARANTINE?
   ↓
YES
   ↓
STAGE 7
   ↓
RUNTIME ATTACK LAB?
   ↓
YES
   ↓
STAGE 8
   ↓
ONE COMMAND DEMO?
   ↓
YES
   ↓
STAGE 9
   ↓
REGRESSION SAFE?
   ↓
YES
   ↓
STAGE 10
   ↓
PRESENTATION READY
```

## Gate status

| Stage | Gate | Status |
|-------|------|--------|
| 0 | Build clean (`typecheck` / `lint` / `build`) | YES |
| 1 | Security tests pass (PolicyEngine / unit) | YES |
| 2 | Real hook works (PreToolUse → `veyra hook`) | YES |
| 3 | Real `.env` blocked before execution | YES |
| 4 | Real-time event stream | YES |
| 5 | LIVE dashboard | YES |
| 6 | Trajectory + quarantine | YES |
| 7 | Runtime attack lab (`--mode=runtime`) | YES |
| 8 | One-command demo (`veyra demo`) | YES |
| 9 | Regression safe (L1/L2 + CI; optional L3) | YES |
| 10 | Presentation ready (honest product docs) | YES |

**Milestone:** PRESENTATION READY

## How to re-verify

```bash
pnpm typecheck && pnpm lint && pnpm test && pnpm build   # 0–1, 9
pnpm veyra bridge status                                  # 2
pnpm veyra demo                                           # 3, 8
pnpm veyra attack --mode=runtime                          # 7
# LIVE: pnpm --filter @veyra/dashboard dev → /live        # 4–5
# Stage 6: veyra demo --mode=stage6                       # 6
```

See [`REAL_ENFORCEMENT_PLAN.md`](REAL_ENFORCEMENT_PLAN.md) and [`WORK_PROGRESS.md`](WORK_PROGRESS.md).
