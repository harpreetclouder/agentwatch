# Milestone gates (Stages A–J)

Official gap-closure checklist. Complete and verify each stage before the next.

```
STAGE A  Repository consistency + baseline
   ↓
STAGE B  Security boundary hardening
   ↓
STAGE C  Real Claude runtime enforcement
   ↓
STAGE D  Real indirect prompt injection
   ↓
STAGE E  Real-time security telemetry
   ↓
STAGE F  Security dashboard
   ↓
STAGE G  Multi-step attack trajectory
   ↓
STAGE H  Runtime Attack Lab
   ↓
STAGE I  Security report + CI
   ↓
STAGE J  One-command developer experience
```

## Gate status

| Stage | Gate | Status |
|-------|------|--------|
| A | VEYRA naming consistent; typecheck/lint/test/build clean | **YES** |
| B | Path auth centralized; plane tamper CRITICAL; redaction; quarantine persists | **YES** |
| C | Real Claude PreToolUse → deny before execute | **YES** (VEYRA_RUNTIME_TESTS=1 passed) |
| D | Real indirect injection demo (synthetic secrets) | **YES** |
| E | Real-time event stream | **YES** |
| F | LIVE security dashboard | **YES** |
| G | Trajectory + quarantine across steps | **YES** |
| H | Attack lab simulation \| hook \| runtime | **YES** |
| I | `veyra report` + concrete counts | **YES** |
| J | `veyra demo` / `veyra attack --ci` DX | **YES** |

**Current:** Stages A–J **YES**.

## Re-verify

```bash
pnpm install && pnpm typecheck && pnpm lint && pnpm test && pnpm build
pnpm veyra attack --ci
pnpm veyra report --json
# Optional live Claude:
VEYRA_RUNTIME_TESTS=1 pnpm --filter veyra exec vitest run tests/stage9-runtime.test.ts
```

See [`REAL_ENFORCEMENT_PLAN.md`](REAL_ENFORCEMENT_PLAN.md), [`BACK_COMPAT_JEV.md`](BACK_COMPAT_JEV.md), [`WORK_PROGRESS.md`](WORK_PROGRESS.md).
