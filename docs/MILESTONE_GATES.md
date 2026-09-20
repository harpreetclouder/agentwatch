# Milestone gates (Stages A–J + Credibility P1–P8)

Official gap-closure checklist (A–J) is complete. Credibility roadmap P1–P8 is **complete**.

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
STAGE G  Trajectory + quarantine across steps
   ↓
STAGE H  Runtime Attack Lab
   ↓
STAGE I  Security report + CI
   ↓
STAGE J  One-command developer experience
   ↓
P1 … P8  Runtime credibility (gap-fill) — DONE
```

**Plan:** [`docs/superpowers/plans/2026-09-20-veyra-runtime-credibility.md`](superpowers/plans/2026-09-20-veyra-runtime-credibility.md)  
**Current focus:** Credibility track **complete** (P1–P8).

## Gate status (A–J)

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

## Credibility gates (P1–P8)

| Priority | Gate | Status |
|----------|------|--------|
| **P1** | Modes distinct; no silent runtime→hook; REAL RUNTIME UNAVAILABLE + tip | **DONE** |
| **P2** | LiveAgentRunner + ClaudeCodeRunner | **DONE** |
| **P3** | Canonical auth-bug task; README injection only | **DONE** |
| **P4** | RuntimeAttackProof 12 gates → CONTAINED | **DONE** |
| **P5** | hook-trajectory-proof + live-trajectory-attack | **DONE** |
| **P6** | Viral `veyra attack` front door; no fake runtime | **DONE** |
| **P7** | LIVE UI matches ops log | **DONE** |
| **P8** | Shareable human / --json / --html | **DONE** |

## Re-verify

```bash
pnpm install && pnpm typecheck && pnpm lint && pnpm test && pnpm build
pnpm veyra attack --ci
pnpm veyra report --json
pnpm veyra report --html --out=/tmp/veyra-report.html
# Optional live Claude:
VEYRA_RUNTIME_TESTS=1 pnpm --filter veyra exec vitest run tests/stage9-runtime.test.ts
```

See [`REAL_ENFORCEMENT_PLAN.md`](REAL_ENFORCEMENT_PLAN.md), [`BACK_COMPAT_JEV.md`](BACK_COMPAT_JEV.md), [`WORK_PROGRESS.md`](WORK_PROGRESS.md).
