# Real local enforcement — plan

User-space hooks (Claude Code / Codex PreToolUse) → `veyra hook` → Watchdog → PolicyEngine → deny/quarantine.  
Not an OS sandbox. A jailbreak must never become authority.

**Active milestone track:** Stages A–J — **complete**.  
**Credibility track:** P1–P8 — **complete**.  
**Roadmap:** [`docs/superpowers/plans/2026-09-20-veyra-runtime-credibility.md`](superpowers/plans/2026-09-20-veyra-runtime-credibility.md) (gap-fill only).

## Stage status (A–J)

| Stage | Focus | Status |
|-------|--------|--------|
| **A** | Repository consistency + baseline | **YES** |
| **B** | Security boundary hardening | **YES** |
| **C** | Real Claude runtime enforcement | **YES** (live test passed) |
| **D** | Real indirect prompt injection | **YES** |
| **E** | Real-time security telemetry | **YES** |
| **F** | Security dashboard LIVE | **YES** |
| **G** | Multi-step attack trajectory | **YES** |
| **H** | Runtime Attack Lab (sim/hook/runtime) | **YES** |
| **I** | Security report + counts | **YES** |
| **J** | One-command DX + CI | **YES** |

## Credibility track (P1–P8)

| Priority | Focus | Status |
|----------|--------|--------|
| **P1** | Runtime definition — no silent runtime→hook fallback | **DONE** |
| **P2** | LiveAgentRunner abstraction | **DONE** |
| **P3** | Canonical indirect injection attack | **DONE** |
| **P4** | RuntimeAttackProof strict gates | **DONE** |
| **P5** | Real Stage-6 trajectory (hook rename + live) | **DONE** |
| **P6** | Viral `veyra attack` front door | **DONE** |
| **P7** | LIVE UI polish | **DONE** |
| **P8** | Shareable reports | **DONE** |

## Honest claims

- Success claim allowed when live Claude path exercised: blocked unauthorized tool before execution.
- Hook-protocol and simulation results must **not** be labeled as live runtime.
- Shareable reports use concrete N/M contained counts + runtime honesty — never % “secure” scores.
- Remaining `jev` strings are intentional only — [`BACK_COMPAT_JEV.md`](BACK_COMPAT_JEV.md).

## Out of scope until asked

Passport / Visa issuance, external daemon / OS sandbox / network gateway, cloud / multi-tenant control plane, billing, enterprise analytics
