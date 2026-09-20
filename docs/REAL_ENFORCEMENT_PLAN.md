# Real local enforcement — plan

User-space hooks (Claude Code / Codex PreToolUse) → `veyra hook` → Watchdog → PolicyEngine → deny/quarantine.  
Not an OS sandbox. A jailbreak must never become authority.

**Active milestone track:** Stages A–J — **complete**.

## Stage status

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

## Honest claims

- Success claim allowed when live Claude path exercised: blocked unauthorized tool before execution.
- Hook-protocol and simulation results must **not** be labeled as live runtime.
- Remaining `jev` strings are intentional only — [`BACK_COMPAT_JEV.md`](BACK_COMPAT_JEV.md).

## Out of scope until asked

Passport / Visa issuance, external daemon / OS sandbox / network gateway, cloud / multi-tenant control plane, billing, enterprise analytics
