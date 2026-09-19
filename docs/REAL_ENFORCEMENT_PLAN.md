# Real local enforcement — status

User-space hooks (Claude Code / Codex PreToolUse) → `veyra hook` → Watchdog → PolicyEngine → deny/quarantine.  
Not an OS sandbox. A jailbreak must never become authority.

**Milestone:** [PRESENTATION READY](MILESTONE_GATES.md) (Stages 0–10 gates YES)

## Stages 0–10 complete

| Stage | Gate |
|-------|------|
| 0 | Build clean |
| 1 | Security tests pass |
| 2 | Real hook works |
| 3 | Real `.env` blocked |
| 4 | Real-time event stream |
| 5 | LIVE dashboard |
| 6 | Trajectory + quarantine |
| 7 | Runtime attack lab |
| 8 | One-command demo |
| 9 | Regression safe |
| 10 | Presentation ready |

Full flowchart: [`MILESTONE_GATES.md`](MILESTONE_GATES.md).

## Remaining (later — do not start until requested)

1. Passport / Visa issuance (runtime)  
2. External enforcement daemon / sandbox / network gateway  
3. Cloud / multi-tenant control plane  

## Out of scope until asked

Cloud infra, enterprise analytics, billing, user management, new policy packs  
