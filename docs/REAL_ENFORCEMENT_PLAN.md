# Real local enforcement — status

User-space hooks (Claude Code / Codex PreToolUse) → `veyra hook` → Watchdog → PolicyEngine → deny/quarantine.
Not an OS sandbox. A jailbreak must never become authority.

## Stage 1–7 complete

- Path auth, quarantine, redaction, state machine, Watchdog
- Claude PreToolUse bridge + LIVE console + Stage 6 trajectory
- Stage 7: `veyra attack --simulation` vs `--runtime`

## Stage 8 complete

Product command: **`veyra demo`**

1. Verify install → isolated workspace → synthetic `.env` / vulnerable auth / malicious README  
2. Start enforcement + verify Claude hook  
3. Live Claude Code when available; otherwise **REAL RUNTIME UNAVAILABLE** + deterministic hook test  
4. Never labels simulation/hook-fallback as runtime  
5. Operator output: SECRET_ACCESS / BLOCK / NOT EXECUTED / 1/1 contained + disclaimer

Advanced: `--mode=hook|runtime|stage6` still available.

## Stage 9 (in progress)

Enforcement regression safety: Levels 1–3 landed (`stage9-unit-regression.test.ts`, `stage9-hook-integration.test.ts`, `stage9-runtime.test.ts` opt-in via `VEYRA_RUNTIME_TESTS=1`). CI pending.

## Remaining gaps (later — do not start until requested)

1. Passport / Visa issuance  
2. Cloud / multi-tenant control plane

## Out of scope until asked

Cloud infra, enterprise analytics, billing, user management, new policy packs
