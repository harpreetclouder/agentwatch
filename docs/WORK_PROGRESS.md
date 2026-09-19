# Work Progress — VEYRA Watchdog

## Current stage

**Stage 16 — Baseline audit & brand consistency** (complete)

Do **not** start next-stage runtime enforcement work from this doc alone — wait for explicit go-ahead.

## Done this stage

- Audited monorepo layout (`apps/cli`, `apps/dashboard`, `@veyra/*` packages). **No `packages/security`** (capabilities live in policy-engine / storage / watchdog).
- Classified remaining `jev` / `JEV` / `.jev` hits; renamed product brand to **VEYRA** / `@veyra/*` / `veyra` / `.veyra`.
- Left **TypeSafe Jev** (`~typesafe/jev-latest`, `TypesafeJev*`) as external model name.
- Left workspace path `/Users/macbook/jev` and historical `*.jev-backup*` alone.
- Legacy `.jev` still detected by security-plane classifier + gitignored.
- Baseline: `pnpm install` · `typecheck` · `lint` · `test` · `build` — all green.

## Verify

```bash
CI=true pnpm install && pnpm typecheck && pnpm lint && pnpm test && pnpm build
pnpm veyra help
pnpm veyra attack --mode=simulation
pnpm veyra attack --mode=runtime
```

## Next (blocked until requested)

Real runtime enforcement hardening per `docs/REAL_ENFORCEMENT_PLAN.md` (plan partially stale — fail-closed / demo / redact / runtime attack already present).
Passport/Visa, cloud, new policies, dashboard features — out of scope until asked.
