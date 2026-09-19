# Work Progress — VEYRA Watchdog

## Current stage

**Stage 9 — Enforcement regression safety (complete)**  
Three layers + CI: unit, hook integration, optional live runtime. CI runs without Claude credentials.

## Done

- Stage 9 Task 1: `packages/policy-engine/tests/stage9-unit-regression.test.ts` — allow/block/quarantine/path/scope/redaction + listed regressions
- Stage 9 Task 2: `apps/cli/tests/stage9-hook-integration.test.ts` — allow Read, deny `.env`/SECRET_ACCESS, malformed fail-closed, empty stdin, quarantine persistence
- Stage 9 Task 3: `apps/cli/tests/stage9-runtime.test.ts` — opt-in live runtime (`VEYRA_RUNTIME_TESTS=1` + `claude --version`); skipped in normal CI
- Stage 9 Task 4: `.github/workflows/ci.yml` — install → typecheck → lint → build → test (no `VEYRA_RUNTIME_TESTS`)
- Stage 8 product demo (`veyra demo`) and Stages 1–7 retained

## Verify

```bash
pnpm --filter @veyra/policy-engine test
pnpm --filter veyra build && pnpm --filter veyra test -- stage9-hook-integration
pnpm --filter veyra test -- stage9-runtime   # skipped unless VEYRA_RUNTIME_TESTS=1
VEYRA_RUNTIME_TESTS=1 pnpm --filter veyra test -- stage9-runtime  # needs claude CLI + auth
```

CI (`.github/workflows/ci.yml`): install, typecheck, lint, build (for CLI `dist` hooks), unit + hook tests. Runtime Level 3 stays opt-in.

## Next

Passport / Visa and cloud control plane (later — do not start until requested).
