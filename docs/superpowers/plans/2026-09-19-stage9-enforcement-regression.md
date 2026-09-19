# Stage 9 — Enforcement Regression Safety

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the real enforcement path regression-safe with three test layers + CI that never requires Claude credentials.

**Architecture:** Keep existing PolicyEngine / hook / runtime tests; add an explicit Stage 9 regression suite and GitHub Actions CI that runs install → typecheck → lint → unit → hook integration. Runtime (live Claude) is opt-in via env flag.

**Tech Stack:** vitest, turbo/pnpm, GitHub Actions

## Global Constraints

- Never require external Claude/API credentials for normal CI
- Runtime tests optional: skip unless `VEYRA_RUNTIME_TESTS=1` and `claude` CLI available
- Never fabricate runtime results
- Fail-closed on malformed PreToolUse
- Synthetic secrets only in fixtures (`veyra_fake_*`)
- Update `docs/WORK_PROGRESS.md` and `docs/REAL_ENFORCEMENT_PLAN.md` at end
- Do not claim complete agent security
- Prefer extending existing test files over duplicating identical cases; add missing regression cases
- Commit only Stage 9 files + docs in Stage 9 commits (Stages 6–8 may already be dirty on branch — include related test/CI work; do not revert prior stage work)

---

### Task 1: Level 1 — PolicyEngine unit regression suite

**Files:**
- Create: `packages/policy-engine/tests/stage9-unit-regression.test.ts`
- Modify (only if needed): existing policy helpers

**Steps:**
1. Write failing tests covering: ALLOW benign source; BLOCK `.env`; QUARANTINE dangerous shell / control-plane write; path authorization (`allowedPaths`/`deniedPaths`); resource scope; redaction of secret values in evidence/reasons.
2. Add regression cases: path traversal (`../.env`, `src/../../.env`), symlink-style escape targets (paths containing `..` and absolute secret paths), prefix confusion (`.env.bak` vs `notenv`, `foo.env` vs `.env`), security-plane tampering (write `.veyra/config.json`), quarantine state persistence via `nextSecurityState` + `isEnforcementFrozen` / session-control helpers, redaction of API keys/tokens.
3. Run `pnpm --filter @veyra/policy-engine test` — all pass.
4. Commit: `test(policy): Stage 9 Level 1 unit regression suite`

---

### Task 2: Level 2 — Hook integration + fail-closed regression

**Files:**
- Create: `apps/cli/tests/stage9-hook-integration.test.ts`
- May reuse helpers from `claude-pretooluse.test.ts` / `runtime-hook.test.ts` / `test-workspace.ts`

**Steps:**
1. Ensure CLI is built (`pnpm --filter veyra build`) before tests that spawn `dist/index.js`.
2. Tests with real Claude PreToolUse JSON:
   - Allowed: Read `src/auth.ts` → empty stdout, no deny
   - Denied: Read `.env` → `permissionDecision=deny`, `policy=SECRET_ACCESS`, no secret in stdout
3. Regression: malformed JSON fail-closed deny; empty stdin no-op exit 0; quarantine persistence (second tool after quarantine still denied with SESSION_QUARANTINED).
4. Run `pnpm --filter veyra test -- stage9-hook-integration` — pass.
5. Commit: `test(cli): Stage 9 Level 2 hook integration regression`

---

### Task 3: Level 3 — Optional runtime test

**Files:**
- Create: `apps/cli/tests/stage9-runtime.test.ts`

**Steps:**
1. Gate entire describe with: skip unless `process.env.VEYRA_RUNTIME_TESTS === '1'` AND `claude --version` succeeds.
2. When enabled: real agent path (or documented live PreToolUse via installed bridge) → block `.env` → assert `.env` fingerprint unchanged and secrets absent from output.
3. When disabled: suite skipped (CI green without credentials).
4. Commit: `test(cli): Stage 9 Level 3 optional live runtime`

---

### Task 4: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: root `package.json` scripts if helpful (`test:unit`, `test:hook` aliases optional — only if clean)
- Modify: `docs/WORK_PROGRESS.md`, `docs/REAL_ENFORCEMENT_PLAN.md`

**Steps:**
1. CI jobs: checkout → pnpm install → typecheck → lint → test (unit + hook via turbo/pnpm test). Do **not** set `VEYRA_RUNTIME_TESTS`.
2. Document runtime opt-in in WORK_PROGRESS / REAL_ENFORCEMENT_PLAN Stage 9 section.
3. Commit: `ci: Stage 9 install/typecheck/lint/unit/hook without Claude credentials`

---

## Acceptance

- [ ] Level 1 unit suite covers allow/block/quarantine/path/scope/redaction + listed regressions
- [ ] Level 2 hook suite covers allow + `.env` deny + malformed fail-closed
- [ ] Level 3 runtime optional / skipped in CI
- [ ] CI runs install, typecheck, lint, unit, hook integration
- [ ] No mandatory external credentials for normal CI
