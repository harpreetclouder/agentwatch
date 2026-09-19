# Stage 14 — Real local enforcement (internal plan)

## Reuse

- Claude/Codex adapters + `normalizeClaudeCodeEvent`
- `veyra hook` / `veyra bridge` / Watchdog / PolicyEngine / SQLite plane
- SECRET_ACCESS + classifySecretPath; quarantine freeze gate
- Existing hook integration tests (`apps/cli/tests/hook.test.ts`)

## Gaps (block real enforcement)

1. Hook **fail-open** on malformed PreToolUse JSON
2. Path allow/deny uses **substring** matching (`includes`/`endsWith`)
3. No proof harness that `.env` bytes were never read
4. `veyra explain` only reads last attack report, not live sessions
5. No `attack --mode=runtime` / `veyra demo` / `examples/real-agent-demo`
6. Network/shell authority incomplete; no redaction helpers; no threat-model doc

## Modify

- `packages/policy-engine/src/paths.ts` (+ tests)
- `packages/policy-engine/src/policies/{secret,credential,task-scope,network,dangerous-shell}*`
- `packages/agent-events/src/context.ts` (ResourceScope)
- `apps/cli/src/commands/{hook,explain,attack,bridge}.ts` + new `demo.ts`
- `apps/cli/src/bridge/install.ts` (backup before write)
- `packages/shared` or policy-engine: redaction
- README, `docs/threat-model.md`, `docs/WORK_PROGRESS.md`

## New (required)

- `examples/real-agent-demo/**`
- `packages/attack-engine` or CLI: `createTestWorkspace` harness
- Hook protocol tests: fail-closed, quarantine persists, `.env` unread
- `scripts/demo-real-agent` via `veyra demo`

## Out of scope (this milestone)

Cloud, auth dashboard redesign, Passport/Visa/Trust Network, full sandbox/OS boundary
