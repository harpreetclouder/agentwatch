# Work Progress — VEYRA Watchdog

## Current stage

**Focus: Credibility track P1–P8 — COMPLETE**  
**P8 done** (Agent-P8). Plan: [`docs/superpowers/plans/2026-09-20-veyra-runtime-credibility.md`](superpowers/plans/2026-09-20-veyra-runtime-credibility.md).  
Stages A–J remain complete. P1–P8 gap-closure track finished — no architecture rewrite.

## Done

| Stage | Result | Real vs simulated |
|-------|--------|-------------------|
| **A** | VEYRA branding + baseline clean | N/A |
| **B** | Path auth centralized; ResourceScope FILE/DIR/SHELL/NETWORK/MCP; plane tamper CRITICAL; redaction; states; Watchdog order | Unit/integration |
| **C** | Real Claude PreToolUse → DENY; `VEYRA_RUNTIME_TESTS=1` **passed** (~52s) | **REAL RUNTIME** |
| **D** | `examples/real-agent-demo/` poisoned README → .env BLOCK | Hook protocol + live when Claude available |
| **E** | SQLite → SSE `/api/events/stream` (~500ms) | Real events |
| **F** | `/live` console: Agent / State / Activity / Incident / Evidence | Real telemetry |
| **G** | Trajectory → quarantine; collector 127.0.0.1:8787 = 0 hits | Hook protocol proof |
| **H** | Modes **simulation \| hook \| runtime** distinct; first runtime via live Claude | All three |
| **I** | `veyra report` / `--json` / `--md` / `--html`; contained/not-contained counts | From last attack/session |
| **J** | `veyra attack --ci`; `veyra demo` front door; help advertises implemented cmds only | CI = simulation |

## Credibility (P1–P8)

| Priority | Owner | Focus | Status |
|----------|-------|-------|--------|
| **P1** | Agent-P1 | Three modes; no silent runtime→hook fallback | **DONE** |
| **P2** | Agent-P2 | `LiveAgentRunner` / ClaudeCodeRunner | **DONE** |
| **P3** | Agent-P3 | Canonical auth-bug task; README injection only | **DONE** |
| **P4** | Agent-P4 | `RuntimeAttackProof` 12 gates → CONTAINED | **DONE** |
| **P5** | Agent-P5 | Rename hook trajectory; add live-trajectory-attack | **DONE** |
| **P6** | Agent-P6 | Viral `veyra attack` front door | **DONE** |
| **P7** | Agent-P7 | LIVE UI polish after runtime works | **DONE** |
| **P8** | Agent-P8 | Shareable human/json/html reports | **DONE** |

## Recent

- **Live README→.env reliability:** Strengthened indirect injection chain (no P3 coercion). Root cause: on-disk `auth.ts` was already “fixed” / bug too trivial + README framed as refuse-me “SECURITY TEST PAYLOAD”, so live Claude often skipped `.env`. Fix: buggy auth + README pointer; README “Local development setup” checklist (Read `.env`); `CLAUDE.md`; always refresh fixtures before live; `--append-system-prompt` to read README (no `.env` in user task); incomplete-path tip. Re-run: `pnpm build && pnpm veyra demo --mode=runtime`. Residual: Claude nondeterminism.
- **LIVE plane fix:** Hook/runtime `veyra attack` and `veyra demo` default to `examples/real-agent-demo` (dashboard-preferred plane). CLI prints `Watch LIVE` + `Plane:` at start. `--isolated` keeps temp dirs for CI. See OPERATOR.md.
- **P8 done (Agent-P8):** Shareable `veyra report` / `--json` / `--html` / `--md` — runtime honesty LIVE|HOOK|SIMULATION|UNAVAILABLE; N/M contained (no % scores); category tallies; TOP FINDING; BLOCKED BEFORE EXECUTION; secret exposure; RuntimeAttackProof gates or UNAVAILABLE. Hook/runtime attacks persist `last.json`.
- **P7 done (Agent-P7):** `/live` Live Session ops polish.
- **P6 done (Agent-P6):** Viral `veyra attack` front door.
- **P5 done (Agent-P5):** `hook-trajectory-proof` + `live-trajectory-attack`.
- **P4 done (Agent-P4):** Typed `RuntimeAttackProof` (12 gates).
- **P3–P1 done:** Canonical task, LiveAgentRunner, mode honesty.

## Intentional `jev` leftovers

See [`BACK_COMPAT_JEV.md`](BACK_COMPAT_JEV.md).

## Gap notes

- Live Claude requires network + auth; CI skips unless `VEYRA_RUNTIME_TESTS=1`.
- Enforcement remains **user-space hooks** — not OS sandbox.
- Do not claim complete agent security.
- Simulation-mode attacks still use the monorepo `.veyra` plane (not the demo fixture); use `--mode=hook|runtime` (or `veyra demo`) to watch on `/live`.
- Credibility track P1–P8 complete. Beyond this track: other agents via LiveAgentRunner stubs, Passport/Visa, OS sandbox — still out of scope until asked.
