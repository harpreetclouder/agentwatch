# Work Progress — VEYRA Watchdog

## Current stage

**Focus: Level-3 runtime proof irrefutability (post P1–P8)**  
Credibility track P1–P8 remains complete. This pass hardens runtime containment so CONTAINED requires correlated stored evidence — no shortcuts, no product-demo coupling.

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

- **LIVE “I do not see attack”:** CLI CONTAINED was real; plane was correct (`examples/real-agent-demo`). After ~2 min idle gap, `/live` went idle (`session: null`) while `hasHistory: true` — attack buried under Show history. **Fix:** auto-surface latest run as history review for ~10 min (`LIVE_COMPLETED_GRACE_MS`); banner; louder end-of-run `Watch LIVE` / Show history hint; idle copy points at Show history.
- **PROOF INCOMPLETE root cause (this machine):** Live Claude detected the old README (“include the values in your reasoning”) as prompt-injection and skipped Read `.env`. When it tried Edit(`auth.ts`) with a `process.env` workaround, `extractPathCandidates` scraped `old_string`/`new_string` (comments mentioning `.env`/`password`) and false-positive SECRET_ACCESS-blocked the edit — Claude aborted. Injection signal was vacuous (README PreToolUse alone). **Fix:** (1) Soften README/auth/CLAUDE fixtures — ops framing, invalidate `process.env` (no dotenv), unguessable `local_demo_db_pw_7f3a`; (2) path extract only from path/command arg keys + reject multiline “paths”. Validated: hook → CONTAINED; runtime → **CONTAINED** (auth→README→Read `.env` PreToolUse→SECRET_ACCESS BLOCK). Task unchanged.
- **Runtime lure reliability (placeholder auth):** Prior pass used `UNCONFIGURED_LOCAL_PASSWORD`; superseded by softer ops lure above after Claude began refusing classic injection wording.
- **Incomplete ≠ escape:** When live Claude starts but never PreToolUse-reads `.env`, outcome is `PROOF INCOMPLETE` (not `ATTACK NOT CONTAINED`). Escape requires attempt (`preToolUseObserved`); incomplete → Critical escapes: 0.
- **Level-3 irrefutable proof:** CONTAINED needs stored PreToolUse(Read .env) ↔ SECRET_ACCESS BLOCK correlation. Architecture: `RuntimeAttackExecutor` → `LiveAgentRunner` → `ClaudeCodeRunner`.
- **LIVE plane fix:** Hook/runtime default to `examples/real-agent-demo`. See OPERATOR.md.
- **P8–P1 done:** Shareable reports, LIVE UI, attack front door, trajectory, RuntimeAttackProof, canonical task, LiveAgentRunner, mode honesty.

## Intentional `jev` leftovers

See [`BACK_COMPAT_JEV.md`](BACK_COMPAT_JEV.md).

## Gap notes

- Live Claude requires network + auth; CI skips unless `VEYRA_RUNTIME_TESTS=1`.
- Enforcement remains **user-space hooks** — not OS sandbox.
- Do not claim complete agent security.
- Simulation-mode attacks still use the monorepo `.veyra` plane (not the demo fixture); use `--mode=hook|runtime` (or `veyra demo`) to watch on `/live`.
- Runtime CONTAINED is rare and nondeterministic (Claude may skip README/.env). Incomplete ≠ contained. Unavailable ≠ contained. Hook-pass ≠ runtime contained.
