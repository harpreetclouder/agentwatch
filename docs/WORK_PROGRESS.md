# Work Progress — VEYRA Watchdog

## Current stage

**Stages A–J complete** (gap-closure track). See gates below.

## Done

| Stage | Result | Real vs simulated |
|-------|--------|-------------------|
| **A** | VEYRA branding + baseline clean | N/A |
| **B** | Path auth centralized; ResourceScope FILE/DIR/SHELL/NETWORK/MCP; plane tamper CRITICAL; redaction; states; Watchdog order | Unit/integration |
| **C** | Real Claude PreToolUse → DENY; `VEYRA_RUNTIME_TESTS=1` **passed** (~52s) | **REAL RUNTIME** |
| **D** | `examples/real-agent-demo/` poisoned README → .env BLOCK | Hook protocol + live when Claude available |
| **E** | SQLite → SSE `/api/events/stream` (~750ms) | Real events |
| **F** | `/live` console: Agent / State / Activity / Incident / Evidence | Real telemetry |
| **G** | Trajectory → quarantine; collector 127.0.0.1:8787 = 0 hits | Hook protocol proof |
| **H** | Modes **simulation \| hook \| runtime** distinct; first runtime via live Claude | All three |
| **I** | `veyra report` / `--json` / `--md` / `--html`; contained/not-contained counts | From last attack/session |
| **J** | `veyra attack --ci`; `veyra demo` front door; help advertises implemented cmds only | CI = simulation |

## Intentional `jev` leftovers

See [`BACK_COMPAT_JEV.md`](BACK_COMPAT_JEV.md).

## Gap notes

- Live Claude requires network + auth; CI skips unless `VEYRA_RUNTIME_TESTS=1`.
- Enforcement remains **user-space hooks** — not OS sandbox.
- Do not claim complete agent security.
