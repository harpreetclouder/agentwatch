# Real local enforcement — status

User-space hooks (Claude Code / Codex PreToolUse) → `veyra hook` → Watchdog → PolicyEngine → deny/quarantine.
Not an OS sandbox. A jailbreak must never become authority.

## Stage 1–4 complete

- Path auth, quarantine, redaction, state machine, Watchdog order
- Claude PreToolUse bridge + real-agent demo
- Real-time telemetry SSE/poll over SQLite

## Stage 5 complete

- VEYRA LIVE Split Board (`/live`): selectable stream + detail pane
- Auto-updates from live plane; click-to-inspect; never shows secret contents

## Remaining gaps (later stages — do not start until requested)

1. Stronger network/shell heuristics beyond current rules
2. Passport / Visa issuance (types exist; runtime not implemented)
3. Cloud / multi-tenant control plane

## Out of scope until asked

Cloud infra, enterprise analytics, billing, user management, new policy packs
