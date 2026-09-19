# Real local enforcement — status

User-space hooks (Claude Code / Codex PreToolUse) → `veyra hook` → Watchdog → PolicyEngine → deny/quarantine.
Not an OS sandbox. A jailbreak must never become authority.

## Stage 1 complete (deterministic boundary)

- Canonical path auth: `canonicalizePath`, `resolveSafePath`, `isPathInside`, `isPathAllowed`, `isPathDenied`, `matchesResourceScope`
- FS policies use path utilities (no substring path authorization)
- Security-plane access → CRITICAL / QUARANTINE
- Evidence/reason redaction on persist
- State machine: LOW/MEDIUM→WARNING, HIGH→RESTRICTED, CRITICAL→QUARANTINED; quarantine persists
- Watchdog order: policy → trajectory → advisory semantic (semantic never grants authority)

## Remaining gaps (later stages — do not start until requested)

1. Stronger network/shell heuristics beyond current rules
2. Passport / Visa issuance (types exist; runtime not implemented)
3. Cloud / multi-tenant control plane
4. Live Claude demo requires authenticated `claude` CLI (`veyra demo --mode=runtime`)

## Out of scope until asked

Cloud infra, dashboard feature work, new policy packs, Trust Network
