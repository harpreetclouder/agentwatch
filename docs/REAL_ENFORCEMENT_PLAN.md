# Real local enforcement — status

User-space hooks (Claude Code / Codex PreToolUse) → `veyra hook` → Watchdog → PolicyEngine → deny/quarantine.
Not an OS sandbox. A jailbreak must never become authority.

## Already in place

- Claude/Codex adapters + bridge install/uninstall
- Fail-closed malformed PreToolUse JSON
- Quarantine freeze gate + operator `quarantine` / `resume`
- Path helpers use `path.relative` / canonicalize (not naive substring containment)
- Redaction helpers (`packages/policy-engine/src/redact.ts`)
- `veyra attack --mode=runtime`, `veyra demo`, `examples/real-agent-demo`
- Hook protocol tests (deny, fail-closed, quarantine persists, secret not echoed)
- `docs/threat-model.md`
- Session-aware `veyra explain <session-id>` (falls back to last attack report)

## Remaining gaps (next stages — do not start until requested)

1. Harder path authority edge cases (symlink races, weird tool arg shapes)
2. Stronger network/shell authority beyond current heuristics
3. Broader live-agent proof beyond controlled demo/runtime attack
4. Passport / Visa issuance (types exist; runtime not implemented)
5. Cloud / multi-tenant control plane

## Out of scope until asked

Cloud infra, dashboard feature work, new policy packs, Trust Network
