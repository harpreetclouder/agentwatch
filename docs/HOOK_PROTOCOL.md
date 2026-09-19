# Claude Code hook protocol (VEYRA Stage 2)

Verified against https://code.claude.com/docs/en/hooks

## Input (stdin JSON)

```json
{
  "session_id": "...",
  "cwd": "/abs/project",
  "hook_event_name": "PreToolUse",
  "tool_name": "Read",
  "tool_input": { "file_path": "/abs/project/.env" },
  "tool_use_id": "toolu_..."
}
```

Also handled: `PostToolUse`, `UserPromptSubmit`, plus transcript `tool_use` / `tool_result` shapes via the Claude adapter.

## Deny response (stdout JSON, exit 0)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "[VEYRA] policy=SECRET_ACCESS decision=BLOCK severity=HIGH | ..."
  }
}
```

Empty stdout = allow (Claude continues its normal permission flow).

## Fail-closed vs fail-open

| Case | Behavior |
|------|----------|
| Malformed PreToolUse JSON | DENY |
| PreToolUse that cannot normalize | DENY |
| Watchdog / store evaluation error on PreToolUse | DENY |
| Policy BLOCK / QUARANTINE | DENY |
| Session QUARANTINED / REVOKED | DENY |
| Empty stdin | exit 0, no output |
| Allowed PreToolUse | exit 0, empty stdout |
| UserPromptSubmit / PostToolUse errors | no PreToolUse deny (informational) |

PolicyEngine stays Claude-independent; only the adapter + `veyra hook` speak Claude's wire format.

## Bridge

```bash
veyra bridge install [--adapter=claude-code|codex|all]
veyra bridge status
veyra bridge uninstall
```

- Merges VEYRA hooks; preserves unrelated hooks
- Backs up `.claude/settings.json` → `.veyra-backup` (restored on uninstall)
- Idempotent re-install (strips managed hooks before re-adding)
