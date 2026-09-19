# Stage 4 — Real-time security telemetry (design)

Date: 2026-09-19

## Goal

Stream live agent security events from the existing SQLite plane to the local dashboard via SSE (with short-poll fallback). No storage redesign. No SaaS dashboard.

## Plane resolution (option C)

1. `VEYRA_PROJECT_ROOT` if set
2. Else `examples/real-agent-demo/.veyra` when that plane exists
3. Else repo/cwd `.veyra` via existing `resolveProjectRoot`

When `sessionId` is omitted: `findLatestActive()`, else `findLatest()`.

## Event DTO

`eventId`, `sessionId`, `agentId`, `timestamp`, `type`, `action` (`{ name, target? }`), `decision`, `policy`, `severity`, `securityState`

Never stream arguments, result, context, evidence bodies, or secret values. Targets are path-safe (basename / relative path); strings redacted.

## API

- `GET /api/events/stream?sessionId=` — SSE (`event: security`, ~750ms SQLite reopen poll)
- `GET /api/events?sessionId=&after=` — JSON poll fallback

## UI

Live feed on `/live` (auto session) and session page. Show BLOCK / SECRET_ACCESS / HIGH without `.env` contents.

## Out of scope

WebSockets, schema changes, new policies, cloud.
