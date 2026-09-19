# VEYRA LIVE — Split Board interactive design

Date: 2026-09-19  
Choice: **C — Split Board**

## Layout

- Left (light): Live Activity stream — selectable rows
- Right (dark detail): Agent · Security State path · Incident · Evidence
- Header: VEYRA LIVE + connection status + current state

## Interactions

1. Click activity row → right pane focuses that event’s decision/evidence
2. Auto-select newest BLOCK/QUARANTINE on arrival (pulse)
3. Horizontal state path animates on transition
4. Esc clears selection (falls back to latest incident)

## Constraints

Real SQLite/SSE data only. Never show secret contents. No analytics/billing/cloud.
