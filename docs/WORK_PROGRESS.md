# Work Progress — JEV Watchdog

## Current stage

**Stage 12 — Advisory LLM semantic provider** (complete; Decisions API fix)

## Done

### Stages 1–11
- Full control plane: events, policies, Watchdog, adapters, CLI, dashboard, bridge, attack corpus, quarantine/resume

### Stage 12
- Advisory semantic via **TypeSafe Jev** on OpenRouter Decisions API (`POST /api/alpha/decisions`)
- Model `~typesafe/jev-latest` — never enforces; chat/completions removed for Jev (was HTTP 400)
- Env: `OPENROUTER_API_KEY` (preferred); optional `JEV_SEMANTIC_DECISIONS_URL`
- Failures degrade to LOW; CRITICAL semantic never sets `blocked`

## Not done (by design)

- Auth / multi-tenant dashboard

## Verify

```bash
pnpm test
pnpm --filter @jev/cli start policy
# optional: OPENROUTER_API_KEY=sk-or-... pnpm --filter @jev/cli start watch -- --stdin ...
```

## Next recommended step

**Stage 13 — Dashboard polish / auth** or packaging (`npx jev`)
