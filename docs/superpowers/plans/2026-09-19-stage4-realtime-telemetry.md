# Stage 4 Real-time Telemetry Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** SSE (+ poll fallback) security telemetry on existing SQLite plane; live dashboard feed.

**Architecture:** Dashboard maps events+decisions → redacted DTO; Route Handlers stream/poll; client EventSource with poll fallback; plane prefers demo `.veyra`.

**Tech Stack:** Next.js 16 App Router, `@veyra/storage`, vitest

## File map

- `apps/dashboard/lib/plane.ts` — root resolution (C)
- `apps/dashboard/lib/telemetry.ts` — DTO + sanitize + list after cursor
- `apps/dashboard/app/api/events/route.ts` — poll JSON
- `apps/dashboard/app/api/events/stream/route.ts` — SSE
- `apps/dashboard/components/live-event-feed.tsx` — client feed
- `apps/dashboard/app/live/page.tsx` — auto session live view
- Update session page + nav; tests; WORK_PROGRESS

### Task 1: Telemetry mapper + tests

Write failing tests for sanitize (no secrets) and DTO shape; implement mapper.

### Task 2: Plane resolution + API routes

Implement plane.ts; GET /api/events and /api/events/stream.

### Task 3: Live UI

LiveEventFeed + /live + session wiring; nav link.

### Task 4: Docs + verify

Update WORK_PROGRESS / REAL_ENFORCEMENT_PLAN; typecheck + tests.
