'use client';

import { VeyraLiveConsole } from '@/components/veyra-live-console';

/** Session page live panel — same console, pinned to session. */
export function LiveEventFeed({ sessionId }: { sessionId?: string; pollMs?: number }) {
  return sessionId ? <VeyraLiveConsole sessionId={sessionId} /> : <VeyraLiveConsole />;
}
