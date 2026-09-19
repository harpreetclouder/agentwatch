import {
  resolveJevDbPath,
  resolveProjectRoot,
  SqliteJevStore,
  type JevStore,
} from '@jev/storage';

function projectRoot(): string {
  return process.env.JEV_PROJECT_ROOT ?? resolveProjectRoot(process.cwd());
}

/** Open read-oriented store against the local .jev plane, or null if uninitialized. */
export function openDashboardStore(): { store: JevStore; root: string } | null {
  const root = projectRoot();
  const dbPath = resolveJevDbPath(root);
  if (!dbPath) {
    return null;
  }
  return { store: SqliteJevStore.open({ dbPath }), root };
}

export function shortId(id: string, len = 8): string {
  return id.length > len ? id.slice(0, len) : id;
}

export function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return iso;
  }
}
