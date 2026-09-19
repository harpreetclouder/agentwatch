import {
  initSecurityPlane,
  resolveJevDbPath,
  SqliteJevStore,
  type JevStore,
} from '@jev/storage';

export function openLocalStore(cwd: string = process.cwd()): JevStore | null {
  const dbPath = resolveJevDbPath(cwd);
  if (!dbPath) {
    return null;
  }
  return SqliteJevStore.open({ dbPath });
}

export function ensureLocalStore(cwd: string = process.cwd()): {
  store: JevStore;
  created: boolean;
  rootDir: string;
} {
  const plane = initSecurityPlane(cwd);
  const store = SqliteJevStore.open({ dbPath: plane.dbPath });
  return { store, created: plane.created, rootDir: plane.rootDir };
}
