import {
  initSecurityPlane,
  resolveVeyraDbPath,
  SqliteVeyraStore,
  type VeyraStore,
} from '@veyra/storage';

export function openLocalStore(cwd: string = process.cwd()): VeyraStore | null {
  const dbPath = resolveVeyraDbPath(cwd);
  if (!dbPath) {
    return null;
  }
  return SqliteVeyraStore.open({ dbPath });
}

export function ensureLocalStore(cwd: string = process.cwd()): {
  store: VeyraStore;
  created: boolean;
  rootDir: string;
} {
  const plane = initSecurityPlane(cwd);
  const store = SqliteVeyraStore.open({ dbPath: plane.dbPath });
  return { store, created: plane.created, rootDir: plane.rootDir };
}
