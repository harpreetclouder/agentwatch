import { printBanner } from '../ui.js';
import { ensureLocalStore } from '../store.js';

export function cmdInit(_args: string[]): number {
  printBanner();
  const { created, rootDir, store } = ensureLocalStore();
  store.close();

  if (created) {
    console.log('Initialized local security plane.');
  } else {
    console.log('Security plane already present.');
  }

  console.log('');
  console.log(`  Path: ${rootDir}`);
  console.log('  DB:   veyra.sqlite');
  console.log('');
  console.log('Note: .veyra/ is a security-plane resource.');
  console.log('Agents must not modify config, policies, or event history.');
  console.log('');
  return 0;
}
