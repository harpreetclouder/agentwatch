import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const file = join(root, 'dist/bundle/veyra.js');

let src = readFileSync(file, 'utf8');
const pairs = [
  [/from ['"]sqlite['"]/g, 'from "node:sqlite"'],
  [/from ['"]fs['"]/g, 'from "node:fs"'],
  [/from ['"]path['"]/g, 'from "node:path"'],
  [/from ['"]os['"]/g, 'from "node:os"'],
  [/from ['"]url['"]/g, 'from "node:url"'],
  [/from ['"]child_process['"]/g, 'from "node:child_process"'],
  [/from ['"]readline['"]/g, 'from "node:readline"'],
  [/from ['"]crypto['"]/g, 'from "node:crypto"'],
  [/from ['"]util['"]/g, 'from "node:util"'],
  [/from ['"]stream['"]/g, 'from "node:stream"'],
];

for (const [re, rep] of pairs) {
  src = src.replace(re, rep);
}

writeFileSync(file, src, 'utf8');
chmodSync(file, 0o755);
console.log('Fixed node: imports in', file);
