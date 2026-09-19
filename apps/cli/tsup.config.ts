import { defineConfig } from 'tsup';

/**
 * Single-file CLI bundle for `npx veyra` / npm publish.
 * Inlines workspace `@veyra/*` packages so consumers need no monorepo install.
 */
export default defineConfig({
  entry: {
    veyra: 'src/index.ts',
  },
  outDir: 'dist/bundle',
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  // Bundle workspace packages; only leave Node builtins external
  noExternal: [/^@veyra\//],
  external: [/^node:/, 'node:sqlite', 'sqlite'],
  esbuildOptions(options) {
    options.legalComments = 'none';
  },
});
