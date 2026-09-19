import type { NextConfig } from 'next';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '../..');

const nextConfig: NextConfig = {
  transpilePackages: ['@veyra/shared', '@veyra/agent-events'],
  // node:sqlite must stay external — do not also list in transpilePackages
  serverExternalPackages: ['@veyra/storage'],
  env: {
    VEYRA_PROJECT_ROOT: process.env.VEYRA_PROJECT_ROOT ?? rootDir,
  },
};

export default nextConfig;
