import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  transpilePackages: ['@veyra/shared', '@veyra/agent-events'],
  // node:sqlite must stay external — do not also list in transpilePackages
  serverExternalPackages: ['@veyra/storage'],
  // Do not bake VEYRA_PROJECT_ROOT here — Stage 4 plane resolution prefers
  // examples/real-agent-demo/.veyra when present (see lib/plane.ts).
  // Override at runtime: VEYRA_PROJECT_ROOT=/path pnpm --filter @veyra/dashboard dev
};

export default nextConfig;
