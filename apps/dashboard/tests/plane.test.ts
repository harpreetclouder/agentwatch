import { describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { resolveDashboardProjectRoot } from '../lib/plane';

describe('dashboard plane resolution', () => {
  it('prefers VEYRA_PROJECT_ROOT when set', () => {
    const prev = process.env.VEYRA_PROJECT_ROOT;
    try {
      process.env.VEYRA_PROJECT_ROOT = '/tmp/veyra-plane-override';
      expect(resolveDashboardProjectRoot()).toBe('/tmp/veyra-plane-override');
    } finally {
      if (prev === undefined) delete process.env.VEYRA_PROJECT_ROOT;
      else process.env.VEYRA_PROJECT_ROOT = prev;
    }
  });

  it('prefers examples/real-agent-demo when its plane exists', () => {
    const prev = process.env.VEYRA_PROJECT_ROOT;
    delete process.env.VEYRA_PROJECT_ROOT;
    try {
      const root = resolveDashboardProjectRoot();
      const demoConfig = join(root, '.veyra', 'config.json');
      // When demo plane is present in this workspace, root must be the demo path
      if (existsSync(join(process.cwd(), '..', '..', 'examples', 'real-agent-demo', '.veyra', 'config.json'))
        || existsSync(join(process.cwd(), 'examples', 'real-agent-demo', '.veyra', 'config.json'))) {
        expect(root.endsWith('real-agent-demo')).toBe(true);
        expect(existsSync(demoConfig)).toBe(true);
      } else {
        expect(root.length).toBeGreaterThan(0);
      }
    } finally {
      if (prev === undefined) delete process.env.VEYRA_PROJECT_ROOT;
      else process.env.VEYRA_PROJECT_ROOT = prev;
    }
  });
});
