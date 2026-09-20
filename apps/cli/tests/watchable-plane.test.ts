import { describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  LIVE_DASHBOARD_URL,
  openDemoWorkspace,
  printLiveWatchHint,
  resolveWatchableDemoRoot,
} from '../src/harness/watchable-plane.js';

describe('watchable plane (LIVE parity)', () => {
  it('defaults to examples/real-agent-demo when present', () => {
    const ws = openDemoWorkspace();
    expect(ws.watchable).toBe(true);
    expect(ws.root).toBe(resolveWatchableDemoRoot());
    expect(existsSync(join(ws.root, '.veyra', 'config.json'))).toBe(true);
    expect(existsSync(ws.envPath)).toBe(true);
    ws.cleanup();
  });

  it('isolated=true uses a temp dir that is not the demo fixture', () => {
    const ws = openDemoWorkspace({ isolated: true, prefix: 'veyra-live-test-' });
    expect(ws.watchable).toBe(false);
    expect(ws.root).not.toBe(resolveWatchableDemoRoot());
    expect(existsSync(ws.envPath)).toBe(true);
    ws.cleanup();
    expect(existsSync(ws.root)).toBe(false);
  });

  it('printLiveWatchHint mentions dashboard URL and plane path', () => {
    const root = resolveWatchableDemoRoot();
    const chunks: string[] = [];
    const orig = console.log;
    console.log = (...a: unknown[]) => {
      chunks.push(a.map(String).join(' '));
    };
    try {
      printLiveWatchHint(root);
    } finally {
      console.log = orig;
    }
    const out = chunks.join('\n');
    expect(out).toContain(`Watch LIVE: ${LIVE_DASHBOARD_URL}`);
    expect(out).toContain(`Plane: ${join(root, '.veyra')}`);
  });
});
