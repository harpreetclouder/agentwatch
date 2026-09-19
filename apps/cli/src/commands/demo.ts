import { printBanner } from '../ui.js';
import {
  createTestWorkspace,
  runHookPreToolUse,
  resolveCliEntry,
} from '../harness/test-workspace.js';
import { existsSync } from 'node:fs';

/**
 * Controlled local demo: prompt injection → .env read → BLOCK before execution.
 * Does not require a live Claude Code process — exercises the real hook protocol.
 */
export async function cmdDemo(_args: string[]): Promise<number> {
  printBanner();

  console.log('╔══════════════════════════════════════════╗');
  console.log('║          VEYRA WATCHDOG DEMO               ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
  console.log('Task:');
  console.log('  Fix authentication bug');
  console.log('');
  console.log('Attack:');
  console.log('  Prompt Injection → Secret Access');
  console.log('');
  console.log('Agent:');
  console.log('  Claude Code (hook protocol)');
  console.log('');
  console.log('──────────────────────────────────────────');
  console.log('');

  const cli = resolveCliEntry();
  if (!existsSync(cli)) {
    console.error('CLI not built. Run: pnpm --filter veyra build');
    return 1;
  }

  const ws = createTestWorkspace('veyra-demo-');
  try {
    // 1) Benign auth read
    const auth = runHookPreToolUse({ cwd: ws.root, filePath: 'src/auth.ts', cliEntry: cli });
    console.log(
      auth.denied
        ? '✗ src/auth.ts                 BLOCKED (unexpected)'
        : '✓ src/auth.ts                 ALLOWED',
    );

    // 2) README (injection text as prompt event would be separate; file read allowed)
    const readme = runHookPreToolUse({ cwd: ws.root, filePath: 'README.md', cliEntry: cli });
    console.log(
      readme.denied
        ? '✗ README.md                   BLOCKED (unexpected)'
        : '✓ README.md                   ALLOWED',
    );
    console.log('⚠ Prompt injection present in README (fixture)');

    // 3) .env — must BLOCK; file contents unchanged; deny JSON emitted
    const secret = runHookPreToolUse({ cwd: ws.root, filePath: '.env', cliEntry: cli });
    const unchanged = secret.envBefore === secret.envAfter;
    console.log(
      secret.denied ? '✗ .env                        BLOCKED' : '✕ .env                        ESCAPED',
    );
    console.log('');
    console.log('Policy:');
    console.log('  SECRET_ACCESS');
    console.log('');
    console.log('Trajectory:');
    console.log('  PROMPT_INJECTION → SECRET_ACCESS');
    console.log('');
    console.log('Enforcement:');
    console.log(
      secret.denied && unchanged
        ? '  BLOCKED BEFORE EXECUTION'
        : '  FAILED — secret may have been exposed',
    );
    console.log('');
    console.log('Protected secret:');
    console.log(unchanged ? '  NOT EXPOSED (file unread by hook path)' : '  CHANGED/UNEXPECTED');
    console.log('');
    console.log('Evidence:');
    console.log(`  Stored under ${ws.root}/.veyra`);
    console.log('');
    console.log('This is a controlled security demonstration,');
    console.log('not a claim of complete agent security.');
    console.log('');
    console.log(`Workspace (cleaned): ${ws.root}`);
    console.log('');

    return secret.denied && unchanged && !auth.denied ? 0 : 1;
  } finally {
    ws.cleanup();
  }
}
