import { quarantineSession, resumeSession } from '@veyra/policy-engine';
import { printBanner } from '../ui.js';
import { openLocalStore } from '../store.js';

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function flagValue(args: string[], name: string): string | undefined {
  const prefixed = args.find((a) => a.startsWith(`${name}=`));
  if (prefixed) {
    return prefixed.slice(name.length + 1);
  }
  const idx = args.indexOf(name);
  if (idx >= 0 && args[idx + 1] && !args[idx + 1]!.startsWith('-')) {
    return args[idx + 1];
  }
  return undefined;
}

function controlOptions(args: string[]): { sessionId?: string; reason?: string } {
  const options: { sessionId?: string; reason?: string } = {};
  const sessionId = flagValue(args, '--session');
  const reason = flagValue(args, '--reason');
  if (sessionId !== undefined) {
    options.sessionId = sessionId;
  }
  if (reason !== undefined) {
    options.reason = reason;
  }
  return options;
}

/**
 * Operator control: quarantine the latest (or specified) session.
 */
export async function cmdQuarantine(args: string[]): Promise<number> {
  printBanner();
  const store = openLocalStore();
  if (!store) {
    console.log('Security plane not initialized. Run `veyra init` first.');
    console.log('');
    return 1;
  }

  try {
    const result = await quarantineSession(store, controlOptions(args));

    console.log('Session quarantined.');
    console.log('');
    console.log(`  Session:  ${shortId(result.session.id)}`);
    console.log(`  Previous: ${result.previousState}`);
    console.log(`  State:    ${result.securityState}`);
    console.log(`  Reason:   ${result.reason}`);
    console.log('');
    console.log('Tool actions are denied until an operator runs `veyra resume`.');
    console.log('');
    return 0;
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    console.log('');
    return 1;
  } finally {
    store.close();
  }
}

/**
 * Operator control: resume a quarantined / restricted session.
 */
export async function cmdResume(args: string[]): Promise<number> {
  printBanner();
  const store = openLocalStore();
  if (!store) {
    console.log('Security plane not initialized. Run `veyra init` first.');
    console.log('');
    return 1;
  }

  try {
    const result = await resumeSession(store, controlOptions(args));

    console.log('Session resumed (operator).');
    console.log('');
    console.log(`  Session:  ${shortId(result.session.id)}`);
    console.log(`  Previous: ${result.previousState}`);
    console.log(`  State:    ${result.securityState}`);
    console.log(`  Reason:   ${result.reason}`);
    console.log('');
    console.log('Authority restored to NORMAL. Continue with `veyra watch` / live hooks.');
    console.log('');
    return 0;
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    console.log('');
    return 1;
  } finally {
    store.close();
  }
}
