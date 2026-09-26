import { printHelp, printCommandHelp, wantsHelp } from './ui.js';
import { cmdVersion } from './commands/version.js';
import { cmdStatus } from './commands/status.js';
import { cmdInit } from './commands/init.js';
import { cmdEvents } from './commands/events.js';
import { cmdPolicy } from './commands/policy.js';
import { cmdAttack } from './commands/attack.js';
import { cmdExplain } from './commands/explain.js';
import { cmdWatch } from './commands/watch.js';
import { cmdBridge } from './commands/bridge.js';
import { cmdHook } from './commands/hook.js';
import { cmdQuarantine, cmdResume } from './commands/enforcement.js';
import { cmdDemo } from './commands/demo.js';
import { cmdReport } from './commands/report.js';
import { cmdEval } from './commands/eval.js';

export async function runCli(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return 0;
  }

  if (command === 'version' || command === '--version' || command === '-V') {
    return cmdVersion();
  }

  // `veyra <cmd> --help` / `-h` / `help` — never execute the command
  if (wantsHelp(rest)) {
    if (!printCommandHelp(command)) {
      console.error(`Unknown command: ${command}`);
      printHelp();
      return 1;
    }
    return 0;
  }

  switch (command) {
    case 'init':
      return cmdInit(rest);
    case 'status':
      return cmdStatus(rest);
    case 'events':
      return cmdEvents(rest);
    case 'policy':
      return cmdPolicy(rest);
    case 'attack':
      return cmdAttack(rest);
    case 'explain':
      return cmdExplain(rest);
    case 'watch':
      return cmdWatch(rest);
    case 'bridge':
      return cmdBridge(rest);
    case 'hook':
      return cmdHook(rest);
    case 'demo':
      return cmdDemo(rest);
    case 'report':
      return cmdReport(rest);
    case 'eval':
      return cmdEval(rest);
    case 'quarantine':
      return cmdQuarantine(rest);
    case 'resume':
      return cmdResume(rest);
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      return 1;
  }
}
