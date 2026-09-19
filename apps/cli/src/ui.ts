export function printBanner(): void {
  console.log('');
  console.log('  VEYRA WATCHDOG');
  console.log('  Agent observability + authority + security enforcement');
  console.log('');
}

/** True when argv asks for help (`--help`, `-h`, or bare `help`). */
export function wantsHelp(args: string[]): boolean {
  return args.includes('--help') || args.includes('-h') || args[0] === 'help';
}

export function printHelp(): void {
  printBanner();
  console.log('Usage: veyra <command>');
  console.log('');
  console.log('Commands:');
  console.log('  init         Initialize local .veyra/ security plane');
  console.log('  watch        Observe agent activity');
  console.log('  bridge       Install/uninstall live Claude Code / Codex hooks');
  console.log('  attack       Run attack lab (--mode=simulation|runtime)');
  console.log('  demo         Controlled real-hook demo (block .env before execution)');
  console.log('  explain      Show session incident timeline or last attack report');
  console.log('  status       Show session / enforcement status');
  console.log('  events       List normalized agent events');
  console.log('  policy       Inspect security policies');
  console.log('  hook         Process one hook event from stdin (used by bridge)');
  console.log('  quarantine   Quarantine a session (operator)');
  console.log('  resume       Resume a quarantined session (operator only)');
  console.log('  version      Print CLI version');
  console.log('  help         Show this help');
  console.log('');
  console.log('Core thesis: a jailbreak should never become authority.');
  console.log('Enforcement: user-space hooks — not an OS sandbox.');
  console.log('');
}

/**
 * Per-command usage. Returns false when `command` is unknown
 * (caller should print top-level help).
 */
export function printCommandHelp(command: string): boolean {
  printBanner();
  switch (command) {
    case 'init':
      console.log('Usage: veyra init');
      console.log('');
      console.log('Initialize the local .veyra/ security plane (config + sqlite).');
      break;
    case 'watch':
      console.log('Usage: veyra watch [--stdin] [--adapter=claude-code|codex|auto]');
      console.log('');
      console.log('Arm Watchdog and optionally ingest JSONL events from stdin.');
      console.log('Without --stdin, prints how to feed events or install live hooks.');
      break;
    case 'bridge':
      console.log('Usage: veyra bridge <install|uninstall|status> [--adapter=claude-code|codex|all]');
      console.log('');
      console.log('Install or remove live Claude Code / Codex PreToolUse hooks.');
      break;
    case 'attack':
      console.log('Usage: veyra attack [--mode=simulation|runtime] [--list] [--id=<attack-id>]');
      console.log('');
      console.log('  simulation  Run policy corpus through Watchdog (default)');
      console.log('  runtime     Exercise real hook protocol against a temp workspace');
      break;
    case 'demo':
      console.log('Usage: veyra demo');
      console.log('');
      console.log('Controlled real-hook demo: allow benign reads, block .env before execution.');
      break;
    case 'explain':
      console.log('Usage: veyra explain [<session-id>]');
      console.log('');
      console.log('Show a live session incident timeline, or the last attack report if omitted.');
      break;
    case 'status':
      console.log('Usage: veyra status');
      console.log('');
      console.log('Show the latest session enforcement state and counters.');
      break;
    case 'events':
      console.log('Usage: veyra events');
      console.log('');
      console.log('List normalized agent events for the latest session.');
      break;
    case 'policy':
      console.log('Usage: veyra policy');
      console.log('');
      console.log('List active deterministic policies and advisory LLM env hints.');
      break;
    case 'hook':
      console.log('Usage: veyra hook [--adapter=claude-code|codex] < event.json');
      console.log('');
      console.log('Process one hook event from stdin (invoked by bridge scripts).');
      console.log('Empty stdin is a no-op (exit 0) so bridge probes stay quiet.');
      console.log('Malformed PreToolUse JSON fail-closes with a deny payload.');
      break;
    case 'quarantine':
      console.log('Usage: veyra quarantine [--session=<id>] [--reason=...]');
      console.log('');
      console.log('Operator: force-quarantine a session. Agents cannot self-clear.');
      break;
    case 'resume':
      console.log('Usage: veyra resume [--session=<id>] [--reason=...]');
      console.log('');
      console.log('Operator: resume a quarantined/restricted session to NORMAL.');
      break;
    case 'version':
      console.log('Usage: veyra version');
      console.log('');
      console.log('Print CLI version.');
      break;
    default:
      return false;
  }
  console.log('');
  return true;
}
