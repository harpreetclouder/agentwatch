export function printBanner(): void {
  console.log('');
  console.log('  VEYRA WATCHDOG');
  console.log('  Test whether your agent can be compromised.');
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
  console.log('  attack       Attack lab (--mode=simulation|hook|runtime) [--ci]');
  console.log('  demo         One-command security demo (veyra demo)');
  console.log('  report       Security report [--json|--md|--html] (counts, not scores)');
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
  console.log('Front door:  veyra demo');
  console.log('CI:          veyra attack --ci');
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
      console.log(
        'Usage: veyra attack [--mode=simulation|hook|runtime] [--ci] [--list] [--id=<attack-id>]',
      );
      console.log('');
      console.log('  simulation  Synthetic AgentEvent corpus through Watchdog (default)');
      console.log('  hook        Real PreToolUse wire format via veyra hook (not live Claude)');
      console.log('  runtime     Live Claude Code only — never fakes success');
      console.log('  --ci        Simulation mode with CI exit codes (0=all contained)');
      console.log('');
      console.log('First hook/runtime attack: prompt-injection-secret-access');
      break;
    case 'demo':
      console.log('Usage: veyra demo [--mode=product|hook|runtime|stage6] [--workspace=<path>]');
      console.log('');
      console.log('  product  Product demo (default) — real hooks; live Claude when available');
      console.log('  hook     Deterministic PreToolUse wire-format proof');
      console.log('  runtime  Live Claude Code only; never fakes success');
      console.log('  stage6   Multi-step trajectory → quarantine + localhost collector');
      console.log('');
      console.log('If Claude Code is unavailable, product mode prints REAL RUNTIME UNAVAILABLE');
      console.log('and runs the deterministic hook test (never labeled as runtime).');
      break;
    case 'report':
      console.log('Usage: veyra report [--json|--md|--html] [--out=<path>]');
      console.log('');
      console.log('Print the last attack/session security report.');
      console.log('Shows concrete contained / not-contained counts — never % scores.');
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
