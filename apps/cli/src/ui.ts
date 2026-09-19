export function printBanner(): void {
  console.log('');
  console.log('  VEYRA WATCHDOG');
  console.log('  Agent observability + authority + security enforcement');
  console.log('');
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
