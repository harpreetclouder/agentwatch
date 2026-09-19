export function printBanner(): void {
  console.log('');
  console.log('  JEV WATCHDOG');
  console.log('  Agent observability + authority + security enforcement');
  console.log('');
}

export function printHelp(): void {
  printBanner();
  console.log('Usage: jev <command>');
  console.log('');
  console.log('Commands:');
  console.log('  init         Initialize local .jev/ security plane');
  console.log('  watch        Observe agent activity');
  console.log('  bridge       Install/uninstall live Claude Code / Codex hooks');
  console.log('  attack       Run controlled security attack simulations (--list, --id)');
  console.log('  explain      Show evidence-based security report');
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
  console.log('');
}
