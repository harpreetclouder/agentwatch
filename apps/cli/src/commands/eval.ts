import { EVAL_CASES, evalReportPath, formatEvalReport, runEvalSuite } from '../harness/eval-suite.js';
import { uiEvalSpec } from '../harness/eval-ui.js';

export type ParsedEvalArgs = {
  ui: boolean;
  live: boolean;
  unknown: string[];
};

/** `--ui` and `--live` are independent. Default eval accepts neither. */
export function parseEvalArgs(args: string[]): ParsedEvalArgs {
  const unknown: string[] = [];
  let ui = false;
  let live = false;
  for (const arg of args) {
    if (arg === '--ui') ui = true;
    else if (arg === '--live') live = true;
    else unknown.push(arg);
  }
  return { ui, live, unknown };
}

/** `veyra eval` — required cases must pass. Default stays CI-safe. */
export async function cmdEval(args: string[]): Promise<number> {
  const parsed = parseEvalArgs(args);
  if (parsed.unknown.length > 0) {
    console.error(`Unknown arguments: ${parsed.unknown.join(' ')}`);
    console.error('Usage: veyra eval [--ui] [--live]');
    return 1;
  }
  if (parsed.live) {
    process.env['VEYRA_RUNTIME_TESTS'] = '1';
  }
  const report = await runEvalSuite(
    parsed.ui ? { cases: [...EVAL_CASES, uiEvalSpec()] } : {},
  );
  console.log(formatEvalReport(report));
  console.log(evalReportPath());
  console.log('');
  return report.exitCode;
}
