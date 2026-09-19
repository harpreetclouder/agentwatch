import { PolicyEngine } from '@veyra/policy-engine';
import { describeSemanticProvider } from '@veyra/watchdog';
import { printBanner } from '../ui.js';

export function cmdPolicy(args: string[]): number {
  printBanner();
  const engine = new PolicyEngine();
  const policies = engine.listPolicies();

  if (args.includes('--json')) {
    console.log(
      JSON.stringify(
        policies.map((p) => ({
          id: p.id,
          severity: p.severity,
          description: p.description,
        })),
        null,
        2,
      ),
    );
    return 0;
  }

  console.log('Active deterministic policies:');
  console.log('');
  for (const policy of policies) {
    console.log(`  ${policy.id.padEnd(28)} [${policy.severity}]`);
    console.log(`    ${policy.description}`);
    console.log('');
  }

  console.log(`Semantic provider: ${describeSemanticProvider()}`);
  console.log('Note: semantic/LLM analysis is advisory and must not bypass these rules.');
  console.log('');
  console.log('Configure advisory LLM (TypeSafe Jev via OpenRouter Decisions API):');
  console.log('  export OPENROUTER_API_KEY=sk-or-...');
  console.log('  # defaults: model=~typesafe/jev-latest');
  console.log('  # endpoint: POST https://openrouter.ai/api/alpha/decisions');
  console.log('  # https://openrouter.ai/~typesafe/jev-latest');
  console.log('  VEYRA_SEMANTIC_PROVIDER=openrouter|mock|off');
  console.log('');
  return 0;
}
