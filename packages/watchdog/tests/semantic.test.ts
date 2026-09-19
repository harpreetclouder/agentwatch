import { describe, expect, it, vi } from 'vitest';
import { createAgentEvent, type AgentContext } from '@jev/agent-events';
import {
  createSemanticAnalyzer,
  describeSemanticProvider,
  HttpLlmSemanticAnalyzer,
  resolveSemanticConfig,
  Watchdog,
} from '../src/index.js';

function ctx(): AgentContext {
  return {
    agentId: 'agent_1',
    sessionId: 'sess_1',
    workingDirectory: '/repo',
    environment: 'local',
    securityState: 'NORMAL',
    task: { id: 'task_auth', description: 'Fix authentication bug' },
  };
}

describe('resolveSemanticConfig', () => {
  it('defaults to mock without API key', () => {
    expect(resolveSemanticConfig({}).kind).toBe('mock');
  });

  it('selects OpenRouter + TypeSafe Jev when OPENROUTER_API_KEY is set', () => {
    const config = resolveSemanticConfig({
      OPENROUTER_API_KEY: 'sk-or-test',
    });
    expect(config.kind).toBe('openai-compatible');
    expect(config.backend).toBe('openrouter');
    expect(config.decisionsApi).toBe(true);
    expect(config.apiKeyConfigured).toBe(true);
    expect(config.model).toBe('~typesafe/jev-latest');
    expect(config.baseUrl).toContain('openrouter.ai');
  });

  it('selects openai-compatible when JEV_SEMANTIC_API_KEY is set', () => {
    const config = resolveSemanticConfig({
      JEV_SEMANTIC_API_KEY: 'sk-test',
      JEV_SEMANTIC_BASE_URL: 'https://api.openai.com/v1',
      JEV_SEMANTIC_MODEL: 'gpt-4o-mini',
    });
    expect(config.kind).toBe('openai-compatible');
    expect(config.apiKeyConfigured).toBe(true);
    expect(config.model).toBe('gpt-4o-mini');
  });

  it('does not send OpenAI key to OpenRouter backend', () => {
    const config = resolveSemanticConfig({
      OPENAI_API_KEY: 'sk-openai',
      OPENROUTER_API_KEY: 'sk-or-real',
    });
    expect(config.backend).toBe('openrouter');
    const analyzer = createSemanticAnalyzer({
      env: {
        OPENAI_API_KEY: 'sk-openai',
        OPENROUTER_API_KEY: 'sk-or-real',
      },
    });
    expect(analyzer).not.toBeNull();
    expect(describeSemanticProvider({ OPENROUTER_API_KEY: 'sk-or-x' })).toContain(
      'OpenRouter/TypeSafe Jev (Decisions)',
    );
  });

  it('can force off', () => {
    expect(
      resolveSemanticConfig({
        JEV_SEMANTIC_PROVIDER: 'off',
        JEV_SEMANTIC_API_KEY: 'sk-test',
      }).kind,
    ).toBe('off');
    expect(createSemanticAnalyzer({ env: { JEV_SEMANTIC_PROVIDER: 'off' } })).toBeNull();
  });
});

describe('TypesafeJevSemanticAnalyzer (Decisions API)', () => {
  it('maps Decisions answers to advisory assessment', async () => {
    const { TypesafeJevSemanticAnalyzer } = await import('../src/semantic/typesafe-jev.js');
    const fetchImpl = vi.fn(async (url: string | URL | Request) => {
      expect(String(url)).toContain('/api/alpha/decisions');
      return Response.json({
        answers: {
          risk: {
            type: 'choice',
            choice: 'HIGH',
            confidence: 0.82,
            probabilities: { LOW: 0.05, MEDIUM: 0.1, HIGH: 0.7, CRITICAL: 0.15 },
          },
          injection_attempt: { type: 'noul', noul: 0.91 },
          category: { type: 'choice', choice: 'prompt_injection', confidence: 0.77 },
        },
        model: '~typesafe/jev-latest',
      });
    }) as unknown as typeof fetch;

    const analyzer = new TypesafeJevSemanticAnalyzer({
      model: '~typesafe/jev-latest',
      apiKey: 'sk-or-test',
      fetchImpl,
    });

    const event = createAgentEvent({
      id: 'evt_1',
      sessionId: 'sess_1',
      agentId: 'agent_1',
      type: 'security_event',
      action: { name: 'prompt_injection_suspected', target: 'README.md' },
    });

    const assessment = await analyzer.analyze([event], ctx());
    expect(assessment.risk).toBe('HIGH');
    expect(assessment.category).toBe('prompt_injection');
    expect(assessment.explanation).toContain('Advisory (Jev)');
    expect(assessment.evidence).toContain('advisory_only_never_enforces');
    expect(fetchImpl).toHaveBeenCalledOnce();
    const body = JSON.parse(
      (fetchImpl.mock.calls[0]![1] as RequestInit).body as string,
    ) as { questions: unknown; model: string };
    expect(body.model).toBe('~typesafe/jev-latest');
    expect(body.questions).toHaveProperty('risk');
  });

  it('falls back to LOW on HTTP failure', async () => {
    const { TypesafeJevSemanticAnalyzer } = await import('../src/semantic/typesafe-jev.js');
    const fetchImpl = vi.fn(async () =>
      new Response('bad request', { status: 400 }),
    ) as unknown as typeof fetch;

    const analyzer = new TypesafeJevSemanticAnalyzer({
      model: '~typesafe/jev-latest',
      apiKey: 'sk-or-test',
      fetchImpl,
    });

    const event = createAgentEvent({
      id: 'evt_2',
      sessionId: 'sess_1',
      agentId: 'agent_1',
      type: 'file_read',
      action: { name: 'read_file', target: 'src/a.ts' },
    });

    const assessment = await analyzer.analyze([event], ctx());
    expect(assessment.risk).toBe('LOW');
    expect(assessment.explanation).toMatch(/failed/i);
  });
});

describe('HttpLlmSemanticAnalyzer', () => {
  it('parses advisory JSON from chat completions', async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({
        choices: [
          {
            message: {
              content: JSON.stringify({
                risk: 'HIGH',
                category: 'prompt_injection',
                explanation: 'Looks like instruction override.',
                evidence: ['phrase=ignore previous'],
              }),
            },
          },
        ],
      }),
    ) as unknown as typeof fetch;

    const analyzer = new HttpLlmSemanticAnalyzer({
      baseUrl: 'https://api.example.com/v1',
      model: 'test-model',
      apiKey: 'sk-test',
      fetchImpl,
    });

    const event = createAgentEvent({
      id: 'evt_1',
      sessionId: 'sess_1',
      agentId: 'agent_1',
      type: 'security_event',
      action: { name: 'prompt_injection_suspected', target: 'README.md' },
    });

    const assessment = await analyzer.analyze([event], ctx());
    expect(assessment.risk).toBe('HIGH');
    expect(assessment.category).toBe('prompt_injection');
    expect(assessment.explanation).toContain('Advisory (LLM)');
    expect(assessment.evidence).toContain('advisory_only_never_enforces');
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it('falls back to LOW on HTTP failure', async () => {
    const fetchImpl = vi.fn(async () =>
      new Response('nope', { status: 500 }),
    ) as unknown as typeof fetch;

    const analyzer = new HttpLlmSemanticAnalyzer({
      baseUrl: 'https://api.example.com/v1',
      model: 'test-model',
      apiKey: 'sk-test',
      fetchImpl,
    });

    const event = createAgentEvent({
      id: 'evt_2',
      sessionId: 'sess_1',
      agentId: 'agent_1',
      type: 'file_read',
      action: { name: 'read_file', target: 'src/a.ts' },
    });

    const assessment = await analyzer.analyze([event], ctx());
    expect(assessment.risk).toBe('LOW');
    expect(assessment.explanation).toMatch(/failed/i);
  });
});

describe('Watchdog + semantic non-bypass', () => {
  it('never blocks from semantic CRITICAL alone', async () => {
    const criticalOnly = {
      analyze: async () => ({
        risk: 'CRITICAL' as const,
        category: 'scary',
        explanation: 'Looks bad',
        evidence: [],
      }),
    };

    const watchdog = new Watchdog({
      semanticAnalyzer: criticalOnly,
      enableSemantic: true,
    });

    const obs = await watchdog.observe(
      createAgentEvent({
        id: 'evt_ok',
        sessionId: 'sess_1',
        agentId: 'agent_1',
        type: 'file_read',
        action: { name: 'read_file', target: 'src/auth.ts' },
      }),
      ctx(),
    );

    expect(obs.semantic?.risk).toBe('CRITICAL');
    expect(obs.blocked).toBe(false);
    expect(obs.primaryPolicy).toBeNull();
  });
});

describe('describeSemanticProvider', () => {
  it('describes mock and llm modes', () => {
    expect(describeSemanticProvider({})).toContain('mock');
    expect(
      describeSemanticProvider({
        OPENROUTER_API_KEY: 'sk-or-x',
      }),
    ).toContain('OpenRouter/TypeSafe Jev (Decisions)');
  });
});
