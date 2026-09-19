import { MockSemanticAnalyzer } from './mock.js';
import { HttpLlmSemanticAnalyzer } from './http-llm.js';
import {
  DEFAULT_DECISIONS_URL,
  TypesafeJevSemanticAnalyzer,
  isTypesafeJevModel,
} from './typesafe-jev.js';
import type { SemanticAnalyzer } from '../types.js';

export type SemanticProviderKind = 'mock' | 'openai-compatible' | 'off';

export type ResolvedSemanticConfig = {
  kind: SemanticProviderKind;
  model: string | null;
  baseUrl: string | null;
  /** True when an API key is present (value never exposed). */
  apiKeyConfigured: boolean;
  /** Human label for which backend (openrouter / openai / custom). */
  backend: 'openrouter' | 'openai' | 'custom' | 'none';
  /** True when model is TypeSafe Jev (Decisions API, not chat). */
  decisionsApi: boolean;
};

/** TypeSafe Jev on OpenRouter — intended advisory model (cheap / low-latency). */
export const DEFAULT_JEV_MODEL = '~typesafe/jev-latest';
export const DEFAULT_OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1';
export const DEFAULT_OPENAI_BASE_URL = 'https://api.openai.com/v1';
export { DEFAULT_DECISIONS_URL };

function resolveApiKey(env: NodeJS.ProcessEnv, backendHint?: 'openrouter' | 'openai' | 'custom'): string {
  const veyraKey = env['VEYRA_SEMANTIC_API_KEY']?.trim() || '';
  const openrouter = env['OPENROUTER_API_KEY']?.trim() || '';
  const openai = env['OPENAI_API_KEY']?.trim() || '';

  // Prefer the key that matches the backend — avoid sending OpenAI keys to OpenRouter (401)
  if (backendHint === 'openrouter') {
    // Do not fall back to OPENAI_API_KEY here
    return openrouter || veyraKey || '';
  }
  if (backendHint === 'openai') {
    return openai || veyraKey || '';
  }
  return veyraKey || openrouter || openai;
}

function prefersOpenRouter(env: NodeJS.ProcessEnv, explicit: string): boolean {
  if (explicit === 'openrouter' || explicit === 'jev') {
    return true;
  }
  if (env['OPENROUTER_API_KEY']?.trim()) {
    return true;
  }
  const base = env['VEYRA_SEMANTIC_BASE_URL'] ?? '';
  return base.includes('openrouter.ai');
}

/**
 * Resolve advisory semantic provider from environment.
 *
 * Preferred stack: OpenRouter + TypeSafe Jev (Decisions API)
 * https://openrouter.ai/~typesafe/jev-latest
 * POST https://openrouter.ai/api/alpha/decisions
 *
 * Env:
 * - OPENROUTER_API_KEY (preferred) | VEYRA_SEMANTIC_API_KEY | OPENAI_API_KEY
 * - VEYRA_SEMANTIC_MODEL (default ~typesafe/jev-latest)
 * - VEYRA_SEMANTIC_BASE_URL (chat models only; Jev uses Decisions URL)
 * - VEYRA_SEMANTIC_DECISIONS_URL (default https://openrouter.ai/api/alpha/decisions)
 * - VEYRA_SEMANTIC_PROVIDER=mock|openrouter|openai-compatible|off
 */
export function resolveSemanticConfig(
  env: NodeJS.ProcessEnv = process.env,
): ResolvedSemanticConfig {
  const explicit = (env['VEYRA_SEMANTIC_PROVIDER'] ?? '').trim().toLowerCase();
  const useOpenRouter = prefersOpenRouter(env, explicit);

  const baseUrl = (
    env['VEYRA_SEMANTIC_BASE_URL'] ??
    (useOpenRouter ? DEFAULT_OPENROUTER_BASE_URL : DEFAULT_OPENAI_BASE_URL)
  ).trim();

  const model = (env['VEYRA_SEMANTIC_MODEL'] ?? DEFAULT_JEV_MODEL).trim();

  let backend: ResolvedSemanticConfig['backend'] = 'none';
  if (baseUrl.includes('openrouter.ai') || useOpenRouter) {
    backend = 'openrouter';
  } else if (baseUrl.includes('openai.com')) {
    backend = 'openai';
  } else if (env['VEYRA_SEMANTIC_BASE_URL']) {
    backend = 'custom';
  }

  const key = resolveApiKey(
    env,
    backend === 'none' ? undefined : backend,
  );

  let kind: SemanticProviderKind = 'mock';
  if (explicit === 'off' || explicit === 'none' || explicit === 'disabled') {
    kind = 'off';
  } else if (
    explicit === 'openai-compatible' ||
    explicit === 'openai' ||
    explicit === 'llm' ||
    explicit === 'openrouter' ||
    explicit === 'jev'
  ) {
    kind = key ? 'openai-compatible' : 'mock';
  } else if (explicit === 'mock') {
    kind = 'mock';
  } else if (key) {
    kind = 'openai-compatible';
  }

  if (kind !== 'openai-compatible') {
    backend = 'none';
  } else if (backend === 'none') {
    backend = 'custom';
  }

  const decisionsApi =
    kind === 'openai-compatible' &&
    (backend === 'openrouter' || isTypesafeJevModel(model)) &&
    isTypesafeJevModel(model);

  return {
    kind,
    model: kind === 'openai-compatible' ? model : null,
    baseUrl: kind === 'openai-compatible' ? baseUrl : null,
    apiKeyConfigured: key.length > 0,
    backend,
    decisionsApi,
  };
}

export type CreateSemanticAnalyzerOptions = {
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
};

export function createSemanticAnalyzer(
  options: CreateSemanticAnalyzerOptions = {},
): SemanticAnalyzer | null {
  const env = options.env ?? process.env;
  const config = resolveSemanticConfig(env);

  if (config.kind === 'off') {
    return null;
  }

  if (config.kind === 'openai-compatible') {
    const apiKey = resolveApiKey(
      env,
      config.backend === 'none' ? undefined : config.backend,
    );
    if (!apiKey || !config.baseUrl || !config.model) {
      return new MockSemanticAnalyzer();
    }
    const timeoutRaw = env['VEYRA_SEMANTIC_TIMEOUT_MS'];
    const timeoutMs = timeoutRaw ? Number(timeoutRaw) : undefined;
    const timeoutOpt =
      timeoutMs !== undefined && Number.isFinite(timeoutMs) ? { timeoutMs } : {};
    const fetchOpt = options.fetchImpl ? { fetchImpl: options.fetchImpl } : {};

    // TypeSafe Jev is Decisions API only — never chat/completions (HTTP 400).
    if (config.decisionsApi) {
      const decisionsUrl = (
        env['VEYRA_SEMANTIC_DECISIONS_URL'] ?? DEFAULT_DECISIONS_URL
      ).trim();
      return new TypesafeJevSemanticAnalyzer({
        decisionsUrl,
        model: config.model,
        apiKey,
        ...timeoutOpt,
        ...fetchOpt,
      });
    }

    return new HttpLlmSemanticAnalyzer({
      baseUrl: config.baseUrl,
      model: config.model,
      apiKey,
      ...timeoutOpt,
      ...fetchOpt,
    });
  }

  return new MockSemanticAnalyzer();
}

export function describeSemanticProvider(env: NodeJS.ProcessEnv = process.env): string {
  const config = resolveSemanticConfig(env);
  if (config.kind === 'off') {
    return 'off (deterministic policies only)';
  }
  if (config.kind === 'openai-compatible') {
    const via =
      config.backend === 'openrouter'
        ? config.decisionsApi
          ? 'OpenRouter/TypeSafe Jev (Decisions)'
          : 'OpenRouter'
        : config.backend === 'openai'
          ? 'OpenAI'
          : 'custom';
    return `${via} · model=${config.model} · advisory only`;
  }
  return 'mock heuristics · advisory only';
}
