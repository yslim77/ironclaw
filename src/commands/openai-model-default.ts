import type { OpenClawConfig } from "../config/config.js";
import { ensureModelAllowlistEntry } from "./model-allowlist.js";

export const OPENAI_DEFAULT_MODEL = "openai/gpt-5.1-codex";
export const OPENAI_DEFAULT_FALLBACK_MODEL = "openai/gpt-5.2-codex";

function ensureFallbackModelList(fallbacks: string[] | undefined): string[] {
  const normalized = Array.isArray(fallbacks)
    ? fallbacks.map((entry) => String(entry).trim()).filter(Boolean)
    : [];
  if (!normalized.includes(OPENAI_DEFAULT_FALLBACK_MODEL)) {
    normalized.push(OPENAI_DEFAULT_FALLBACK_MODEL);
  }
  return normalized;
}

export function applyOpenAIProviderConfig(cfg: OpenClawConfig): OpenClawConfig {
  const withPrimary = ensureModelAllowlistEntry({
    cfg,
    modelRef: OPENAI_DEFAULT_MODEL,
  });
  const next = ensureModelAllowlistEntry({
    cfg: withPrimary,
    modelRef: OPENAI_DEFAULT_FALLBACK_MODEL,
  });
  const models = { ...next.agents?.defaults?.models };
  models[OPENAI_DEFAULT_MODEL] = {
    ...models[OPENAI_DEFAULT_MODEL],
    alias: models[OPENAI_DEFAULT_MODEL]?.alias ?? "GPT",
  };
  models[OPENAI_DEFAULT_FALLBACK_MODEL] = {
    ...models[OPENAI_DEFAULT_FALLBACK_MODEL],
    alias: models[OPENAI_DEFAULT_FALLBACK_MODEL]?.alias ?? "GPT Codex Fallback",
  };

  return {
    ...next,
    agents: {
      ...next.agents,
      defaults: {
        ...next.agents?.defaults,
        models,
      },
    },
  };
}

export function applyOpenAIConfig(cfg: OpenClawConfig): OpenClawConfig {
  const next = applyOpenAIProviderConfig(cfg);
  const modelConfig = next.agents?.defaults?.model;
  const existingFallbacks =
    modelConfig && typeof modelConfig === "object" ? modelConfig.fallbacks : undefined;
  const fallbackList = ensureFallbackModelList(existingFallbacks);
  return {
    ...next,
    agents: {
      ...next.agents,
      defaults: {
        ...next.agents?.defaults,
        model: {
          ...(modelConfig && typeof modelConfig === "object" ? modelConfig : {}),
          primary: OPENAI_DEFAULT_MODEL,
          fallbacks: fallbackList,
        },
      },
    },
  };
}
