import type { OpenClawConfig } from "../config/config.js";
import type { AgentModelListConfig } from "../config/types.js";
import { OPENAI_DEFAULT_FALLBACK_MODEL } from "./openai-model-default.js";

export const OPENAI_CODEX_DEFAULT_MODEL = "openai-codex/gpt-5.3-codex";

function shouldSetOpenAICodexModel(model?: string): boolean {
  const trimmed = model?.trim();
  if (!trimmed) {
    return true;
  }
  const normalized = trimmed.toLowerCase();
  if (normalized.startsWith("openai-codex/")) {
    return false;
  }
  if (normalized.startsWith("openai/")) {
    return true;
  }
  return normalized === "gpt" || normalized === "gpt-mini";
}

function resolvePrimaryModel(model?: AgentModelListConfig | string): string | undefined {
  if (typeof model === "string") {
    return model;
  }
  if (model && typeof model === "object" && typeof model.primary === "string") {
    return model.primary;
  }
  return undefined;
}

function ensureFallbackModelList(fallbacks: string[] | undefined): string[] {
  const normalized = Array.isArray(fallbacks)
    ? fallbacks.map((entry) => String(entry).trim()).filter(Boolean)
    : [];
  if (!normalized.includes(OPENAI_DEFAULT_FALLBACK_MODEL)) {
    normalized.push(OPENAI_DEFAULT_FALLBACK_MODEL);
  }
  return normalized;
}

export function applyOpenAICodexModelDefault(cfg: OpenClawConfig): {
  next: OpenClawConfig;
  changed: boolean;
} {
  const current = resolvePrimaryModel(cfg.agents?.defaults?.model);
  if (!shouldSetOpenAICodexModel(current)) {
    return { next: cfg, changed: false };
  }
  const modelConfig = cfg.agents?.defaults?.model;
  const existingFallbacks =
    modelConfig && typeof modelConfig === "object" ? modelConfig.fallbacks : undefined;
  const fallbackList = ensureFallbackModelList(existingFallbacks);
  return {
    next: {
      ...cfg,
      agents: {
        ...cfg.agents,
        defaults: {
          ...cfg.agents?.defaults,
          model: {
            ...(modelConfig && typeof modelConfig === "object" ? modelConfig : {}),
            primary: OPENAI_CODEX_DEFAULT_MODEL,
            fallbacks: fallbackList,
          },
        },
      },
    },
    changed: true,
  };
}
