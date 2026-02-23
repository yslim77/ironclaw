import fs from "node:fs/promises";
import path from "node:path";
import { resolveDefaultAgentId } from "../agents/agent-scope.js";
import { type OpenClawConfig, loadConfig } from "../config/config.js";
import { resolveStateDir } from "../config/paths.js";
import { resolveHeartbeatSummaryForAgent } from "../infra/heartbeat-runner.js";
import { createFixedWindowRateLimiter } from "../infra/fixed-window-rate-limit.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { getActiveTaskCount, getTotalQueueSize } from "../process/command-queue.js";
import type { MonitoringConfig, SecurityFrameworkConfig } from "../config/types.js";
import { isPathWithinRoot } from "../shared/avatar-policy.js";

const log = createSubsystemLogger("security/framework");

const DEFAULT_AUDIT_FILE = path.join(resolveStateDir(process.env), "logs", "security-audit.jsonl");

const DEFAULT_MONITORING: Required<
  Pick<MonitoringConfig, "enabled" | "heartbeat" | "queue" | "resources" | "errorTracking">
> = {
  enabled: true,
  heartbeat: { enabled: true, intervalSeconds: 30 },
  queue: { enabled: true, warnDepth: 25 },
  resources: { enabled: true, sampleSeconds: 30, maxRssMb: 1536, maxHeapUsedMb: 1024 },
  errorTracking: { enabled: true },
};

const DEFAULT_SECURITY: Required<
  Pick<SecurityFrameworkConfig, "secrets" | "audit" | "rbac" | "rateLimit" | "sandbox">
> = {
  secrets: {
    enabled: true,
    preferredProvider: "env",
    providers: {
      env: { enabled: true },
      keychain: { enabled: false },
      onePassword: { enabled: false },
    },
    placeholders: {
      envPrefix: "env:",
      keychainPrefix: "keychain:",
      onePasswordPrefix: "op://",
    },
  },
  audit: {
    enabled: true,
    file: DEFAULT_AUDIT_FILE,
    includePayloads: false,
  },
  rbac: {
    enabled: true,
    scopedTokens: {},
  },
  rateLimit: {
    enabled: true,
    default: { maxRequests: 120, windowMs: 60_000 },
    byScope: {},
  },
  sandbox: {
    enabled: true,
    defaultPolicy: "deny",
    allowedTools: [],
    deniedTools: [],
    allowedPaths: [],
    deniedPaths: [],
  },
};

type AuditEventPayload = Record<string, unknown>;

type SecurityAuditEvent = {
  ts: string;
  event: string;
  payload?: AuditEventPayload;
};

type SecurityRateLimitDecision = {
  allowed: boolean;
  retryAfterMs: number;
  remaining: number;
};

type ScopedTokenAuthResult =
  | { ok: true; tokenId: string; scopes: string[] }
  | { ok: false; reason: "missing" | "expired" | "scope_denied" | "mismatch" };

type SecretResolutionResult =
  | { ok: true; value: string; provider: "env" | "literal" }
  | { ok: false; provider: "keychain" | "1password" | "unknown"; reason: string };

type AlertSink = "email" | "telegram" | "slack";

type FrameworkMonitorMetrics = {
  queueDepth: number;
  activeTasks: number;
  rssMb: number;
  heapUsedMb: number;
  heartbeatEnabled: boolean;
  heartbeatEveryMs: number | null;
};

export function applySecurityMonitoringDefaults(config: OpenClawConfig): OpenClawConfig {
  return {
    ...config,
    security: {
      ...DEFAULT_SECURITY,
      ...config.security,
      secrets: {
        ...DEFAULT_SECURITY.secrets,
        ...config.security?.secrets,
        providers: {
          ...DEFAULT_SECURITY.secrets.providers,
          ...config.security?.secrets?.providers,
          env: {
            ...DEFAULT_SECURITY.secrets.providers.env,
            ...config.security?.secrets?.providers?.env,
          },
          keychain: {
            ...DEFAULT_SECURITY.secrets.providers.keychain,
            ...config.security?.secrets?.providers?.keychain,
          },
          onePassword: {
            ...DEFAULT_SECURITY.secrets.providers.onePassword,
            ...config.security?.secrets?.providers?.onePassword,
          },
        },
        placeholders: {
          ...DEFAULT_SECURITY.secrets.placeholders,
          ...config.security?.secrets?.placeholders,
        },
      },
      audit: {
        ...DEFAULT_SECURITY.audit,
        ...config.security?.audit,
      },
      rbac: {
        ...DEFAULT_SECURITY.rbac,
        ...config.security?.rbac,
        scopedTokens: {
          ...DEFAULT_SECURITY.rbac.scopedTokens,
          ...config.security?.rbac?.scopedTokens,
        },
      },
      rateLimit: {
        ...DEFAULT_SECURITY.rateLimit,
        ...config.security?.rateLimit,
        default: {
          ...DEFAULT_SECURITY.rateLimit.default,
          ...config.security?.rateLimit?.default,
        },
        byScope: {
          ...DEFAULT_SECURITY.rateLimit.byScope,
          ...config.security?.rateLimit?.byScope,
        },
      },
      sandbox: {
        ...DEFAULT_SECURITY.sandbox,
        ...config.security?.sandbox,
      },
    },
    monitoring: {
      ...DEFAULT_MONITORING,
      ...config.monitoring,
      heartbeat: {
        ...DEFAULT_MONITORING.heartbeat,
        ...config.monitoring?.heartbeat,
      },
      queue: {
        ...DEFAULT_MONITORING.queue,
        ...config.monitoring?.queue,
      },
      resources: {
        ...DEFAULT_MONITORING.resources,
        ...config.monitoring?.resources,
      },
      errorTracking: {
        ...DEFAULT_MONITORING.errorTracking,
        ...config.monitoring?.errorTracking,
      },
      alerts: config.monitoring?.alerts,
    },
  };
}

export async function writeSecurityAuditEvent(params: {
  config: OpenClawConfig;
  event: string;
  payload?: AuditEventPayload;
}): Promise<void> {
  const cfg = applySecurityMonitoringDefaults(params.config);
  if (cfg.security?.audit?.enabled === false) {
    return;
  }
  const filePath = cfg.security?.audit?.file?.trim() || DEFAULT_AUDIT_FILE;
  const includePayload = cfg.security?.audit?.includePayloads === true;
  const line: SecurityAuditEvent = {
    ts: new Date().toISOString(),
    event: params.event,
    ...(includePayload && params.payload ? { payload: params.payload } : {}),
  };
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.appendFile(filePath, `${JSON.stringify(line)}\n`, "utf-8");
}

export function validateSecurityFrameworkConfig(config: OpenClawConfig): Array<{
  path: string;
  message: string;
}> {
  const issues: Array<{ path: string; message: string }> = [];
  const scopedTokens = config.security?.rbac?.scopedTokens ?? {};
  const seenTokens = new Map<string, string>();
  for (const [tokenId, entry] of Object.entries(scopedTokens)) {
    if (!entry?.token) {
      continue;
    }
    const token = entry.token.trim();
    if (!token) {
      continue;
    }
    const priorTokenId = seenTokens.get(token);
    if (priorTokenId) {
      issues.push({
        path: `security.rbac.scopedTokens.${tokenId}.token`,
        message: `duplicate token value already used by scopedTokens.${priorTokenId}`,
      });
    } else {
      seenTokens.set(token, tokenId);
    }
    if (entry.expiresAt) {
      const timeMs = Date.parse(entry.expiresAt);
      if (!Number.isFinite(timeMs)) {
        issues.push({
          path: `security.rbac.scopedTokens.${tokenId}.expiresAt`,
          message: "expiresAt must be a valid ISO-8601 timestamp",
        });
      }
    }
  }
  return issues;
}

export function resolveManagedSecret(params: {
  config: OpenClawConfig;
  value?: string;
  env?: NodeJS.ProcessEnv;
}): SecretResolutionResult {
  const value = params.value?.trim();
  if (!value) {
    return { ok: true, value: "", provider: "literal" };
  }
  const cfg = applySecurityMonitoringDefaults(params.config);
  const envPrefix = cfg.security?.secrets?.placeholders?.envPrefix ?? "env:";
  const keychainPrefix = cfg.security?.secrets?.placeholders?.keychainPrefix ?? "keychain:";
  const opPrefix = cfg.security?.secrets?.placeholders?.onePasswordPrefix ?? "op://";
  const env = params.env ?? process.env;

  if (value.startsWith(envPrefix)) {
    const name = value.slice(envPrefix.length).trim();
    return { ok: true, value: (name ? env[name] : "") ?? "", provider: "env" };
  }
  if (value.startsWith(keychainPrefix)) {
    return {
      ok: false,
      provider: "keychain",
      reason: "keychain placeholders are configured as integration stubs",
    };
  }
  if (value.startsWith(opPrefix)) {
    return {
      ok: false,
      provider: "1password",
      reason: "1Password placeholders are configured as integration stubs",
    };
  }
  return { ok: true, value, provider: "literal" };
}

export function authorizeScopedToken(params: {
  config: OpenClawConfig;
  token?: string;
  requiredScope?: string;
  now?: () => number;
}): ScopedTokenAuthResult {
  const token = params.token?.trim();
  if (!token) {
    return { ok: false, reason: "missing" };
  }
  const nowMs = params.now?.() ?? Date.now();
  const scopedTokens = applySecurityMonitoringDefaults(params.config).security?.rbac?.scopedTokens ?? {};
  for (const [tokenId, entry] of Object.entries(scopedTokens)) {
    if (!entry || entry.enabled === false || !entry.token || entry.token.trim() !== token) {
      continue;
    }
    if (entry.expiresAt) {
      const expiresMs = Date.parse(entry.expiresAt);
      if (Number.isFinite(expiresMs) && expiresMs <= nowMs) {
        return { ok: false, reason: "expired" };
      }
    }
    const scopes = Array.isArray(entry.scopes)
      ? entry.scopes.filter((scope) => typeof scope === "string" && scope.trim())
      : [];
    if (params.requiredScope && !scopes.includes(params.requiredScope)) {
      return { ok: false, reason: "scope_denied" };
    }
    return { ok: true, tokenId, scopes };
  }
  return { ok: false, reason: "mismatch" };
}

export function createSecurityRateLimitChecker(params: { config: OpenClawConfig }) {
  const cfg = applySecurityMonitoringDefaults(params.config);
  const enabled = cfg.security?.rateLimit?.enabled !== false;
  const byScope = cfg.security?.rateLimit?.byScope ?? {};
  const defaultRule = cfg.security?.rateLimit?.default ?? { maxRequests: 120, windowMs: 60_000 };
  const limiterMap = new Map<string, ReturnType<typeof createFixedWindowRateLimiter>>();

  const resolveRule = (scope: string) => {
    const scoped = byScope[scope];
    return {
      maxRequests: scoped?.maxRequests ?? defaultRule.maxRequests ?? 120,
      windowMs: scoped?.windowMs ?? defaultRule.windowMs ?? 60_000,
    };
  };

  return {
    check(scope: string, key: string): SecurityRateLimitDecision {
      if (!enabled) {
        return { allowed: true, retryAfterMs: 0, remaining: Number.MAX_SAFE_INTEGER };
      }
      const mapKey = `${scope}:${key}`;
      let limiter = limiterMap.get(mapKey);
      if (!limiter) {
        const rule = resolveRule(scope);
        limiter = createFixedWindowRateLimiter({
          maxRequests: rule.maxRequests,
          windowMs: rule.windowMs,
        });
        limiterMap.set(mapKey, limiter);
      }
      const result = limiter.consume();
      return {
        allowed: result.allowed,
        retryAfterMs: result.retryAfterMs,
        remaining: result.remaining,
      };
    },
  };
}

export function enforceSandboxPermissionGate(params: {
  config: OpenClawConfig;
  toolName: string;
  targetPath?: string;
}): { ok: true } | { ok: false; reason: string } {
  const gate = applySecurityMonitoringDefaults(params.config).security?.sandbox;
  if (!gate || gate.enabled === false) {
    return { ok: true };
  }

  const deniedTools = new Set((gate.deniedTools ?? []).map((tool) => tool.trim()).filter(Boolean));
  if (deniedTools.has(params.toolName)) {
    return { ok: false, reason: `tool denied by sandbox gate: ${params.toolName}` };
  }

  const allowedTools = (gate.allowedTools ?? []).map((tool) => tool.trim()).filter(Boolean);
  if (allowedTools.length > 0 && !allowedTools.includes(params.toolName)) {
    return { ok: false, reason: `tool not in sandbox allowlist: ${params.toolName}` };
  }

  if (params.targetPath) {
    const deniedPaths = (gate.deniedPaths ?? []).map((entry) => path.resolve(entry));
    const normalizedTarget = path.resolve(params.targetPath);
    for (const blocked of deniedPaths) {
      if (isPathWithinRoot(blocked, normalizedTarget) || blocked === normalizedTarget) {
        return { ok: false, reason: `path denied by sandbox gate: ${normalizedTarget}` };
      }
    }

    const allowedPaths = (gate.allowedPaths ?? []).map((entry) => path.resolve(entry));
    if (allowedPaths.length > 0) {
      const allowed = allowedPaths.some(
        (allowedRoot) =>
          isPathWithinRoot(allowedRoot, normalizedTarget) || allowedRoot === normalizedTarget,
      );
      if (!allowed) {
        return { ok: false, reason: `path not allowed by sandbox gate: ${normalizedTarget}` };
      }
    }
  }

  if (gate.defaultPolicy === "deny" && !params.targetPath && allowedTools.length === 0) {
    return { ok: false, reason: "sandbox defaultPolicy=deny blocks unscoped operations" };
  }

  return { ok: true };
}

async function emitAlertStub(params: {
  config: OpenClawConfig;
  sink: AlertSink;
  subject: string;
  body: string;
}) {
  const alerts = applySecurityMonitoringDefaults(params.config).monitoring?.alerts;
  if (!alerts) {
    return;
  }
  if (params.sink === "email" && alerts.email?.enabled) {
    log.warn(`alert stub email to=${alerts.email.to ?? "unset"} subject="${params.subject}"`);
    log.warn(params.body);
  }
  if (params.sink === "telegram" && alerts.telegram?.enabled) {
    const token = resolveManagedSecret({
      config: params.config,
      value: alerts.telegram.botToken,
    });
    log.warn(
      `alert stub telegram chatId=${alerts.telegram.chatId ?? "unset"} subject="${params.subject}"`,
    );
    if (!token.ok) {
      log.warn(`alert stub telegram token resolver: ${token.reason}`);
    }
    log.warn(params.body);
  }
  if (params.sink === "slack" && alerts.slack?.enabled) {
    const webhook = resolveManagedSecret({
      config: params.config,
      value: alerts.slack.webhookUrl,
    });
    log.warn(
      `alert stub slack channel=${alerts.slack.channel ?? "unset"} subject="${params.subject}"`,
    );
    if (!webhook.ok) {
      log.warn(`alert stub slack webhook resolver: ${webhook.reason}`);
    }
    log.warn(params.body);
  }
}

function collectMonitoringMetrics(config: OpenClawConfig): FrameworkMonitorMetrics {
  const defaultAgentId = resolveDefaultAgentId(config);
  const heartbeat = resolveHeartbeatSummaryForAgent(config, defaultAgentId);
  const usage = process.memoryUsage();
  return {
    queueDepth: getTotalQueueSize(),
    activeTasks: getActiveTaskCount(),
    rssMb: Math.round((usage.rss / (1024 * 1024)) * 100) / 100,
    heapUsedMb: Math.round((usage.heapUsed / (1024 * 1024)) * 100) / 100,
    heartbeatEnabled: heartbeat.enabled,
    heartbeatEveryMs: heartbeat.everyMs,
  };
}

export function startSecurityMonitoringDaemon(params?: { config?: OpenClawConfig }) {
  const initialCfg = params?.config ?? loadConfig();
  const cfg = applySecurityMonitoringDefaults(initialCfg);
  if (cfg.monitoring?.enabled === false) {
    return {
      stop: () => {},
      trackError: async (_error: unknown, _context?: AuditEventPayload) => {},
    };
  }

  const queueThreshold = cfg.monitoring?.queue?.warnDepth ?? DEFAULT_MONITORING.queue.warnDepth;
  const maxRssMb = cfg.monitoring?.resources?.maxRssMb ?? DEFAULT_MONITORING.resources.maxRssMb;
  const maxHeapUsedMb =
    cfg.monitoring?.resources?.maxHeapUsedMb ?? DEFAULT_MONITORING.resources.maxHeapUsedMb;
  const sampleSeconds =
    cfg.monitoring?.resources?.sampleSeconds ?? DEFAULT_MONITORING.resources.sampleSeconds;

  const tick = async () => {
    const fresh = applySecurityMonitoringDefaults(loadConfig());
    const metrics = collectMonitoringMetrics(fresh);
    await writeSecurityAuditEvent({
      config: fresh,
      event: "monitor.tick",
      payload: metrics,
    }).catch((err) => log.warn(`failed to write monitor tick: ${String(err)}`));

    if (fresh.monitoring?.queue?.enabled !== false && metrics.queueDepth >= queueThreshold) {
      await emitAlertStub({
        config: fresh,
        sink: "slack",
        subject: "Queue depth warning",
        body: `queueDepth=${metrics.queueDepth} activeTasks=${metrics.activeTasks} threshold=${queueThreshold}`,
      });
    }
    if (fresh.monitoring?.resources?.enabled !== false && metrics.rssMb >= maxRssMb) {
      await emitAlertStub({
        config: fresh,
        sink: "email",
        subject: "RSS threshold warning",
        body: `rssMb=${metrics.rssMb} threshold=${maxRssMb}`,
      });
    }
    if (fresh.monitoring?.resources?.enabled !== false && metrics.heapUsedMb >= maxHeapUsedMb) {
      await emitAlertStub({
        config: fresh,
        sink: "telegram",
        subject: "Heap threshold warning",
        body: `heapUsedMb=${metrics.heapUsedMb} threshold=${maxHeapUsedMb}`,
      });
    }
  };

  const timer = setInterval(() => {
    void tick();
  }, Math.max(5, sampleSeconds) * 1000);
  timer.unref?.();

  return {
    stop: () => clearInterval(timer),
    trackError: async (error: unknown, context?: AuditEventPayload) => {
      const fresh = applySecurityMonitoringDefaults(loadConfig());
      if (fresh.monitoring?.errorTracking?.enabled === false) {
        return;
      }
      await writeSecurityAuditEvent({
        config: fresh,
        event: "monitor.error",
        payload: {
          error: error instanceof Error ? error.message : String(error),
          ...(context ?? {}),
        },
      });
      await emitAlertStub({
        config: fresh,
        sink: "slack",
        subject: "Error tracking event",
        body: error instanceof Error ? error.stack ?? error.message : String(error),
      });
    },
  };
}
