import { execFile as execFileCallback } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { resolveDefaultAgentId } from "../agents/agent-scope.js";
import { createDefaultDeps } from "../cli/deps.js";
import { type OpenClawConfig, loadConfig } from "../config/config.js";
import { resolveStateDir } from "../config/paths.js";
import type { MonitoringConfig, SecurityFrameworkConfig } from "../config/types.js";
import { createFixedWindowRateLimiter } from "../infra/fixed-window-rate-limit.js";
import { resolveHeartbeatSummaryForAgent } from "../infra/heartbeat-runner.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { getActiveTaskCount, getTotalQueueSize } from "../process/command-queue.js";
import { isPathWithinRoot } from "../shared/avatar-policy.js";

const execFile = promisify(execFileCallback);
const log = createSubsystemLogger("security/framework");

const DEFAULT_AUDIT_FILE = path.join(resolveStateDir(process.env), "logs", "security-audit.jsonl");

const DEFAULT_MONITORING: Required<
  Pick<
    MonitoringConfig,
    "enabled" | "heartbeat" | "queue" | "resources" | "errorTracking" | "metrics"
  >
> = {
  enabled: true,
  heartbeat: { enabled: true, intervalSeconds: 30 },
  queue: { enabled: true, warnDepth: 25 },
  resources: { enabled: true, sampleSeconds: 30, maxRssMb: 1536, maxHeapUsedMb: 1024 },
  errorTracking: { enabled: true },
  metrics: { enabled: true, path: "/metrics" },
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
  | { ok: true; value: string; provider: "env" | "literal" | "keychain" | "1password" }
  | { ok: false; provider: "keychain" | "1password" | "unknown"; reason: string };

type AlertSink = "email" | "telegram" | "slack";

type FrameworkMonitorMetrics = {
  queueDepth: number;
  activeTasks: number;
  rssMb: number;
  heapUsedMb: number;
  heartbeatEnabled: boolean;
  heartbeatEveryMs: number | null;
  alertsDeliveredTotal: number;
  alertsFailedTotal: number;
  errorsTrackedTotal: number;
};

type SecretCommandRunner = (params: {
  file: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
}) => Promise<{ stdout: string; stderr: string }>;

const defaultSecretCommandRunner: SecretCommandRunner = async (params) => {
  return await execFile(params.file, params.args, {
    env: params.env,
    timeout: 10_000,
    maxBuffer: 1024 * 1024,
  });
};

const monitoringCounters = {
  alertsDeliveredTotal: 0,
  alertsFailedTotal: 0,
  errorsTrackedTotal: 0,
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
      metrics: {
        ...DEFAULT_MONITORING.metrics,
        ...config.monitoring?.metrics,
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

function normalizeOnePasswordRef(params: {
  placeholder: string;
  prefix: string;
  defaultVault?: string;
}): string {
  const trimmed = params.placeholder.trim();
  if (trimmed.startsWith("op://")) {
    return trimmed;
  }
  const raw = trimmed.startsWith(params.prefix)
    ? trimmed.slice(params.prefix.length).trim()
    : trimmed;
  const normalized = raw.startsWith("op://") ? raw : `op://${raw.replace(/^\/+/, "")}`;
  const vault = params.defaultVault?.trim();
  if (!vault) {
    return normalized;
  }
  const body = normalized.slice("op://".length).replace(/^\/+/, "");
  const parts = body.split("/").filter(Boolean);
  if (parts.length >= 3) {
    return normalized;
  }
  return `op://${vault}/${parts.join("/")}`;
}

function parseKeychainSelector(params: {
  selector: string;
  defaultService?: string;
  defaultAccount?: string;
}): { service?: string; account?: string } {
  const selector = params.selector.trim();
  const [servicePart, accountPart] = selector.split("/", 2);
  const service = (servicePart?.trim() || params.defaultService || "").trim();
  const account = (accountPart?.trim() || params.defaultAccount || "").trim();
  return {
    ...(service ? { service } : {}),
    ...(account ? { account } : {}),
  };
}

export async function resolveManagedSecret(params: {
  config: OpenClawConfig;
  value?: string;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  commandRunner?: SecretCommandRunner;
}): Promise<SecretResolutionResult> {
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
    const envProvider = cfg.security?.secrets?.providers?.env;
    if (envProvider?.enabled === false) {
      return {
        ok: false,
        provider: "unknown",
        reason: "env secret provider is disabled",
      };
    }
    const name = value.slice(envPrefix.length).trim();
    return { ok: true, value: (name ? env[name] : "") ?? "", provider: "env" };
  }

  const commandRunner = params.commandRunner ?? defaultSecretCommandRunner;

  if (value.startsWith(keychainPrefix)) {
    const keychainProvider = cfg.security?.secrets?.providers?.keychain;
    if (keychainProvider?.enabled !== true) {
      return {
        ok: false,
        provider: "keychain",
        reason: "keychain provider is disabled",
      };
    }
    if ((params.platform ?? process.platform) !== "darwin") {
      return {
        ok: false,
        provider: "keychain",
        reason: "keychain provider is only supported on macOS",
      };
    }

    const selector = value.slice(keychainPrefix.length).trim();
    const parsed = parseKeychainSelector({
      selector,
      defaultService: keychainProvider.service,
      defaultAccount: keychainProvider.account,
    });
    if (!parsed.service || !parsed.account) {
      return {
        ok: false,
        provider: "keychain",
        reason: "keychain placeholder must include service/account or provider defaults",
      };
    }

    try {
      const keychainCommand = keychainProvider.command?.trim() || "security";
      const { stdout } = await commandRunner({
        file: keychainCommand,
        args: ["find-generic-password", "-w", "-s", parsed.service, "-a", parsed.account],
      });
      return { ok: true, provider: "keychain", value: stdout.trim() };
    } catch (err) {
      return {
        ok: false,
        provider: "keychain",
        reason: `failed to resolve macOS keychain secret: ${String(err)}`,
      };
    }
  }

  if (value.startsWith(opPrefix)) {
    const onePasswordProvider = cfg.security?.secrets?.providers?.onePassword;
    if (onePasswordProvider?.enabled !== true) {
      return {
        ok: false,
        provider: "1password",
        reason: "1Password provider is disabled",
      };
    }

    const secretRef = normalizeOnePasswordRef({
      placeholder: value,
      prefix: opPrefix,
      defaultVault: onePasswordProvider.vault,
    });
    const account = onePasswordProvider.account?.trim();
    const args = ["read", secretRef, ...(account ? ["--account", account] : [])];

    try {
      const onePasswordCommand = onePasswordProvider.command?.trim() || "op";
      const { stdout } = await commandRunner({
        file: onePasswordCommand,
        args,
        env: account ? { ...env, OP_ACCOUNT: account } : env,
      });
      return { ok: true, provider: "1password", value: stdout.trim() };
    } catch (err) {
      return {
        ok: false,
        provider: "1password",
        reason: `failed to resolve 1Password secret via op: ${String(err)}`,
      };
    }
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
  const scopedTokens =
    applySecurityMonitoringDefaults(params.config).security?.rbac?.scopedTokens ?? {};
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
    alertsDeliveredTotal: monitoringCounters.alertsDeliveredTotal,
    alertsFailedTotal: monitoringCounters.alertsFailedTotal,
    errorsTrackedTotal: monitoringCounters.errorsTrackedTotal,
  };
}

export function renderMonitoringMetrics(config: OpenClawConfig): string {
  const metrics = collectMonitoringMetrics(applySecurityMonitoringDefaults(config));
  const lines = [
    "# HELP openclaw_monitoring_queue_depth Current command queue depth.",
    "# TYPE openclaw_monitoring_queue_depth gauge",
    `openclaw_monitoring_queue_depth ${metrics.queueDepth}`,
    "# HELP openclaw_monitoring_active_tasks Current active command task count.",
    "# TYPE openclaw_monitoring_active_tasks gauge",
    `openclaw_monitoring_active_tasks ${metrics.activeTasks}`,
    "# HELP openclaw_monitoring_rss_mb Process resident set size in MB.",
    "# TYPE openclaw_monitoring_rss_mb gauge",
    `openclaw_monitoring_rss_mb ${metrics.rssMb}`,
    "# HELP openclaw_monitoring_heap_used_mb Process heap used in MB.",
    "# TYPE openclaw_monitoring_heap_used_mb gauge",
    `openclaw_monitoring_heap_used_mb ${metrics.heapUsedMb}`,
    "# HELP openclaw_monitoring_heartbeat_enabled Whether heartbeat is enabled (1/0).",
    "# TYPE openclaw_monitoring_heartbeat_enabled gauge",
    `openclaw_monitoring_heartbeat_enabled ${metrics.heartbeatEnabled ? 1 : 0}`,
    "# HELP openclaw_monitoring_heartbeat_interval_ms Heartbeat interval in milliseconds.",
    "# TYPE openclaw_monitoring_heartbeat_interval_ms gauge",
    `openclaw_monitoring_heartbeat_interval_ms ${metrics.heartbeatEveryMs ?? 0}`,
    "# HELP openclaw_monitoring_alerts_delivered_total Total monitoring alerts successfully delivered.",
    "# TYPE openclaw_monitoring_alerts_delivered_total counter",
    `openclaw_monitoring_alerts_delivered_total ${metrics.alertsDeliveredTotal}`,
    "# HELP openclaw_monitoring_alerts_failed_total Total monitoring alerts that failed delivery.",
    "# TYPE openclaw_monitoring_alerts_failed_total counter",
    `openclaw_monitoring_alerts_failed_total ${metrics.alertsFailedTotal}`,
    "# HELP openclaw_monitoring_errors_tracked_total Total errors recorded by the monitoring daemon.",
    "# TYPE openclaw_monitoring_errors_tracked_total counter",
    `openclaw_monitoring_errors_tracked_total ${metrics.errorsTrackedTotal}`,
  ];
  return `${lines.join("\n")}\n`;
}

async function tryAlertHook(params: {
  command?: string;
  sink: AlertSink;
  subject: string;
  body: string;
  commandRunner?: SecretCommandRunner;
}): Promise<boolean> {
  const command = params.command?.trim();
  if (!command) {
    return false;
  }
  const commandRunner = params.commandRunner ?? defaultSecretCommandRunner;
  const messageText = `[OpenClaw alert] ${params.subject}\n${params.body}`;
  try {
    await commandRunner({
      file: command,
      args: [params.sink],
      env: {
        ...process.env,
        OPENCLAW_ALERT_SINK: params.sink,
        OPENCLAW_ALERT_SUBJECT: params.subject,
        OPENCLAW_ALERT_BODY: params.body,
        OPENCLAW_ALERT_MESSAGE: messageText,
      },
    });
    return true;
  } catch (err) {
    log.warn(`alert hook failed for ${params.sink}: ${String(err)}`);
    return false;
  }
}

export async function deliverMonitoringAlert(params: {
  config: OpenClawConfig;
  sink: AlertSink;
  subject: string;
  body: string;
  commandRunner?: SecretCommandRunner;
}): Promise<void> {
  const cfg = applySecurityMonitoringDefaults(params.config);
  const alerts = cfg.monitoring?.alerts;
  if (!alerts) {
    monitoringCounters.alertsFailedTotal += 1;
    return;
  }

  const messageText = `[OpenClaw alert] ${params.subject}\n${params.body}`;

  if (params.sink === "email" && alerts.email?.enabled) {
    if (alerts.email.hookEnabled === true) {
      const hooked = await tryAlertHook({
        command: alerts.email.hookCommand,
        sink: "email",
        subject: params.subject,
        body: params.body,
        commandRunner: params.commandRunner,
      });
      if (hooked) {
        monitoringCounters.alertsDeliveredTotal += 1;
        return;
      }
    }
    const to = alerts.email.to?.trim();
    if (!to) {
      log.warn(`email alert target missing for subject="${params.subject}"`);
      log.warn(params.body);
      monitoringCounters.alertsFailedTotal += 1;
      return;
    }
    let delivered = false;
    for (const modulePath of [
      "../infra/email/send.js",
      "../email/send.js",
      "../hooks/email/send.js",
    ]) {
      try {
        const module = (await import(modulePath)) as {
          sendEmail?: (params: {
            to: string;
            from?: string;
            subject: string;
            text: string;
          }) => Promise<unknown>;
        };
        if (!module.sendEmail) {
          continue;
        }
        const prefix = alerts.email.subjectPrefix?.trim();
        await module.sendEmail({
          to,
          from: alerts.email.from,
          subject: prefix ? `${prefix} ${params.subject}` : params.subject,
          text: params.body,
        });
        delivered = true;
        break;
      } catch {
        // Continue to fallback behavior below.
      }
    }
    if (!delivered) {
      log.warn(`email alert utility unavailable; to=${to} subject="${params.subject}"`);
      log.warn(params.body);
      monitoringCounters.alertsFailedTotal += 1;
    } else {
      monitoringCounters.alertsDeliveredTotal += 1;
    }
    return;
  }

  if (params.sink === "telegram" && alerts.telegram?.enabled) {
    if (alerts.telegram.hookEnabled === true) {
      const hooked = await tryAlertHook({
        command: alerts.telegram.hookCommand,
        sink: "telegram",
        subject: params.subject,
        body: params.body,
        commandRunner: params.commandRunner,
      });
      if (hooked) {
        monitoringCounters.alertsDeliveredTotal += 1;
        return;
      }
    }
    const chatId = alerts.telegram.chatId?.trim();
    if (!chatId) {
      log.warn(`telegram alert chatId missing for subject="${params.subject}"`);
      log.warn(params.body);
      monitoringCounters.alertsFailedTotal += 1;
      return;
    }
    const token = await resolveManagedSecret({ config: cfg, value: alerts.telegram.botToken });
    if (!token.ok && alerts.telegram.botToken?.trim()) {
      log.warn(`telegram alert token resolver failed: ${token.reason}`);
    }
    try {
      const deps = createDefaultDeps();
      await deps.sendMessageTelegram(chatId, messageText, {
        ...(token.ok && token.value ? { token: token.value } : {}),
        ...(alerts.telegram.accountId ? { accountId: alerts.telegram.accountId } : {}),
        silent: true,
      });
    } catch (err) {
      log.warn(`telegram alert delivery failed: ${String(err)}`);
      log.warn(params.body);
      monitoringCounters.alertsFailedTotal += 1;
      return;
    }
    monitoringCounters.alertsDeliveredTotal += 1;
    return;
  }

  if (params.sink === "slack" && alerts.slack?.enabled) {
    if (alerts.slack.hookEnabled === true) {
      const hooked = await tryAlertHook({
        command: alerts.slack.hookCommand,
        sink: "slack",
        subject: params.subject,
        body: params.body,
        commandRunner: params.commandRunner,
      });
      if (hooked) {
        monitoringCounters.alertsDeliveredTotal += 1;
        return;
      }
    }
    const token = await resolveManagedSecret({ config: cfg, value: alerts.slack.botToken });
    if (!token.ok && alerts.slack.botToken?.trim()) {
      log.warn(`slack alert token resolver failed: ${token.reason}`);
    }

    const channel = alerts.slack.channel?.trim();
    if (channel) {
      try {
        const deps = createDefaultDeps();
        await deps.sendMessageSlack(channel, messageText, {
          ...(token.ok && token.value ? { token: token.value } : {}),
          ...(alerts.slack.accountId ? { accountId: alerts.slack.accountId } : {}),
        });
        monitoringCounters.alertsDeliveredTotal += 1;
        return;
      } catch (err) {
        log.warn(`slack alert channel delivery failed: ${String(err)}`);
      }
    }

    const webhook = await resolveManagedSecret({ config: cfg, value: alerts.slack.webhookUrl });
    if (webhook.ok && webhook.value.trim()) {
      try {
        const response = await fetch(webhook.value, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: messageText }),
        });
        if (!response.ok) {
          throw new Error(`status ${response.status}`);
        }
        monitoringCounters.alertsDeliveredTotal += 1;
        return;
      } catch (err) {
        log.warn(`slack alert webhook delivery failed: ${String(err)}`);
      }
    } else if (!webhook.ok && alerts.slack.webhookUrl?.trim()) {
      log.warn(`slack alert webhook resolver failed: ${webhook.reason}`);
    }

    log.warn(`slack alert fallback (not delivered) subject="${params.subject}"`);
    log.warn(params.body);
    monitoringCounters.alertsFailedTotal += 1;
    return;
  }

  monitoringCounters.alertsFailedTotal += 1;
}

function shouldSendAlert(params: {
  cooldownMap: Map<string, number>;
  config: OpenClawConfig;
  sink: AlertSink;
  subject: string;
  nowMs: number;
}): boolean {
  const cooldownSeconds = params.config.monitoring?.alerts?.cooldownSeconds ?? 300;
  if (cooldownSeconds <= 0) {
    return true;
  }
  const key = `${params.sink}:${params.subject}`;
  const prior = params.cooldownMap.get(key);
  if (prior && params.nowMs - prior < cooldownSeconds * 1000) {
    return false;
  }
  params.cooldownMap.set(key, params.nowMs);
  return true;
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
  const alertCooldownMap = new Map<string, number>();

  const maybeAlert = async (
    fresh: OpenClawConfig,
    sink: AlertSink,
    subject: string,
    body: string,
  ) => {
    if (
      !shouldSendAlert({
        cooldownMap: alertCooldownMap,
        config: fresh,
        sink,
        subject,
        nowMs: Date.now(),
      })
    ) {
      return;
    }
    await deliverMonitoringAlert({ config: fresh, sink, subject, body });
  };

  const tick = async () => {
    const fresh = applySecurityMonitoringDefaults(loadConfig());
    const metrics = collectMonitoringMetrics(fresh);
    await writeSecurityAuditEvent({
      config: fresh,
      event: "monitor.tick",
      payload: metrics,
    }).catch((err) => log.warn(`failed to write monitor tick: ${String(err)}`));

    if (fresh.monitoring?.queue?.enabled !== false && metrics.queueDepth >= queueThreshold) {
      await maybeAlert(
        fresh,
        "slack",
        "Queue depth warning",
        `queueDepth=${metrics.queueDepth} activeTasks=${metrics.activeTasks} threshold=${queueThreshold}`,
      );
    }
    if (fresh.monitoring?.resources?.enabled !== false && metrics.rssMb >= maxRssMb) {
      await maybeAlert(
        fresh,
        "email",
        "RSS threshold warning",
        `rssMb=${metrics.rssMb} threshold=${maxRssMb}`,
      );
    }
    if (fresh.monitoring?.resources?.enabled !== false && metrics.heapUsedMb >= maxHeapUsedMb) {
      await maybeAlert(
        fresh,
        "telegram",
        "Heap threshold warning",
        `heapUsedMb=${metrics.heapUsedMb} threshold=${maxHeapUsedMb}`,
      );
    }
  };

  const timer = setInterval(
    () => {
      void tick();
    },
    Math.max(5, sampleSeconds) * 1000,
  );
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
          ...context,
        },
      });
      monitoringCounters.errorsTrackedTotal += 1;
      await maybeAlert(
        fresh,
        "slack",
        "Error tracking event",
        error instanceof Error ? (error.stack ?? error.message) : String(error),
      );
    },
  };
}
