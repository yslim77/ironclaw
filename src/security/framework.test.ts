import { describe, expect, it } from "vitest";
import {
  applySecurityMonitoringDefaults,
  authorizeScopedToken,
  createSecurityRateLimitChecker,
  deliverMonitoringAlert,
  enforceSandboxPermissionGate,
  renderMonitoringMetrics,
  resolveManagedSecret,
  validateSecurityFrameworkConfig,
} from "./framework.js";

describe("security framework defaults", () => {
  it("injects baseline security and monitoring defaults", () => {
    const config = applySecurityMonitoringDefaults({});
    expect(config.security?.audit?.enabled).toBe(true);
    expect(config.security?.rbac?.enabled).toBe(true);
    expect(config.monitoring?.enabled).toBe(true);
    expect(config.monitoring?.resources?.sampleSeconds).toBe(30);
  });
});

describe("security framework config validation", () => {
  it("rejects duplicate scoped token values", () => {
    const result = validateSecurityFrameworkConfig({
      security: {
        rbac: {
          scopedTokens: {
            first: { token: "same-token" },
            second: { token: "same-token" },
          },
        },
      },
    });
    expect(result.some((issue) => issue.path.includes("second.token"))).toBe(true);
  });
});

describe("scoped token authorization", () => {
  it("authorizes valid scoped tokens", () => {
    const auth = authorizeScopedToken({
      config: {
        security: {
          rbac: {
            scopedTokens: {
              monitor: {
                token: "tkn-monitor",
                scopes: ["gateway.connect", "monitor.read"],
              },
            },
          },
        },
      },
      token: "tkn-monitor",
      requiredScope: "gateway.connect",
    });
    expect(auth.ok).toBe(true);
  });

  it("denies missing scopes", () => {
    const auth = authorizeScopedToken({
      config: {
        security: {
          rbac: {
            scopedTokens: {
              monitor: {
                token: "tkn-monitor",
                scopes: ["monitor.read"],
              },
            },
          },
        },
      },
      token: "tkn-monitor",
      requiredScope: "gateway.connect",
    });
    expect(auth).toEqual({ ok: false, reason: "scope_denied" });
  });
});

describe("security framework rate limiter", () => {
  it("enforces per-scope request budget", () => {
    const limiter = createSecurityRateLimitChecker({
      config: {
        security: {
          rateLimit: {
            default: { maxRequests: 2, windowMs: 60_000 },
          },
        },
      },
    });
    expect(limiter.check("gateway.connect", "ip:1").allowed).toBe(true);
    expect(limiter.check("gateway.connect", "ip:1").allowed).toBe(true);
    expect(limiter.check("gateway.connect", "ip:1").allowed).toBe(false);
  });
});

describe("sandbox permission gates", () => {
  it("rejects denied tools and paths", () => {
    const deniedTool = enforceSandboxPermissionGate({
      config: {
        security: {
          sandbox: {
            deniedTools: ["sandbox.bind"],
          },
        },
      },
      toolName: "sandbox.bind",
      targetPath: "/tmp/file.txt",
    });
    expect(deniedTool.ok).toBe(false);

    const deniedPath = enforceSandboxPermissionGate({
      config: {
        security: {
          sandbox: {
            deniedPaths: ["/etc"],
          },
        },
      },
      toolName: "sandbox.bind",
      targetPath: "/etc/passwd",
    });
    expect(deniedPath.ok).toBe(false);
  });
});

describe("secret resolver", () => {
  it("resolves env placeholders and reports keychain disabled state", async () => {
    const envResolved = await resolveManagedSecret({
      config: {},
      value: "env:OPENCLAW_TEST_SECRET",
      env: { OPENCLAW_TEST_SECRET: "abc" },
    });
    expect(envResolved).toEqual({ ok: true, provider: "env", value: "abc" });

    const keychainStub = await resolveManagedSecret({
      config: {},
      value: "keychain:openclaw/main",
    });
    expect(keychainStub.ok).toBe(false);
  });

  it("resolves macOS keychain placeholders when enabled", async () => {
    const resolved = await resolveManagedSecret({
      config: {
        security: {
          secrets: {
            providers: {
              keychain: { enabled: true, command: "security-wrapper" },
            },
          },
        },
      },
      value: "keychain:openclaw/main",
      platform: "darwin",
      commandRunner: async ({ file, args }) => {
        expect(file).toBe("security-wrapper");
        expect(args).toEqual(["find-generic-password", "-w", "-s", "openclaw", "-a", "main"]);
        return { stdout: "kc-secret\n", stderr: "" };
      },
    });
    expect(resolved).toEqual({ ok: true, provider: "keychain", value: "kc-secret" });
  });

  it("resolves 1Password placeholders via op read when enabled", async () => {
    const resolved = await resolveManagedSecret({
      config: {
        security: {
          secrets: {
            providers: {
              onePassword: { enabled: true, account: "my.1password.com", command: "op-wrapper" },
            },
          },
        },
      },
      value: "op://Private/Npmjs/password",
      commandRunner: async ({ file, args }) => {
        expect(file).toBe("op-wrapper");
        expect(args).toEqual([
          "read",
          "op://Private/Npmjs/password",
          "--account",
          "my.1password.com",
        ]);
        return { stdout: "op-secret\n", stderr: "" };
      },
    });
    expect(resolved).toEqual({ ok: true, provider: "1password", value: "op-secret" });
  });
});

describe("monitoring alerts", () => {
  it("supports hook-based alert delivery and publishes alert metrics", async () => {
    await deliverMonitoringAlert({
      config: {
        monitoring: {
          alerts: {
            email: {
              enabled: true,
              hookEnabled: true,
              hookCommand: "alert-hook",
            },
          },
        },
      },
      sink: "email",
      subject: "hook test",
      body: "hello",
      commandRunner: async ({ file, args, env }) => {
        expect(file).toBe("alert-hook");
        expect(args).toEqual(["email"]);
        expect(env?.OPENCLAW_ALERT_SUBJECT).toBe("hook test");
        return { stdout: "", stderr: "" };
      },
    });

    const metrics = renderMonitoringMetrics({});
    expect(metrics).toContain("openclaw_monitoring_alerts_delivered_total");
  });
});
