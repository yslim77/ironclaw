import { describe, expect, it } from "vitest";
import {
  applySecurityMonitoringDefaults,
  authorizeScopedToken,
  createSecurityRateLimitChecker,
  enforceSandboxPermissionGate,
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
  it("resolves env placeholders and reports keychain stubs", () => {
    const envResolved = resolveManagedSecret({
      config: {},
      value: "env:OPENCLAW_TEST_SECRET",
      env: { OPENCLAW_TEST_SECRET: "abc" },
    });
    expect(envResolved).toEqual({ ok: true, provider: "env", value: "abc" });

    const keychainStub = resolveManagedSecret({
      config: {},
      value: "keychain:openclaw/main",
    });
    expect(keychainStub.ok).toBe(false);
  });
});
