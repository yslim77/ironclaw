import type { IncomingMessage, ServerResponse } from "node:http";
import { describe, expect, test, vi } from "vitest";
import type { ResolvedGatewayAuth } from "./auth.js";
import { createGatewayHttpServer } from "./server-http.js";
import { withTempConfig } from "./test-temp-config.js";

function createRequest(params: {
  path: string;
  authorization?: string;
  method?: string;
}): IncomingMessage {
  const headers: Record<string, string> = {
    host: "localhost:18789",
  };
  if (params.authorization) {
    headers.authorization = params.authorization;
  }
  return {
    method: params.method ?? "GET",
    url: params.path,
    headers,
    socket: { remoteAddress: "127.0.0.1" },
  } as IncomingMessage;
}

function createResponse(): {
  res: ServerResponse;
  setHeader: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
  getBody: () => string;
} {
  const setHeader = vi.fn();
  let body = "";
  const end = vi.fn((chunk?: unknown) => {
    if (typeof chunk === "string") {
      body = chunk;
      return;
    }
    if (chunk == null) {
      body = "";
      return;
    }
    body = JSON.stringify(chunk);
  });
  const res = {
    headersSent: false,
    statusCode: 200,
    setHeader,
    end,
  } as unknown as ServerResponse;
  return {
    res,
    setHeader,
    end,
    getBody: () => body,
  };
}

async function dispatchRequest(
  server: ReturnType<typeof createGatewayHttpServer>,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  server.emit("request", req, res);
  await new Promise((resolve) => setImmediate(resolve));
}

describe("gateway metrics endpoint", () => {
  test("serves Prometheus metrics with gateway auth", async () => {
    const resolvedAuth: ResolvedGatewayAuth = {
      mode: "token",
      token: "test-token",
      password: undefined,
      allowTailscale: false,
    };

    await withTempConfig({
      cfg: {
        gateway: { trustedProxies: [] },
        monitoring: { enabled: true, metrics: { enabled: true, path: "/metrics" } },
      },
      prefix: "openclaw-server-metrics-test-",
      run: async () => {
        const server = createGatewayHttpServer({
          canvasHost: null,
          clients: new Set(),
          controlUiEnabled: false,
          controlUiBasePath: "/__control__",
          openAiChatCompletionsEnabled: false,
          openResponsesEnabled: false,
          handleHooksRequest: async () => false,
          resolvedAuth,
        });

        const unauth = createResponse();
        await dispatchRequest(server, createRequest({ path: "/metrics" }), unauth.res);
        expect(unauth.res.statusCode).toBe(401);

        const authed = createResponse();
        await dispatchRequest(
          server,
          createRequest({ path: "/metrics", authorization: "Bearer test-token" }),
          authed.res,
        );
        expect(authed.res.statusCode).toBe(200);
        expect(authed.getBody()).toContain("openclaw_monitoring_queue_depth");
        expect(authed.getBody()).toContain("openclaw_monitoring_alerts_delivered_total");
      },
    });
  });

  test("returns method not allowed for non-GET metrics calls", async () => {
    const resolvedAuth: ResolvedGatewayAuth = {
      mode: "token",
      token: "test-token",
      password: undefined,
      allowTailscale: false,
    };

    await withTempConfig({
      cfg: {
        gateway: { trustedProxies: [] },
        monitoring: { enabled: true, metrics: { enabled: true, path: "/metrics" } },
      },
      prefix: "openclaw-server-metrics-method-test-",
      run: async () => {
        const server = createGatewayHttpServer({
          canvasHost: null,
          clients: new Set(),
          controlUiEnabled: false,
          controlUiBasePath: "/__control__",
          openAiChatCompletionsEnabled: false,
          openResponsesEnabled: false,
          handleHooksRequest: async () => false,
          resolvedAuth,
        });

        const res = createResponse();
        await dispatchRequest(
          server,
          createRequest({
            path: "/metrics",
            method: "POST",
            authorization: "Bearer test-token",
          }),
          res.res,
        );
        expect(res.res.statusCode).toBe(405);
      },
    });
  });
});
