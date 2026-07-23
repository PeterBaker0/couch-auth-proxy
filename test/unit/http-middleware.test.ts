import { describe, expect, it } from "vitest";
import { createApp, createServices } from "../../src/app.js";
import { loadConfig } from "../../src/config.js";

describe("HTTP compatibility middleware", () => {
  it("returns 503, not a gateway error, for global overload", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "true",
      RATE_LIMIT_MAX: "1",
      RATE_LIMIT_WINDOW_MS: "60000",
      RATE_LIMIT_IP_MAX: "100",
    });
    const app = createApp(createServices(config));

    expect((await app.request("http://localhost/_couch-auth-proxy/health")).status).toBe(200);
    const limited = await app.request("http://localhost/_couch-auth-proxy/health");
    expect(limited.status).toBe(503);
    expect(await limited.json()).toEqual({
      error: "service_unavailable",
      reason: "rate limit",
    });
  });

  it("allows Couch conditional and range headers in browser preflights", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
      CORS_ORIGINS: "https://app.example",
    });
    const app = createApp(createServices(config));
    const res = await app.request("http://localhost/docs/doc", {
      method: "OPTIONS",
      headers: {
        Origin: "https://app.example",
        "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "if-match,range,x-couch-full-commit",
      },
    });

    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://app.example");
    const headers = res.headers.get("access-control-allow-headers")?.toLowerCase() ?? "";
    expect(headers).toContain("if-match");
    expect(headers).toContain("range");
    expect(headers).toContain("x-couch-full-commit");
  });

  it("returns an opaque 500 response for unexpected middleware failures", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const services = createServices(config);
    services.sessions.resolve = async () => {
      throw new Error("credential backend detail");
    };
    const app = createApp(services);

    const res = await app.request("http://localhost/_couch-auth-proxy/health", {
      headers: { Authorization: "Bearer invalid" },
    });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({
      error: "internal_server_error",
      reason: "Internal server error",
    });
  });
});
