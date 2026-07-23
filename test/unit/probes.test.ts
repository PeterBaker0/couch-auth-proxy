/**
 * Health/ready probes must return non-sensitive `{ ok }` bodies only.
 */
import { describe, expect, it, vi } from "vitest";
import { createApp, createServices } from "../../src/app.js";
import { loadConfig } from "../../src/config.js";
import { anonymousPrincipal } from "../../src/auth/principal.js";

describe("health / ready probes", () => {
  it("health returns only { ok: true }", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const services = createServices(config);
    services.sessions.resolve = async () => anonymousPrincipal();
    const app = createApp(services);

    const res = await app.request("http://localhost/_couch-auth-proxy/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("ready returns only { ok } without DB inventory", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const services = createServices(config);
    services.sessions.resolve = async () => anonymousPrincipal();
    services.aclCache.adminClient.ping = vi.fn(async () => true);
    const app = createApp(services);

    const res = await app.request("http://localhost/_couch-auth-proxy/ready");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("ready is 503 with { ok: false } when Couch is down", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const services = createServices(config);
    services.sessions.resolve = async () => anonymousPrincipal();
    services.aclCache.adminClient.ping = vi.fn(async () => false);
    const app = createApp(services);

    const res = await app.request("http://localhost/_couch-auth-proxy/ready");
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ ok: false });
  });
});
