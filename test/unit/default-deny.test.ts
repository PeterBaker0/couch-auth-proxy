/**
 * Unit tests for unmapped-route default-deny (non-admins cannot silently pipe).
 */
import { describe, expect, it } from "vitest";
import { createApp, createServices } from "../../src/app.js";
import { loadConfig } from "../../src/config.js";
import { buildPrincipal } from "../../src/auth/principal.js";
import type { Principal } from "../../src/auth/types.js";
import type { DbAclState } from "../../src/acl/cache.js";

function principalAlice(): Principal {
  return buildPrincipal({
    ok: true,
    userCtx: { name: "alice", roles: ["readers"] },
    info: { authenticated: "cookie" },
  });
}

function readyState(name: string): DbAclState {
  return {
    name,
    acl: new Map(),
    noacl: false,
    ready: true,
    followerUp: true,
  };
}

describe("default-deny catch-all", () => {
  it("returns 404 for reserved underscore paths mistaken as doc ids", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      COUCH_ADMIN_USER: "admin",
      COUCH_ADMIN_PASSWORD: "password",
      RATE_LIMIT_ENABLED: "false",
    });
    const services = createServices(config);
    services.sessions.resolve = async () => principalAlice();
    services.aclCache.requireReady = async (db: string) => readyState(db);
    const app = createApp(services);

    const res = await app.request("http://localhost/acldemo/_purged_infos_limit");
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe("not_found");
  });

  it("returns 403 for unmapped system underscore paths", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const services = createServices(config);
    services.sessions.resolve = async () => principalAlice();
    const app = createApp(services);

    const res = await app.request("http://localhost/_membership");
    expect(res.status).toBe(403);
  });

  it("returns 404 from catch-all for unmapped methods", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const services = createServices(config);
    services.sessions.resolve = async () => principalAlice();
    const app = createApp(services);
    const res = await app.request("http://localhost/acldemo", { method: "PATCH" });
    expect(res.status).toBe(404);
  });
});
