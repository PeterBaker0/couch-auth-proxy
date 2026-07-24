/**
 * In-process HTTP tests for env DB/route access policy enforcement.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DbAclState } from "../../src/acl/cache.js";
import { createApp, createServices } from "../../src/app.js";
import { buildPrincipal } from "../../src/auth/principal.js";
import type { Principal } from "../../src/auth/types.js";
import { loadConfig } from "../../src/config.js";

function principal(name: string, roles: string[] = []): Principal {
  return buildPrincipal({
    ok: true,
    userCtx: { name, roles },
    info: { authenticated: "jwt" },
  });
}

function openState(name: string): DbAclState {
  return {
    name,
    acl: new Map(),
    noacl: false,
    ready: true,
    followerUp: true,
  };
}

function appWithPolicy(
  env: Record<string, string>,
  user: Principal = principal("alice", ["readers"]),
) {
  const config = loadConfig({
    COUCH_URL: "http://127.0.0.1:5984",
    RATE_LIMIT_ENABLED: "false",
    ...env,
  });
  const services = createServices(config);
  services.sessions.resolve = async () => user;
  services.aclCache.requireReady = async (db) => openState(db);
  services.aclCache.inspectAccessPolicy = async () => ({
    compiledRestrict: undefined,
    noacl: false,
  });
  return { app: createApp(services), services };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("env DB access policy (HTTP)", () => {
  it("defaults to historical behaviour (no DB blocking)", async () => {
    const { app } = appWithPolicy({});
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ db_name: "acldemo" }), { status: 200 })),
    );
    const res = await app.request("http://localhost/acldemo");
    expect(res.status).toBe(200);
  });

  it("404s non-matching DBs when ACL_DB_INCLUDE is set", async () => {
    const { app } = appWithPolicy({ ACL_DB_INCLUDE: "/^data-/" });
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const denied = await app.request("http://localhost/acldemo");
    expect(denied.status).toBe(404);
    expect(await denied.json()).toEqual({
      error: "not_found",
      reason: "Database does not exist.",
    });
    expect(upstream).not.toHaveBeenCalled();

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ db_name: "data-app" }), { status: 200 })),
    );
    const allowed = await app.request("http://localhost/data-app");
    expect(allowed.status).toBe(200);
  });

  it("applies ACL_DB_EXCLUDE even when include would allow", async () => {
    const { app } = appWithPolicy({
      ACL_DB_INCLUDE: "/^data-/",
      ACL_DB_EXCLUDE: "data-secret",
    });
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);
    const res = await app.request("http://localhost/data-secret");
    expect(res.status).toBe(404);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("filters _all_dbs through env DB policy", async () => {
    const { app } = appWithPolicy({ ACL_DB_INCLUDE: "/^data-/" });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify(["acldemo", "data-a", "data-b", "_users"]), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
    const res = await app.request("http://localhost/_all_dbs");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(["data-a", "data-b"]);
  });

  it("lets admins bypass DB policy", async () => {
    const { app } = appWithPolicy({ ACL_DB_INCLUDE: "/^data-/" }, principal("admin", ["_admin"]));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ db_name: "acldemo" }), { status: 200 })),
    );
    const res = await app.request("http://localhost/acldemo");
    expect(res.status).toBe(200);
  });
});

describe("env route access policy (HTTP)", () => {
  it("403s routes outside ACL_ROUTE_INCLUDE", async () => {
    const { app } = appWithPolicy({ ACL_ROUTE_INCLUDE: "session,docs,db" });
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const find = await app.request("http://localhost/data-app/_find", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(find.status).toBe(403);
    expect(await find.json()).toEqual({
      error: "forbidden",
      reason: "Endpoint not allowed.",
    });
    expect(upstream).not.toHaveBeenCalled();
  });

  it("allows pouch-sync bundle routes", async () => {
    const { app } = appWithPolicy({
      ACL_DB_INCLUDE: "/^data-/",
      ACL_ROUTE_INCLUDE: "pouch-sync",
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () => new Response(JSON.stringify({ results: [], last_seq: "0" }), { status: 200 }),
      ),
    );
    const changes = await app.request("http://localhost/data-app/_changes");
    expect(changes.status).toBe(200);
  });

  it("excludes features listed in ACL_ROUTE_EXCLUDE", async () => {
    const { app } = appWithPolicy({
      ACL_ROUTE_INCLUDE: "pouch-sync,find",
      ACL_ROUTE_EXCLUDE: "find",
    });
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);
    const find = await app.request("http://localhost/db/_find", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(find.status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("does not gate health/ready probes", async () => {
    const { app, services } = appWithPolicy({ ACL_ROUTE_INCLUDE: "session" });
    services.aclCache.adminClient.ping = async () => true;
    expect((await app.request("http://localhost/_couch-auth-proxy/health")).status).toBe(200);
    expect((await app.request("http://localhost/_couch-auth-proxy/ready")).status).toBe(200);
  });

  it("supports request-path regex route includes", async () => {
    const { app } = appWithPolicy({
      ACL_ROUTE_INCLUDE: "/^GET \\/data-[^/]+\\/_changes$/",
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () => new Response(JSON.stringify({ results: [], last_seq: "0" }), { status: 200 }),
      ),
    );
    expect((await app.request("http://localhost/data-app/_changes")).status).toBe(200);

    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);
    expect((await app.request("http://localhost/acldemo/_changes")).status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });
});
