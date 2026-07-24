/**
 * In-process route tests for authorization decisions that depend on request
 * rewriting rather than Couch itself.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { AclUnavailableError, type DbAclState } from "../../src/acl/cache.js";
import { aclRowFromDoc } from "../../src/acl/resolve.js";
import { compileRestrict } from "../../src/acl/restrict.js";
import { createApp, createServices } from "../../src/app.js";
import { anonymousPrincipal, buildPrincipal } from "../../src/auth/principal.js";
import type { Principal } from "../../src/auth/types.js";
import { loadConfig } from "../../src/config.js";
import { toClientResponse } from "../../src/proxy/forward.js";

function bobPrincipal() {
  return buildPrincipal({
    ok: true,
    userCtx: { name: "bob", roles: ["writers"] },
    info: { authenticated: "jwt" },
  });
}

function stateWith(docs: Array<Parameters<typeof aclRowFromDoc>[0]>): DbAclState {
  return {
    name: "docs",
    acl: new Map(docs.map((doc) => [doc._id, aclRowFromDoc(doc)])),
    noacl: false,
    ready: true,
    followerUp: true,
  };
}

function appWithState(state: DbAclState, maxIdLength = 200, principal: Principal = bobPrincipal()) {
  const config = loadConfig({
    COUCH_URL: "http://127.0.0.1:5984",
    COUCH_MAX_ID_LENGTH: String(maxIdLength),
    RATE_LIMIT_ENABLED: "false",
  });
  const services = createServices(config);
  services.sessions.resolve = async () => principal;
  services.aclCache.requireReady = async () => state;
  return { app: createApp(services), services };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("database authentication gate", () => {
  it("rejects anonymous access before forwarding ACL-backed database requests", async () => {
    const { app } = appWithState(stateWith([]), 200, anonymousPrincipal());
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_local/checkpoint", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({
      error: "unauthorized",
      reason: "Authentication required.",
    });
    expect(upstream).not.toHaveBeenCalled();
  });
});

describe("single-document authorization hardening", () => {
  it("returns 503 when a missing ACL row cannot be confirmed as a create", async () => {
    const state = stateWith([]);
    const { app, services } = appWithState(state);
    services.aclCache.refreshDoc = vi.fn(async () => {
      throw new AclUnavailableError("view failed");
    });
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/possibly-existing", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ creator: "bob" }),
    });

    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({
      error: "service_unavailable",
      reason: "ACL cache unavailable",
    });
    expect(upstream).not.toHaveBeenCalled();
  });

  it("enforces the configured document-id length before proxying", async () => {
    const { app } = appWithState(stateWith([]), 5);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/too-long", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });

    expect(res.status).toBe(404);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("requires delete permission for a PUT tombstone", async () => {
    const state = stateWith([{ _id: "owned", creator: "alice", owners: ["u-bob"] }]);
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/owned", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ _id: "owned", _rev: "2-old", _deleted: true }),
    });

    expect(res.status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("never forwards uninspectable multipart document writes for non-admins", async () => {
    const state = stateWith([{ _id: "owned", creator: "alice", owners: ["u-bob"] }]);
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/owned", {
      method: "PUT",
      headers: { "Content-Type": "multipart/related; boundary=docs" },
      body: "--docs\r\nContent-Type: application/json\r\n\r\n{}\r\n--docs--",
    });

    expect(res.status).toBe(415);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("requires write and delete permission for design update handlers", async () => {
    const state = stateWith([{ _id: "shared", creator: "alice", acl: ["u-bob"] }]);
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_design/app/_update/touch/shared", {
      method: "POST",
    });

    expect(res.status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("protects GET and HEAD update-handler invocations too", async () => {
    const state = stateWith([{ _id: "shared", creator: "alice", acl: ["u-bob"] }]);
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    for (const method of ["GET", "HEAD"]) {
      const res = await app.request("http://localhost/docs/_design/app/_update/touch/shared", {
        method,
      });
      expect(res.status, method).toBe(403);
    }
    expect(upstream).not.toHaveBeenCalled();
  });
});

describe("_bulk_docs input validation", () => {
  it("rejects a non-array docs envelope without throwing", async () => {
    const { app } = appWithState(stateWith([]));
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_bulk_docs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ docs: null }),
    });

    expect(res.status).toBe(400);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("returns a per-document error for a non-string id", async () => {
    const { app } = appWithState(stateWith([]));
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_bulk_docs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ docs: [{ _id: 42, value: "invalid" }] }),
    });

    expect(res.status).toBe(201);
    expect(await res.json()).toEqual([
      {
        error: "bad_request",
        reason: "Document id must be a non-empty string.",
      },
    ]);
    expect(upstream).not.toHaveBeenCalled();
  });
});

describe("replication revision probes", () => {
  it("refreshes unknown ids before deciding create-path access", async () => {
    const state = stateWith([]);
    const { app, services } = appWithState(state);
    services.aclCache.refreshDoc = vi.fn(async (_db: string, id: string) => {
      if (id === "private") {
        state.acl.set("private", aclRowFromDoc({ _id: "private", creator: "alice" }));
      }
    });
    const upstream = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body))).toEqual({
        "new-doc": ["1-new"],
      });
      return new Response(JSON.stringify({ "new-doc": { missing: ["1-new"] } }), {
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_revs_diff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        private: ["1-secret"],
        "new-doc": ["1-new"],
      }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ "new-doc": { missing: ["1-new"] } });
    expect(services.aclCache.refreshDoc).toHaveBeenCalledTimes(2);
  });
});

describe("Couch response compatibility", () => {
  it("drops shared validators on identity-filtered responses", async () => {
    const state = stateWith([
      { _id: "private", creator: "alice" },
      { _id: "shared", creator: "alice", acl: ["u-bob"] },
    ]);
    const { app } = appWithState(state);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        expect(new Headers(init?.headers).has("if-none-match")).toBe(false);
        return new Response(
          JSON.stringify({
            total_rows: 2,
            rows: [
              { id: "private", key: "private", value: { rev: "1-a" } },
              { id: "shared", key: "shared", value: { rev: "1-b" } },
            ],
          }),
          {
            headers: {
              "Content-Type": "application/json",
              ETag: '"couch-etag"',
              "X-Couch-Request-ID": "request-123",
              Connection: "keep-alive",
            },
          },
        );
      }),
    );

    const res = await app.request("http://localhost/docs/_all_docs", {
      headers: { "If-None-Match": '"previous-principal-etag"' },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("etag")).toBeNull();
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("x-couch-request-id")).toBe("request-123");
    expect(res.headers.get("connection")).toBeNull();
    const body = (await res.json()) as { rows: Array<{ id: string }> };
    expect(body.rows.map((row) => row.id)).toEqual(["shared"]);
  });

  it("fetches and filters GET representation for HEAD row endpoints", async () => {
    const state = stateWith([{ _id: "shared", creator: "alice", acl: ["u-bob"] }]);
    const { app } = appWithState(state);
    const upstream = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.method).toBe("GET");
      return new Response(
        JSON.stringify({
          rows: [{ id: "shared", key: "shared", value: { rev: "1-a" } }],
        }),
        { headers: { "Content-Type": "application/json", ETag: '"upstream"' } },
      );
    });
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_all_docs", { method: "HEAD" });
    expect(res.status).toBe(200);
    expect(res.headers.get("etag")).toBeNull();
    expect(await res.text()).toBe("");
    expect(upstream).toHaveBeenCalledOnce();
  });

  it("removes compressed framing when the fetch layer decoded the body", async () => {
    const res = toClientResponse(
      new Response("decoded", {
        headers: {
          "Content-Encoding": "gzip",
          "Content-Length": "42",
          "Content-Type": "text/plain",
        },
      }),
    );
    expect(res.headers.get("content-encoding")).toBeNull();
    expect(res.headers.get("content-length")).toBeNull();
    expect(await res.text()).toBe("decoded");
  });
});

describe("admin forwarding", () => {
  it("rejects protocol-relative paths instead of escaping the Couch origin", async () => {
    const admin = buildPrincipal({
      ok: true,
      userCtx: { name: "admin", roles: ["_admin"] },
      info: { authenticated: "default" },
    });
    const { app } = appWithState(stateWith([]), 200, admin);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost//127.0.0.1:9/secret", {
      headers: { Authorization: "Basic sensitive" },
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "bad_request",
      reason: "Invalid request path",
    });
    expect(upstream).not.toHaveBeenCalled();
  });

  it("passes official routes shadowed by generic patterns for admins", async () => {
    const admin = buildPrincipal({
      ok: true,
      userCtx: { name: "admin", roles: ["_admin"] },
      info: { authenticated: "default" },
    });
    const { app } = appWithState(stateWith([]), 200, admin);
    const upstream = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", upstream);

    expect((await app.request("http://localhost/_membership")).status).toBe(200);
    expect((await app.request("http://localhost/docs/_shards")).status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(2);
  });

  it("rewrites Couch-origin redirects so clients stay on the proxy", async () => {
    const admin = buildPrincipal({
      ok: true,
      userCtx: { name: "admin", roles: ["_admin"] },
      info: { authenticated: "default" },
    });
    const { app } = appWithState(stateWith([]), 200, admin);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        return new Response(null, {
          status: 301,
          headers: {
            Location: "http://127.0.0.1:5984/docs/_design/app/_view/by_kind?reduce=false",
          },
        });
      }),
    );

    const res = await app.request("http://proxy.test/docs");
    expect(res.status).toBe(301);
    expect(res.headers.get("location")).toBe("/docs/_design/app/_view/by_kind?reduce=false");
  });

  it("strips spoofed forwarded-host headers and rewrites Couch Location", async () => {
    const { app } = appWithState(stateWith([]));
    const upstream = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.has("x-forwarded-host")).toBe(false);
      expect(headers.has("x-forwarded-proto")).toBe(false);
      return new Response("{}", {
        status: 201,
        headers: { Location: "http://127.0.0.1:5984/docs/new" },
      });
    });
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/new", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-Host": "attacker.example",
        "X-Forwarded-Proto": "https",
      },
      body: JSON.stringify({ creator: "bob" }),
    });
    expect(res.status).toBe(201);
    expect(res.headers.get("location")).toBe("/docs/new");
  });
});

describe("no-ACL database route policy", () => {
  it("still enforces proxy admin-only routes", async () => {
    const state = stateWith([]);
    state.noacl = true;
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_index", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ index: { fields: ["kind"] } }),
    });
    expect(res.status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("continues to pass through ordinary COPY requests", async () => {
    const state = stateWith([]);
    state.noacl = true;
    const { app } = appWithState(state);
    const upstream = vi.fn(async () => new Response("{}", { status: 201 }));
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/source", {
      method: "COPY",
      headers: { Destination: "destination" },
    });
    expect(res.status).toBe(201);
    expect(upstream).toHaveBeenCalledOnce();
  });
});

describe("authoritative write refresh", () => {
  it("does not trust submitted ACL fields after new_edits:false writes", async () => {
    const state = stateWith([
      { _id: "shared", creator: "alice", owners: ["u-bob"], acl: ["u-bob"] },
    ]);
    const { app, services } = appWithState(state);
    services.aclCache.refreshDoc = vi.fn(async () => {
      state.acl.set(
        "shared",
        aclRowFromDoc({
          _id: "shared",
          _rev: "2-winning",
          creator: "alice",
          owners: ["u-bob"],
          acl: ["u-bob"],
        }),
      );
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("{}", { status: 201 })),
    );

    const res = await app.request("http://localhost/docs/shared?new_edits=false", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        _id: "shared",
        _rev: "1-replayed",
        creator: "alice",
        owners: ["u-bob"],
        acl: ["u-carol"],
      }),
    });

    expect(res.status).toBe(201);
    expect(services.aclCache.refreshDoc).toHaveBeenCalledWith("docs", "shared");
    expect(state.acl.get("shared")?._r["u-carol"]).toBeUndefined();
  });

  it("refreshes administrator writes instead of waiting for the follower", async () => {
    const state = stateWith([{ _id: "shared", creator: "alice" }]);
    const admin = buildPrincipal({
      ok: true,
      userCtx: { name: "admin", roles: ["_admin"] },
      info: { authenticated: "default" },
    });
    const { app, services } = appWithState(state, 200, admin);
    services.aclCache.refreshDoc = vi.fn(async () => {});
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("{}", { status: 201 })),
    );

    const res = await app.request("http://localhost/docs/shared", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ _id: "shared", creator: "alice", acl: [] }),
    });

    expect(res.status).toBe(201);
    expect(services.aclCache.refreshDoc).toHaveBeenCalledWith("docs", "shared");
  });

  it("retains tombstone grants when a non-winning revision is replayed", async () => {
    const state = stateWith([{ _id: "deleted", creator: "bob" }]);
    state.acl.set("deleted", { ...state.acl.get("deleted")!, deleted: true });
    const { app, services } = appWithState(state);
    services.aclCache.refreshDoc = vi.fn(async () => {
      state.acl.delete("deleted");
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("[]", { status: 201 })),
    );

    const res = await app.request("http://localhost/docs/deleted?new_edits=false", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ _id: "deleted", _rev: "1-old", creator: "bob" }),
    });

    expect(res.status).toBe(201);
    expect(state.acl.get("deleted")?.deleted).toBe(true);
    expect(state.acl.get("deleted")?._r["u-bob"]).toBe(1);
  });

  it("marks a successfully deleted parent before authorizing children", async () => {
    const state = stateWith([
      { _id: "parent", creator: "bob" },
      { _id: "child", creator: "alice", parent: "parent" },
    ]);
    const { app, services } = appWithState(state);
    services.aclCache.refreshDoc = vi.fn(async () => {
      state.acl.delete("parent");
    });
    const upstream = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", upstream);

    const deleted = await app.request("http://localhost/docs/parent", {
      method: "DELETE",
    });
    expect(deleted.status).toBe(200);
    expect(state.acl.get("parent")?.deleted).toBe(true);

    const child = await app.request("http://localhost/docs/child");
    expect(child.status).toBe(404);
    expect(upstream).toHaveBeenCalledOnce();
  });

  it("allows recreating a deleted document id after a deny-tombstone refresh", async () => {
    const alice = buildPrincipal({
      ok: true,
      userCtx: { name: "alice", roles: ["readers"] },
      info: { authenticated: "jwt" },
    });
    const state = stateWith([{ _id: "gone", creator: "alice", acl: ["u-bob"] }]);
    const { app, services } = appWithState(state, 200, alice);
    services.aclCache.refreshDoc = vi.fn(async () => {
      // Simulate failed pre-delete recovery: empty deny row replaces grants.
      state.acl.set("gone", {
        s: "2-deleted",
        p: "",
        deleted: true,
        _r: {},
        _w: {},
        _d: {},
      });
    });
    const upstream = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const method = (init?.method ?? "GET").toUpperCase();
      if (method === "DELETE") return new Response('{"ok":true}', { status: 200 });
      return new Response('{"ok":true}', { status: 201 });
    });
    vi.stubGlobal("fetch", upstream);

    const deleted = await app.request("http://localhost/docs/gone", { method: "DELETE" });
    expect(deleted.status).toBe(200);
    // Retained pre-delete grants win over the empty deny reconstruction.
    expect(state.acl.get("gone")).toMatchObject({
      deleted: true,
      _r: { "u-alice": 1, "u-bob": 1 },
      _w: { "u-alice": 1 },
    });

    const recreated = await app.request("http://localhost/docs/gone", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ _id: "gone", creator: "alice", acl: ["u-bob"], body: "back" }),
    });
    expect(recreated.status).toBe(201);
    expect(upstream).toHaveBeenCalledTimes(2);
  });
});

describe("COPY destination authorization", () => {
  const state = stateWith([
    { _id: "source", creator: "alice", acl: ["u-bob"] },
    { _id: "destination", creator: "alice" },
  ]);

  it("authorizes the destination id without its revision query", async () => {
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/source", {
      method: "COPY",
      headers: { Destination: "destination?rev=2-existing" },
    });

    expect(res.status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("rejects absolute and cross-database destination paths", async () => {
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    for (const destination of ["other-db/destination", "/docs/destination", "https://x/doc"]) {
      const res = await app.request("http://localhost/docs/source", {
        method: "COPY",
        headers: { Destination: destination },
      });
      expect(res.status, destination).toBe(400);
    }
    expect(upstream).not.toHaveBeenCalled();
  });

  it("applies PUT method restrictions to the COPY destination", async () => {
    const restricted = stateWith([{ _id: "source", creator: "alice", acl: ["u-bob"] }]);
    restricted.compiledRestrict = compileRestrict({
      put: { "*": [] },
    });
    const { app } = appWithState(restricted);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/source", {
      method: "COPY",
      headers: { Destination: "new-document" },
    });

    expect(res.status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });
});

describe("reserved design endpoints", () => {
  it("classifies CouchDB 3.5 search and rewrite routes before attachments", async () => {
    const state = stateWith([{ _id: "_design/app" }]);
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    for (const path of [
      "/docs/_design/app/_search/by_name",
      "/docs/_design/app/_nouveau/by_name",
      "/docs/_design/app/_search_info/by_name",
      "/docs/_design/app/_nouveau_info/by_name",
      "/docs/_design/app/_rewrite",
    ]) {
      const res = await app.request(`http://localhost${path}`);
      expect(res.status, path).toBe(403);
    }
    expect(upstream).not.toHaveBeenCalled();
  });

  it("rejects encoded design separators before generic attachment routing", async () => {
    const state = stateWith([{ _id: "_design/app" }, { _id: "private", creator: "alice" }]);
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    for (const path of [
      "/docs/_design%2Fapp/_view/by_kind?include_docs=true",
      "/docs/_design/app/_view%2Fby_kind?include_docs=true",
      "/docs/_design/app/_search%2Fby_name",
      "/docs/_design/app/_rewrite%2Ftarget",
    ]) {
      const res = await app.request(`http://localhost${path}`);
      expect(res.status, path).toBe(404);
    }
    expect(upstream).not.toHaveBeenCalled();
  });
});

describe("_bulk_get cache synchronization", () => {
  it("refreshes requested ids before filtering the Couch response", async () => {
    const state = stateWith([]);
    const { app, services } = appWithState(state);
    services.aclCache.refreshDoc = vi.fn(async (_db: string, id: string) => {
      state.acl.set(id, aclRowFromDoc({ _id: id, creator: "bob" }));
    });
    const upstream = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body))).toEqual({
        docs: [{ id: "just-created" }, { id: "just-created" }],
      });
      return new Response(
        JSON.stringify({
          results: [{ id: "just-created", docs: [{ ok: { _id: "just-created" } }] }],
        }),
        { headers: { "Content-Type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_bulk_get", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ docs: [{ id: "just-created" }, { id: "just-created" }] }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      results: [{ id: "just-created", docs: [{ ok: { _id: "just-created" } }] }],
    });
    expect(services.aclCache.refreshDoc).toHaveBeenCalledWith("docs", "just-created");
    expect(services.aclCache.refreshDoc).toHaveBeenCalledTimes(1);
  });
});

describe("Mango field projection", () => {
  it("injects _id for filtering and removes it from the client projection", async () => {
    const state = stateWith([
      { _id: "private", creator: "alice" },
      { _id: "shared", creator: "alice", acl: ["u-bob"] },
    ]);
    const { app } = appWithState(state);
    const upstream = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const request = JSON.parse(String(init?.body)) as { fields: string[] };
      expect(request.fields).toEqual(["kind", "_id"]);
      return new Response(
        JSON.stringify({
          docs: [
            { _id: "private", kind: "secret" },
            { _id: "shared", kind: "visible" },
          ],
          bookmark: "next",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_find", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        selector: { kind: { $exists: true } },
        fields: ["kind"],
      }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      docs: [{ kind: "visible" }],
      bookmark: "next",
    });
    expect(upstream).toHaveBeenCalledOnce();
  });

  it("preserves Couch's all-fields behavior for an empty fields array", async () => {
    const state = stateWith([
      { _id: "private", creator: "alice" },
      { _id: "shared", creator: "alice", acl: ["u-bob"] },
    ]);
    const { app } = appWithState(state);
    const upstream = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const request = JSON.parse(String(init?.body)) as { fields: string[] };
      expect(request.fields).toEqual([]);
      return new Response(
        JSON.stringify({
          docs: [
            { _id: "private", kind: "secret" },
            { _id: "shared", kind: "visible" },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", upstream);

    const res = await app.request("http://localhost/docs/_find", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selector: {}, fields: [] }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      docs: [{ _id: "shared", kind: "visible" }],
    });
  });
});
