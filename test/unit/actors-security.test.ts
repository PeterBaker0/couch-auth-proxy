/**
 * In-process route tests for authorization decisions that depend on request
 * rewriting rather than Couch itself.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { AclUnavailableError, type DbAclState } from "../../src/acl/cache.js";
import { aclRowFromDoc } from "../../src/acl/resolve.js";
import { compileRestrict } from "../../src/acl/restrict.js";
import { createApp, createServices } from "../../src/app.js";
import { buildPrincipal } from "../../src/auth/principal.js";
import type { Principal } from "../../src/auth/types.js";
import { loadConfig } from "../../src/config.js";

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
  it("preserves end-to-end Couch headers on filtered responses", async () => {
    const state = stateWith([
      { _id: "private", creator: "alice" },
      { _id: "shared", creator: "alice", acl: ["u-bob"] },
    ]);
    const { app } = appWithState(state);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
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

    const res = await app.request("http://localhost/docs/_all_docs");
    expect(res.status).toBe(200);
    expect(res.headers.get("etag")).toBe('"couch-etag"');
    expect(res.headers.get("x-couch-request-id")).toBe("request-123");
    expect(res.headers.get("connection")).toBeNull();
    const body = (await res.json()) as { rows: Array<{ id: string }> };
    expect(body.rows.map((row) => row.id)).toEqual(["shared"]);
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

  it("rejects encoded design prefixes before generic attachment routing", async () => {
    const state = stateWith([{ _id: "_design/app" }, { _id: "private", creator: "alice" }]);
    const { app } = appWithState(state);
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);

    const res = await app.request(
      "http://localhost/docs/_design%2Fapp/_view/by_kind?include_docs=true",
    );

    expect(res.status).toBe(404);
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
      expect(JSON.parse(String(init?.body))).toEqual({ docs: [{ id: "just-created" }] });
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
      body: JSON.stringify({ docs: [{ id: "just-created" }] }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      results: [{ id: "just-created", docs: [{ ok: { _id: "just-created" } }] }],
    });
    expect(services.aclCache.refreshDoc).toHaveBeenCalledWith("docs", "just-created");
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
