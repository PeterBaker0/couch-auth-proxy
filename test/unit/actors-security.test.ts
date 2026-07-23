/**
 * In-process route tests for authorization decisions that depend on request
 * rewriting rather than Couch itself.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { AclUnavailableError, type DbAclState } from "../../src/acl/cache.js";
import { aclRowFromDoc } from "../../src/acl/resolve.js";
import { createApp, createServices } from "../../src/app.js";
import { buildPrincipal } from "../../src/auth/principal.js";
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

function appWithState(state: DbAclState, maxIdLength = 200) {
  const config = loadConfig({
    COUCH_URL: "http://127.0.0.1:5984",
    COUCH_MAX_ID_LENGTH: String(maxIdLength),
    RATE_LIMIT_ENABLED: "false",
  });
  const services = createServices(config);
  services.sessions.resolve = async () => bobPrincipal();
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
});
