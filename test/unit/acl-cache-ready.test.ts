/**
 * Unit tests for AclCache readiness / fail-closed behavior when the
 * changes follower is down or ensure fails.
 */
import { describe, expect, it, vi } from "vitest";
import { AclCache, AclUnavailableError, type DbAclState } from "../../src/acl/cache.js";
import { ChangesFollower } from "../../src/acl/changesFollower.js";
import { ACL_MAP_SOURCE } from "../../src/acl/ddoc.js";
import { loadConfig } from "../../src/config.js";

function cacheWithState(state: DbAclState): AclCache {
  const config = loadConfig({
    COUCH_URL: "http://127.0.0.1:5984",
    COUCH_ADMIN_USER: "admin",
    COUCH_ADMIN_PASSWORD: "password",
    RATE_LIMIT_ENABLED: "false",
  });
  const cache = new AclCache(config);
  (cache as unknown as { dbs: Map<string, DbAclState> }).dbs.set(state.name, state);
  return cache;
}

describe("AclCache.requireReady", () => {
  it("fails closed when the changes follower is down", async () => {
    const cache = cacheWithState({
      name: "acldemo",
      acl: new Map(),
      noacl: false,
      ready: true,
      followerUp: false,
    });
    await expect(cache.requireReady("acldemo")).rejects.toBeInstanceOf(AclUnavailableError);
    await expect(cache.requireReady("acldemo")).rejects.toThrow(/follower/i);
  });

  it("allows noacl buckets without a live follower", async () => {
    const cache = cacheWithState({
      name: "passthru",
      acl: new Map(),
      noacl: true,
      ready: true,
      followerUp: false,
    });
    const state = await cache.requireReady("passthru");
    expect(state.noacl).toBe(true);
  });

  it("allows ready ACL buckets with follower up", async () => {
    const cache = cacheWithState({
      name: "acldemo",
      acl: new Map(),
      noacl: false,
      ready: true,
      followerUp: true,
    });
    const state = await cache.requireReady("acldemo");
    expect(state.name).toBe("acldemo");
  });
});

describe("ChangesFollower onUp / onError", () => {
  it("signals onUp after a successful feed open", async () => {
    const enc = new TextEncoder();
    const admin = {
      fetch: vi.fn(async () => ({
        ok: true,
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(enc.encode("\n"));
          },
        }),
      })),
    };

    const events: string[] = [];
    const follower = new ChangesFollower(
      admin as never,
      "acldemo",
      {
        onChange: async () => {},
        onUp: () => events.push("up"),
        onError: () => events.push("err"),
      },
      "0",
    );

    follower.start();
    await vi.waitFor(() => expect(events).toContain("up"), { timeout: 2000 });
    follower.stop();
    expect(events).toContain("up");
  });

  it("signals onError when the feed request fails", async () => {
    const admin = {
      fetch: vi.fn(async () => ({ ok: false, body: null, status: 500 })),
    };
    const events: string[] = [];
    const follower = new ChangesFollower(
      admin as never,
      "acldemo",
      {
        onChange: async () => {},
        onUp: () => events.push("up"),
        onError: () => events.push("err"),
      },
      "0",
    );
    follower.start();
    await vi.waitFor(() => expect(events).toContain("err"), { timeout: 2000 });
    follower.stop();
    expect(events).not.toContain("up");
  });

  it("does not advance past a change whose ACL refresh failed", async () => {
    const enc = new TextEncoder();
    let calls = 0;
    const admin = {
      fetch: vi.fn(async () => {
        calls += 1;
        if (calls > 1) return { ok: false, body: null, status: 500 };
        return {
          ok: true,
          body: new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(
                enc.encode('{"id":"secret","seq":"5-opaque","changes":[{"rev":"2-x"}]}\n'),
              );
            },
          }),
        };
      }),
    };
    const errors: unknown[] = [];
    const follower = new ChangesFollower(
      admin as never,
      "acldemo",
      {
        onChange: async () => {
          throw new Error("ACL view failed");
        },
        onError: (err) => errors.push(err),
      },
      "4-previous",
    );

    follower.start();
    await vi.waitFor(() => expect(errors).toHaveLength(1), { timeout: 2000 });
    expect(follower.lastSeq).toBe("4-previous");
    follower.stop();
  });
});

describe("AclCache row refresh failures", () => {
  it("retains rows but marks the DB unavailable when a change refresh fails", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      COUCH_ADMIN_USER: "admin",
      COUCH_ADMIN_PASSWORD: "password",
      RATE_LIMIT_ENABLED: "false",
    });
    const cache = new AclCache(config);
    const state: DbAclState = {
      name: "acldemo",
      acl: new Map([
        [
          "secret",
          {
            s: "1-abc",
            p: "",
            _r: { "u-alice": 1 },
            _w: { "u-alice": 1 },
            _d: { "u-alice": 1 },
          },
        ],
      ]),
      noacl: false,
      ready: true,
      followerUp: true,
    };
    (cache as unknown as { dbs: Map<string, DbAclState> }).dbs.set("acldemo", state);

    cache.adminClient.json = vi.fn(async () => ({
      ok: false as const,
      status: 500,
      text: "boom",
    })) as typeof cache.adminClient.json;

    await expect(
      (
        cache as unknown as {
          applyChange: (
            db: string,
            state: DbAclState,
            id: string,
            deleted?: boolean,
          ) => Promise<void>;
        }
      ).applyChange("acldemo", state, "secret", false),
    ).rejects.toBeInstanceOf(AclUnavailableError);

    expect(state.acl.has("secret")).toBe(true);
    expect(state.ready).toBe(false);
    expect(state.followerUp).toBe(false);
    expect(state.error).toMatch(/refresh failed/i);
  });

  it("fails closed when an on-demand missing-row lookup fails", async () => {
    const cache = cacheWithState({
      name: "acldemo",
      acl: new Map(),
      noacl: false,
      ready: true,
      followerUp: true,
    });
    cache.adminClient.json = vi.fn(async () => ({
      ok: false as const,
      status: 500,
      text: "boom",
    })) as typeof cache.adminClient.json;

    await expect(cache.refreshDoc("acldemo", "possibly-existing")).rejects.toBeInstanceOf(
      AclUnavailableError,
    );
    const state = cache.get("acldemo")!;
    expect(state.ready).toBe(false);
    expect(state.followerUp).toBe(false);
    expect(state.error).toMatch(/row unavailable/i);
  });

  it("fails closed when a row refresh throws before returning an HTTP result", async () => {
    const cache = cacheWithState({
      name: "acldemo",
      acl: new Map(),
      noacl: false,
      ready: true,
      followerUp: true,
    });
    cache.adminClient.json = vi.fn(async () => {
      throw new SyntaxError("invalid view JSON");
    }) as typeof cache.adminClient.json;

    await expect(cache.refreshDoc("acldemo", "unknown")).rejects.toBeInstanceOf(
      AclUnavailableError,
    );
    expect(cache.get("acldemo")).toMatchObject({
      ready: false,
      followerUp: false,
    });
  });

  it("keeps ACL rows on deleted:true so tombstones stay readable", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const cache = new AclCache(config);
    const state: DbAclState = {
      name: "acldemo",
      acl: new Map([
        [
          "secret",
          {
            s: "1-abc",
            p: "",
            _r: { "u-alice": 1, "u-bob": 1 },
            _w: { "u-alice": 1 },
            _d: { "u-alice": 1 },
          },
        ],
      ]),
      noacl: false,
      ready: true,
      followerUp: true,
    };
    (cache as unknown as { dbs: Map<string, DbAclState> }).dbs.set("acldemo", state);

    await (
      cache as unknown as {
        applyChange: (
          db: string,
          state: DbAclState,
          id: string,
          deleted?: boolean,
          rev?: string,
        ) => Promise<void>;
      }
    ).applyChange("acldemo", state, "secret", true, "2-dead");

    expect(state.acl.has("secret")).toBe(true);
    expect(state.acl.get("secret")?._r["u-bob"]).toBe(1);
  });

  it("deletes ACL rows when the view confirms absence", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const cache = new AclCache(config);
    const state: DbAclState = {
      name: "acldemo",
      acl: new Map([
        [
          "gone",
          {
            s: "1-abc",
            p: "",
            _r: { "u-alice": 1 },
            _w: { "u-alice": 1 },
            _d: { "u-alice": 1 },
          },
        ],
      ]),
      noacl: false,
      ready: true,
      followerUp: true,
    };
    (cache as unknown as { dbs: Map<string, DbAclState> }).dbs.set("acldemo", state);

    cache.adminClient.json = vi.fn(async () => ({
      ok: true as const,
      status: 200,
      body: { rows: [{ key: "gone", error: "not_found" }] },
    })) as typeof cache.adminClient.json;

    await (
      cache as unknown as {
        applyChange: (
          db: string,
          state: DbAclState,
          id: string,
          deleted?: boolean,
          rev?: string,
        ) => Promise<void>;
      }
    ).applyChange("acldemo", state, "gone", false);

    expect(state.acl.has("gone")).toBe(false);
  });

  it("derives a shipped-map ACL row when the live view index briefly lags", async () => {
    const cache = cacheWithState({
      name: "acldemo",
      acl: new Map(),
      generatedAclMap: true,
      noacl: false,
      ready: true,
      followerUp: true,
    });
    cache.adminClient.json = vi.fn(async (path: string) => {
      if (path.endsWith("/_view/acl")) {
        return {
          ok: true as const,
          status: 200,
          body: { rows: [{ key: "fresh", error: "not_found" }] },
        };
      }
      if (path.endsWith("/_all_docs")) {
        return {
          ok: true as const,
          status: 200,
          body: { rows: [{ id: "fresh", value: { rev: "1-fresh" } }] },
        };
      }
      return {
        ok: true as const,
        status: 200,
        body: {
          _id: "fresh",
          _rev: "1-fresh",
          creator: "alice",
          acl: ["u-bob"],
        },
      };
    }) as typeof cache.adminClient.json;

    await cache.refreshDoc("acldemo", "fresh");

    expect(cache.get("acldemo")?.acl.get("fresh")?._r).toMatchObject({
      "u-alice": 1,
      "u-bob": 1,
    });
  });

  it("recovers ACL from pre-delete revision when cache was cold", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const cache = new AclCache(config);
    const state: DbAclState = {
      name: "acldemo",
      acl: new Map(),
      generatedAclMap: true,
      noacl: false,
      ready: true,
      followerUp: true,
    };
    (cache as unknown as { dbs: Map<string, DbAclState> }).dbs.set("acldemo", state);

    cache.adminClient.json = vi.fn(
      async (path: string, init?: { query?: Record<string, string> }) => {
        const rev = init?.query?.rev;
        if (rev === "2-del" && init?.query?.revs === "true") {
          return {
            ok: true as const,
            status: 200,
            body: {
              _deleted: true,
              _revisions: { start: 2, ids: ["del", "alive"] },
            },
          };
        }
        if (rev === "1-alive") {
          return {
            ok: true as const,
            status: 200,
            body: {
              _id: "cold",
              creator: "alice",
              acl: ["u-bob"],
            },
          };
        }
        return { ok: false as const, status: 404, text: "missing" };
      },
    ) as typeof cache.adminClient.json;

    await (
      cache as unknown as {
        applyChange: (
          db: string,
          state: DbAclState,
          id: string,
          deleted?: boolean,
          rev?: string,
        ) => Promise<void>;
      }
    ).applyChange("acldemo", state, "cold", true, "2-del");

    expect(state.acl.get("cold")?._r["u-bob"]).toBe(1);
    expect(state.acl.get("cold")?._w["u-alice"]).toBe(1);
  });
});

describe("AclCache auto-install policy", () => {
  it("inspects _all_dbs visibility without installing or caching ACL state", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      ACL_AUTO_INSTALL: "true",
      RATE_LIMIT_ENABLED: "false",
    });
    const cache = new AclCache(config);
    const methods: string[] = [];
    cache.adminClient.fetch = vi.fn(async (_path: string, init?: { method?: string }) => {
      methods.push(init?.method ?? "GET");
      return new Response("not found", { status: 404 });
    }) as typeof cache.adminClient.fetch;

    const policy = await cache.inspectAccessPolicy("fresh-app");

    expect(policy).toEqual({ noacl: true });
    expect(methods).toEqual(["GET"]);
    expect(cache.get("fresh-app")).toBeUndefined();
  });

  it("does not PUT _design/acl into system DBs", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      COUCH_ADMIN_USER: "admin",
      COUCH_ADMIN_PASSWORD: "password",
      ACL_AUTO_INSTALL: "true",
      RATE_LIMIT_ENABLED: "false",
    });
    const cache = new AclCache(config);
    const puts: string[] = [];
    cache.adminClient.fetch = vi.fn(async (path: string, init?: { method?: string }) => {
      const method = init?.method ?? "GET";
      if (method === "PUT") {
        puts.push(path);
        return new Response("{}", { status: 201 });
      }
      if (path.endsWith("/_design/acl")) {
        return new Response("not found", { status: 404 });
      }
      // DB head
      return new Response("{}", { status: 200 });
    }) as typeof cache.adminClient.fetch;

    const state = await cache.ensureDb("_users");
    expect(state.ready).toBe(true);
    expect(state.noacl).toBe(true);
    expect(puts).toEqual([]);
  });

  it("skips install for app DBs when ACL_AUTO_INSTALL=false", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      ACL_AUTO_INSTALL: "false",
      RATE_LIMIT_ENABLED: "false",
    });
    const cache = new AclCache(config);
    const puts: string[] = [];
    cache.adminClient.fetch = vi.fn(async (path: string, init?: { method?: string }) => {
      const method = init?.method ?? "GET";
      if (method === "PUT") {
        puts.push(path);
        return new Response("{}", { status: 201 });
      }
      if (path.endsWith("/_design/acl")) {
        return new Response("not found", { status: 404 });
      }
      return new Response("{}", { status: 200 });
    }) as typeof cache.adminClient.fetch;

    const state = await cache.ensureDb("appdb");
    expect(state.noacl).toBe(true);
    expect(puts).toEqual([]);
  });
});

describe("AclCache bulk load", () => {
  it("pages the ACL view and swaps in the complete result", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const cache = new AclCache(config);
    const state: DbAclState = {
      name: "large",
      acl: new Map(),
      noacl: false,
      ready: false,
      followerUp: false,
    };
    const row = (id: string) => ({
      id,
      key: id,
      value: {
        s: "1-a",
        p: "",
        _r: { "u-alice": 1 },
        _w: { "u-alice": 1 },
        _d: { "u-alice": 1 },
      },
    });
    const firstPage = Array.from({ length: 2_000 }, (_, i) =>
      row(`doc-${String(i).padStart(4, "0")}`),
    );
    const viewQueries: Array<Record<string, string> | undefined> = [];

    cache.adminClient.json = vi.fn(
      async (path: string, init?: { query?: Record<string, string> }) => {
        if (path.endsWith("/_design/acl")) {
          return {
            ok: true as const,
            status: 200,
            body: { views: { acl: { map: ACL_MAP_SOURCE } } },
          };
        }
        if (path.endsWith("/_changes")) {
          return {
            ok: true as const,
            status: 200,
            body: { results: [], last_seq: "2001-final", pending: 0 },
          };
        }
        viewQueries.push(init?.query);
        return {
          ok: true as const,
          status: 200,
          body: { rows: viewQueries.length === 1 ? firstPage : [row("doc-final")] },
        };
      },
    ) as typeof cache.adminClient.json;

    await (
      cache as unknown as {
        loadAll: (db: string, target: DbAclState) => Promise<void>;
      }
    ).loadAll("large", state);

    expect(state.acl).toHaveLength(2_001);
    expect(state.acl.has("doc-final")).toBe(true);
    expect(viewQueries).toHaveLength(2);
    expect(viewQueries[0]).toMatchObject({ limit: "2000", reduce: "false" });
    expect(viewQueries[1]).toMatchObject({
      startkey: JSON.stringify("doc-1999"),
      skip: "1",
    });
  });

  it("reconstructs newly discovered tombstones on every full snapshot reload", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
      }),
    );
    const state: DbAclState = {
      name: "restarted",
      acl: new Map(),
      tombstones: new Set(),
      tombstonesLoaded: true,
      aclMapSource: ACL_MAP_SOURCE,
      generatedAclMap: true,
      noacl: false,
      ready: false,
      followerUp: false,
    };

    cache.adminClient.json = vi.fn(
      async (path: string, init?: { query?: Record<string, string> }) => {
        if (path.endsWith("/_design/acl")) {
          return {
            ok: true as const,
            status: 200,
            body: { views: { acl: { map: ACL_MAP_SOURCE } } },
          };
        }
        if (path.endsWith("/_view/acl")) {
          return { ok: true as const, status: 200, body: { rows: [] } };
        }
        if (path.endsWith("/_changes")) {
          return {
            ok: true as const,
            status: 200,
            body: {
              results: [
                {
                  id: "deleted-private",
                  deleted: true,
                  changes: [{ rev: "2-deleted" }],
                },
              ],
              last_seq: "4-opaque",
              pending: 0,
            },
          };
        }
        if (init?.query?.rev === "2-deleted") {
          return {
            ok: true as const,
            status: 200,
            body: {
              _deleted: true,
              _revisions: { start: 2, ids: ["deleted", "original"] },
            },
          };
        }
        if (init?.query?.rev === "1-original") {
          return {
            ok: true as const,
            status: 200,
            body: {
              _id: "deleted-private",
              creator: "alice",
              acl: ["u-bob"],
            },
          };
        }
        return { ok: false as const, status: 404, text: "missing" };
      },
    ) as typeof cache.adminClient.json;

    await (
      cache as unknown as {
        loadAll: (db: string, target: DbAclState, scanCurrentTombstones?: boolean) => Promise<void>;
      }
    ).loadAll("restarted", state);

    expect(state.tombstones?.has("deleted-private")).toBe(true);
    expect(state.acl.get("deleted-private")?._r).toMatchObject({
      "u-alice": 1,
      "u-bob": 1,
    });
  });

  it("fails closed instead of applying generated semantics to custom ACL maps", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
      }),
    );
    const state: DbAclState = {
      name: "custom-map",
      acl: new Map(),
      noacl: false,
      ready: false,
      followerUp: false,
    };
    const customMap = "function (doc) { emit(doc._id, {s: doc._rev, _r:{}, _w:{}, _d:{}}); }";
    cache.adminClient.json = vi.fn(async (path: string) => {
      if (path.endsWith("/_design/acl")) {
        return {
          ok: true as const,
          status: 200,
          body: { views: { acl: { map: customMap } } },
        };
      }
      if (path.endsWith("/_view/acl")) {
        return { ok: true as const, status: 200, body: { rows: [] } };
      }
      if (path.endsWith("/_changes")) {
        return {
          ok: true as const,
          status: 200,
          body: {
            results: [
              {
                id: "deleted-custom",
                deleted: true,
                changes: [{ rev: "2-deleted" }],
              },
            ],
            last_seq: "2-opaque",
            pending: 0,
          },
        };
      }
      throw new Error("custom-map tombstones must not use document-field reconstruction");
    }) as typeof cache.adminClient.json;

    await (
      cache as unknown as {
        loadAll: (db: string, target: DbAclState) => Promise<void>;
      }
    ).loadAll("custom-map", state);

    expect(state.generatedAclMap).toBe(false);
    expect(state.tombstones?.has("deleted-custom")).toBe(true);
    expect(state.acl.get("deleted-custom")).toMatchObject({
      _r: {},
      _w: {},
      _d: {},
    });
  });

  it("retains known tombstone rows across ACL design-document reloads", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
      }),
    );
    const retained = {
      s: "1-original",
      p: "",
      _r: { "u-alice": 1 as const, "u-bob": 1 as const },
      _w: { "u-alice": 1 as const },
      _d: { "u-alice": 1 as const },
    };
    const state: DbAclState = {
      name: "reloaded",
      acl: new Map([["deleted-private", retained]]),
      tombstones: new Set(["deleted-private"]),
      tombstonesLoaded: true,
      aclMapSource: ACL_MAP_SOURCE,
      generatedAclMap: true,
      noacl: false,
      ready: true,
      followerUp: true,
    };
    cache.adminClient.json = vi.fn(async (path: string) => {
      if (path.endsWith("/_design/acl")) {
        return {
          ok: true as const,
          status: 200,
          body: { views: { acl: { map: ACL_MAP_SOURCE } } },
        };
      }
      return { ok: true as const, status: 200, body: { rows: [] } };
    }) as typeof cache.adminClient.json;

    await (
      cache as unknown as {
        loadAll: (db: string, target: DbAclState, scanCurrentTombstones?: boolean) => Promise<void>;
      }
    ).loadAll("reloaded", state, false);

    expect(state.acl.get("deleted-private")).toEqual(retained);
    expect(state.tombstones?.has("deleted-private")).toBe(true);
  });
});
