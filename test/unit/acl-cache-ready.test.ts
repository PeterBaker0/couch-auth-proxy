/**
 * Unit tests for AclCache readiness / fail-closed behavior when the
 * changes follower is down or ensure fails.
 */
import { describe, expect, it, vi } from "vitest";
import { AclCache, AclUnavailableError, type DbAclState } from "../../src/acl/cache.js";
import { ChangesFollower } from "../../src/acl/changesFollower.js";
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
});

describe("AclCache.applyChange fetch failures", () => {
  it("does not delete ACL rows when the view fetch fails", async () => {
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

    await (
      cache as unknown as {
        applyChange: (
          db: string,
          state: DbAclState,
          id: string,
          deleted?: boolean,
        ) => Promise<void>;
      }
    ).applyChange("acldemo", state, "secret", false);

    expect(state.acl.has("secret")).toBe(true);
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

  it("recovers ACL from pre-delete revision when cache was cold", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    const cache = new AclCache(config);
    const state: DbAclState = {
      name: "acldemo",
      acl: new Map(),
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
