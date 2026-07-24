import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { SessionResolver } from "../../src/auth/session.js";
import { bearerToken, verifyJwtLocally } from "../../src/auth/jwt.js";
import { loadConfig } from "../../src/config.js";

const SECRET = "local-test-secret-with-enough-entropy";

function localConfig() {
  return loadConfig({
    COUCH_URL: "http://127.0.0.1:5984",
    AUTH_RESOLVE_VIA_COUCH_SESSION: "false",
    JWT_LOCAL_VERIFY: "true",
    JWT_HMAC_SECRET: SECRET,
    RATE_LIMIT_ENABLED: "false",
  });
}

async function token(sub = "alice", roles = ["readers"], expiration = "1h") {
  return new SignJWT({ "_couchdb.roles": roles })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(sub)
    .setExpirationTime(expiration)
    .sign(new TextEncoder().encode(SECRET));
}

describe("local JWT authentication", () => {
  it("verifies Couch-style role claims and builds ACL tokens", async () => {
    const principal = await verifyJwtLocally(await token(), localConfig());
    expect(principal.name).toBe("alice");
    expect(principal.roles).toEqual(["readers"]);
    expect(principal.aclTokens).toEqual(
      expect.arrayContaining(["r-*", "u-alice", "readers", "r-readers"]),
    );
  });

  it("is selected when Couch session resolution is disabled", async () => {
    const resolver = new SessionResolver(localConfig());
    const couchFetch = vi.spyOn(globalThis, "fetch");
    const principal = await resolver.resolve(
      new Headers({ Authorization: `Bearer ${await token("bob", ["writers"])}` }),
    );

    expect(principal.name).toBe("bob");
    expect(principal.roles).toEqual(["writers"]);
    expect(couchFetch).not.toHaveBeenCalled();
    couchFetch.mockRestore();
  });

  it("fails closed to anonymous for invalid tokens", async () => {
    const resolver = new SessionResolver(localConfig());
    const principal = await resolver.resolve(
      new Headers({ Authorization: "Bearer invalid.signature.value" }),
    );
    expect(principal.name).toBeNull();
    expect(principal.aclTokens).not.toContain("r-*");
  });

  it("rejects an unusable local-auth configuration", () => {
    expect(() =>
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        AUTH_RESOLVE_VIA_COUCH_SESSION: "false",
        JWT_LOCAL_VERIFY: "false",
      }),
    ).toThrow(/JWT_LOCAL_VERIFY/);

    expect(() =>
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        AUTH_RESOLVE_VIA_COUCH_SESSION: "false",
        JWT_LOCAL_VERIFY: "true",
      }),
    ).toThrow(/JWT_HMAC_SECRET/);
  });
});

describe("bearerToken", () => {
  it("parses bearer tokens case-insensitively and rejects other schemes", () => {
    expect(bearerToken("bearer abc.def")).toBe("abc.def");
    expect(bearerToken("Basic abc")).toBeNull();
    expect(bearerToken(null)).toBeNull();
  });
});

describe("Couch session principal freshness", () => {
  it("caches roles by default for SESSION_CACHE_TTL_MS (5000)", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    expect(config.couch.sessionCacheTtlMs).toBe(5000);
    const responses = [
      { ok: true, userCtx: { name: "bob", roles: ["writers"] } },
      { ok: true, userCtx: { name: "bob", roles: [] } },
    ];
    const couchFetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      return new Response(JSON.stringify(responses.shift()), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    const resolver = new SessionResolver(config);
    const headers = new Headers({ Authorization: "Basic credentials" });

    expect((await resolver.resolve(headers)).roles).toEqual(["writers"]);
    // Within the default TTL, the second resolve must reuse the cached principal.
    expect((await resolver.resolve(headers)).roles).toEqual(["writers"]);
    expect(couchFetch).toHaveBeenCalledTimes(1);
    couchFetch.mockRestore();
  });

  it("re-resolves every request when SESSION_CACHE_TTL_MS=0", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
      SESSION_CACHE_TTL_MS: "0",
    });
    const responses = [
      { ok: true, userCtx: { name: "bob", roles: ["writers"] } },
      { ok: true, userCtx: { name: "bob", roles: [] } },
    ];
    const couchFetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      return new Response(JSON.stringify(responses.shift()), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    const resolver = new SessionResolver(config);
    const headers = new Headers({ Authorization: "Basic credentials" });

    expect((await resolver.resolve(headers)).roles).toEqual(["writers"]);
    expect((await resolver.resolve(headers)).roles).toEqual([]);
    expect(couchFetch).toHaveBeenCalledTimes(2);
    couchFetch.mockRestore();
  });

  it("coalesces concurrent identical credential lookups into one /_session fetch", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
      SESSION_CACHE_TTL_MS: "0",
    });
    let inflight = 0;
    let maxInflight = 0;
    let fetches = 0;
    const couchFetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      fetches += 1;
      inflight += 1;
      maxInflight = Math.max(maxInflight, inflight);
      await new Promise((r) => setTimeout(r, 20));
      inflight -= 1;
      return new Response(
        JSON.stringify({ ok: true, userCtx: { name: "bob", roles: ["writers"] } }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    const resolver = new SessionResolver(config);
    const headers = new Headers({ Authorization: "Basic credentials" });

    const principals = await Promise.all([
      resolver.resolve(headers),
      resolver.resolve(headers),
      resolver.resolve(headers),
    ]);

    expect(fetches).toBe(1);
    expect(maxInflight).toBe(1);
    expect(principals.every((p) => p.name === "bob")).toBe(true);
    couchFetch.mockRestore();
  });
});
