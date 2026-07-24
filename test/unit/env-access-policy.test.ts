/**
 * Unit tests for env DB/route access policy compilation and gates.
 */
import { describe, expect, it } from "vitest";
import {
  compileAccessPolicy,
  compileRouteGate,
  isDbAllowedByPolicy,
  parseRoutePolicyEntries,
} from "../../src/acl/envAccessPolicy.js";
import { buildPrincipal } from "../../src/auth/principal.js";
import { loadConfig } from "../../src/config.js";
import type { RouteDef } from "../../src/routes/restmap.js";

function user(name: string, roles: string[] = []) {
  return buildPrincipal({
    ok: true,
    userCtx: { name, roles },
    info: { authenticated: "cookie" },
  });
}

function admin() {
  return user("admin", ["_admin"]);
}

describe("loadConfig access lists", () => {
  it("defaults to empty opt-in lists", () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    expect(config.access).toEqual({
      dbInclude: [],
      dbExclude: [],
      routeInclude: [],
      routeExclude: [],
    });
  });

  it("parses CSV env lists", () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      ACL_DB_INCLUDE: "/^data-/,acldemo",
      ACL_DB_EXCLUDE: "_users",
      ACL_ROUTE_INCLUDE: "pouch-sync,find",
      ACL_ROUTE_EXCLUDE: "admin",
    });
    expect(config.access.dbInclude).toEqual(["/^data-/", "acldemo"]);
    expect(config.access.dbExclude).toEqual(["_users"]);
    expect(config.access.routeInclude).toEqual(["pouch-sync", "find"]);
    expect(config.access.routeExclude).toEqual(["admin"]);
  });

  it("rejects unknown route features at config load", () => {
    expect(() =>
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        ACL_ROUTE_INCLUDE: "not-a-real-feature",
      }),
    ).toThrow(/unknown route feature/);
  });

  it("rejects invalid DB regexes at config load", () => {
    expect(() =>
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        ACL_DB_INCLUDE: "/(/",
      }),
    ).toThrow(/ACL_DB_INCLUDE/);
  });
});

describe("parseRoutePolicyEntries", () => {
  it("expands bundles into features", () => {
    const parsed = parseRoutePolicyEntries(["pouch-sync", "find"]);
    expect(parsed.features.has("changes")).toBe(true);
    expect(parsed.features.has("docs")).toBe(true);
    expect(parsed.features.has("find")).toBe(true);
    expect(parsed.features.has("admin")).toBe(false);
  });

  it("accepts METHOD /path templates", () => {
    const parsed = parseRoutePolicyEntries(["GET /:db/_changes"]);
    expect([...parsed.templates]).toEqual(["GET /:db/_changes"]);
  });

  it("accepts request-path regexes", () => {
    const parsed = parseRoutePolicyEntries(["/^GET \\/data-[^/]+\\/_changes$/"]);
    expect(parsed.regexes).toHaveLength(1);
    expect(parsed.regexes[0]!.test("GET /data-app/_changes")).toBe(true);
    expect(parsed.regexes[0]!.test("GET /acldemo/_changes")).toBe(false);
  });
});

describe("isDbAllowedByPolicy", () => {
  const policy = compileAccessPolicy({
    dbInclude: ["/^data-/"],
    dbExclude: ["data-secret"],
    routeInclude: [],
    routeExclude: [],
  });

  it("allows admins always", () => {
    expect(isDbAllowedByPolicy(policy, "acldemo", admin())).toBe(true);
  });

  it("enforces include/exclude for non-admins", () => {
    const alice = user("alice", ["readers"]);
    expect(isDbAllowedByPolicy(policy, "data-app", alice)).toBe(true);
    expect(isDbAllowedByPolicy(policy, "data-secret", alice)).toBe(false);
    expect(isDbAllowedByPolicy(policy, "acldemo", alice)).toBe(false);
  });

  it("is inert when lists are empty", () => {
    const open = compileAccessPolicy({
      dbInclude: [],
      dbExclude: [],
      routeInclude: [],
      routeExclude: [],
    });
    expect(open.db.enabled).toBe(false);
    expect(isDbAllowedByPolicy(open, "anything", user("alice"))).toBe(true);
  });
});

describe("compileRouteGate", () => {
  const changesRoute: RouteDef = {
    method: "get",
    path: "/:db/_changes",
    actors: ["db", "changes"],
    features: ["changes"],
  };
  const findRoute: RouteDef = {
    method: "post",
    path: "/:db/_find",
    actors: ["db", "find"],
    features: ["find"],
  };
  const adminRoute: RouteDef = {
    method: "get",
    path: "/_utils",
    actors: ["admin"],
    features: ["admin"],
  };

  it("allows all routes when policy disabled", () => {
    const policy = compileAccessPolicy({
      dbInclude: [],
      dbExclude: [],
      routeInclude: [],
      routeExclude: [],
    });
    expect(compileRouteGate(policy, findRoute).allowed(user("a"), "POST", "/db/_find")).toBe(true);
  });

  it("includes pouch-sync features and excludes admin", () => {
    const policy = compileAccessPolicy({
      dbInclude: [],
      dbExclude: [],
      routeInclude: ["pouch-sync"],
      routeExclude: ["admin"],
    });
    const alice = user("alice");
    expect(compileRouteGate(policy, changesRoute).allowed(alice, "GET", "/data-1/_changes")).toBe(
      true,
    );
    expect(compileRouteGate(policy, findRoute).allowed(alice, "POST", "/data-1/_find")).toBe(false);
    expect(compileRouteGate(policy, adminRoute).allowed(alice, "GET", "/_utils")).toBe(false);
    expect(compileRouteGate(policy, adminRoute).allowed(admin(), "GET", "/_utils")).toBe(true);
  });

  it("supports request-path regex includes", () => {
    const policy = compileAccessPolicy({
      dbInclude: [],
      dbExclude: [],
      routeInclude: ["/^GET \\/data-[^/]+\\/_changes$/"],
      routeExclude: [],
    });
    const gate = compileRouteGate(policy, changesRoute);
    const alice = user("alice");
    expect(gate.allowed(alice, "GET", "/data-app/_changes")).toBe(true);
    expect(gate.allowed(alice, "GET", "/acldemo/_changes")).toBe(false);
  });

  it("supports METHOD template includes", () => {
    const policy = compileAccessPolicy({
      dbInclude: [],
      dbExclude: [],
      routeInclude: ["GET /:db/_changes"],
      routeExclude: [],
    });
    const alice = user("alice");
    expect(compileRouteGate(policy, changesRoute).allowed(alice, "GET", "/x/_changes")).toBe(true);
    expect(compileRouteGate(policy, findRoute).allowed(alice, "POST", "/x/_find")).toBe(false);
  });
});
