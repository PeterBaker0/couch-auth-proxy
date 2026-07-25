/**
 * Boot preload resolution: explicit names ∪ `/_all_dbs` include patterns.
 */
import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "../../src/config.js";
import { resolvePreloadDbs } from "../../src/acl/preload.js";
import type { AdminClient } from "../../src/couch/adminClient.js";

function config(env: Record<string, string>) {
  return loadConfig({
    COUCH_URL: "http://127.0.0.1:5984",
    RATE_LIMIT_ENABLED: "false",
    ...env,
  });
}

function adminListing(dbs: string[]): AdminClient {
  return {
    json: vi.fn(async () => ({ ok: true as const, status: 200, body: dbs })),
  } as unknown as AdminClient;
}

describe("loadConfig COUCH_PRELOAD_DB_INCLUDE", () => {
  it("defaults to empty (lazy ensure)", () => {
    const cfg = config({});
    expect(cfg.couch.preloadDbs).toEqual([]);
    expect(cfg.couch.preloadDbInclude).toEqual([]);
  });

  it("parses CSV patterns", () => {
    const cfg = config({
      COUCH_PRELOAD_DB_INCLUDE: "/^data-/,shared",
    });
    expect(cfg.couch.preloadDbInclude).toEqual(["/^data-/", "shared"]);
  });

  it("rejects invalid regexes at config load", () => {
    expect(() =>
      config({
        COUCH_PRELOAD_DB_INCLUDE: "/(/",
      }),
    ).toThrow(/COUCH_PRELOAD_DB_INCLUDE/);
  });
});

describe("resolvePreloadDbs", () => {
  it("returns only explicit names when include is unset", async () => {
    const admin = adminListing(["data-a", "acldemo"]);
    const dbs = await resolvePreloadDbs(admin, config({ COUCH_PRELOAD_DBS: "acldemo,extra" }));
    expect(dbs).toEqual(["acldemo", "extra"]);
    expect(admin.json).not.toHaveBeenCalled();
  });

  it("unions explicit names with /_all_dbs include matches", async () => {
    const admin = adminListing([
      "_users",
      "_replicator",
      "_global_changes",
      "acldemo",
      "data-alpha",
      "data-beta",
      "meta",
    ]);
    const dbs = await resolvePreloadDbs(
      admin,
      config({
        COUCH_PRELOAD_DBS: "acldemo",
        COUCH_PRELOAD_DB_INCLUDE: "/^data-/",
      }),
    );
    expect(dbs).toEqual(["acldemo", "data-alpha", "data-beta"]);
  });

  it("skips system DBs from include matches", async () => {
    const admin = adminListing(["_users", "_replicator", "data-1"]);
    const dbs = await resolvePreloadDbs(admin, config({ COUCH_PRELOAD_DB_INCLUDE: "/.*/" }));
    expect(dbs).toEqual(["data-1"]);
  });

  it("honours ACL_DB_INCLUDE / ACL_DB_EXCLUDE so preload cannot widen scope", async () => {
    const admin = adminListing(["data-ok", "data-secret", "acldemo", "other"]);
    const dbs = await resolvePreloadDbs(
      admin,
      config({
        COUCH_PRELOAD_DBS: "acldemo,other",
        COUCH_PRELOAD_DB_INCLUDE: "/^data-/",
        ACL_DB_INCLUDE: "/^data-/",
        ACL_DB_EXCLUDE: "data-secret",
      }),
    );
    expect(dbs).toEqual(["data-ok"]);
  });

  it("returns empty when nothing is configured", async () => {
    const admin = adminListing(["data-a"]);
    const dbs = await resolvePreloadDbs(admin, config({}));
    expect(dbs).toEqual([]);
    expect(admin.json).not.toHaveBeenCalled();
  });

  it("fails closed when /_all_dbs errors and include is set", async () => {
    const admin = {
      json: vi.fn(async () => ({ ok: false as const, status: 503, text: "down" })),
    } as unknown as AdminClient;
    await expect(
      resolvePreloadDbs(admin, config({ COUCH_PRELOAD_DB_INCLUDE: "/^data-/" })),
    ).rejects.toThrow(/_all_dbs failed/);
  });
});
