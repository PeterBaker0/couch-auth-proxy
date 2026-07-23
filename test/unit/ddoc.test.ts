import { describe, expect, it, vi } from "vitest";
import { AclCache } from "../../src/acl/cache.js";
import { buildAclDesignDoc, VALIDATE_DOC_UPDATE_SOURCE } from "../../src/acl/ddoc.js";
import { loadConfig } from "../../src/config.js";

describe("generated ACL design document", () => {
  it("leaves delete authorization to proxy r/w/d resolution", () => {
    const ddoc = buildAclDesignDoc();
    expect(ddoc.version).toBe("2.3.0");
    expect(ddoc.options.partitioned).toBe(false);
    expect(VALIDATE_DOC_UPDATE_SOURCE).not.toContain("You can't delete doc");
    expect(VALIDATE_DOC_UPDATE_SOURCE).toContain("Creator can not be changed");
  });

  it("lets role owners change readers but not retarget parent inheritance", () => {
    const validate = Function(`return (${VALIDATE_DOC_UPDATE_SOURCE});`)() as (
      next: Record<string, unknown>,
      old: Record<string, unknown> | null,
      user: { name: string; roles: string[] },
      security: Record<string, unknown>,
    ) => void;
    const old = {
      _id: "shared",
      creator: "alice",
      owners: ["r-writers"],
      acl: ["u-alice"],
      parent: "folder-a",
    };
    expect(() =>
      validate(
        { ...old, acl: ["u-alice", "u-carol"] },
        old,
        { name: "bob", roles: ["writers"] },
        {},
      ),
    ).not.toThrow();

    let denied: unknown;
    try {
      validate({ ...old, parent: "folder-b" }, old, { name: "bob", roles: ["writers"] }, {});
    } catch (err) {
      denied = err;
    }
    expect(denied).toEqual({ forbidden: "Parent can not be changed." });
  });

  it("prevents claiming creator-less documents and rejects malformed ACL metadata", () => {
    const validate = Function(`return (${VALIDATE_DOC_UPDATE_SOURCE});`)() as (
      next: Record<string, unknown>,
      old: Record<string, unknown> | null,
      user: { name: string; roles: string[] },
      security: Record<string, unknown>,
    ) => void;
    const open = { _id: "open", body: "before" };

    expect(() =>
      validate({ ...open, body: "ordinary edit" }, open, { name: "bob", roles: [] }, {}),
    ).not.toThrow();
    expect(() =>
      validate({ ...open, creator: "bob" }, open, { name: "bob", roles: [] }, {}),
    ).toThrow();
    expect(() => validate({ ...open, acl: [] }, open, { name: "bob", roles: [] }, {})).toThrow();
    expect(() =>
      validate({ _id: "new", acl: "bob" }, null, { name: "bob", roles: [] }, {}),
    ).toThrow();
  });

  it("compares owner arrays without comma-collision ambiguity", () => {
    const validate = Function(`return (${VALIDATE_DOC_UPDATE_SOURCE});`)() as (
      next: Record<string, unknown>,
      old: Record<string, unknown> | null,
      user: { name: string; roles: string[] },
      security: Record<string, unknown>,
    ) => void;
    const old = {
      _id: "shared",
      creator: "alice",
      owners: ["u-bob", "u-charlie,u-dave"],
    };
    expect(() =>
      validate(
        { ...old, owners: ["u-bob,u-charlie", "u-dave"] },
        old,
        { name: "bob", roles: [] },
        {},
      ),
    ).toThrow();
  });

  it("upgrades legacy generated rules without discarding bucket policy", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
      }),
    );
    let written: Record<string, unknown> | undefined;
    cache.adminClient.fetch = vi.fn(async (_path: string, init?: RequestInit) => {
      written = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response("{}", { status: 201 });
    }) as typeof cache.adminClient.fetch;

    const legacy = {
      _id: "_design/acl",
      _rev: "4-old",
      version: "2.0.0",
      type: "ddoc",
      acl: ["u-ops"],
      dbacl: { _r: ["r-support"] },
      restrict: { "*": ["r-members"] },
      views: {
        acl: { map: "function (doc) { emit(doc._id, doc); }" },
        custom: { map: "function (doc) { emit(doc.kind, 1); }" },
      },
      validate_doc_update: `function () { throw { forbidden: "You can't delete doc." }; }`,
    };

    await (
      cache as unknown as {
        maybeMigrateStamp: (db: string, response: Response) => Promise<void>;
      }
    ).maybeMigrateStamp(
      "docs",
      new Response(JSON.stringify(legacy), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(written).toBeDefined();
    const upgraded = written!;
    expect(upgraded).toMatchObject({
      _id: "_design/acl",
      _rev: "4-old",
      version: "2.3.0",
      acl: ["u-ops"],
      dbacl: { _r: ["r-support"] },
      restrict: { "*": ["r-members"] },
    });
    expect((upgraded.views as Record<string, unknown>).custom).toEqual(legacy.views.custom);
    expect(String(upgraded.validate_doc_update)).not.toContain("You can't delete doc");
  });

  it("upgrades generated v2.1 owner policy without replacing custom views", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
      }),
    );
    let written: Record<string, unknown> | undefined;
    cache.adminClient.fetch = vi.fn(async (_path: string, init?: RequestInit) => {
      written = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response("{}", { status: 201 });
    }) as typeof cache.adminClient.fetch;
    const old = {
      _id: "_design/acl",
      _rev: "3-old",
      version: "2.1.0",
      type: "ddoc",
      acl: [],
      options: { local_seq: true, partitioned: false },
      views: {
        acl: { map: "function (doc) { emit(doc._id, doc); }" },
        custom: { map: "function (doc) { emit(doc.kind, 1); }" },
      },
      validate_doc_update:
        'function () { throw { forbidden: "Readers list can not be changed." }; }',
    };

    await (
      cache as unknown as {
        maybeMigrateStamp: (db: string, response: Response) => Promise<void>;
      }
    ).maybeMigrateStamp(
      "docs",
      new Response(JSON.stringify(old), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(written).toMatchObject({
      _id: "_design/acl",
      _rev: "3-old",
      version: "2.3.0",
      views: old.views,
    });
    expect(String(written?.validate_doc_update)).toContain("roleToken");
    expect(String(written?.validate_doc_update)).toContain("Parent can not be changed.");
  });

  it("adds the global-view option to early v2.1 ddocs without replacing custom code", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
      }),
    );
    let written: Record<string, unknown> | undefined;
    cache.adminClient.fetch = vi.fn(async (_path: string, init?: RequestInit) => {
      written = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response("{}", { status: 201 });
    }) as typeof cache.adminClient.fetch;
    const map = "function (doc) { emit(doc._id, { custom: true }); }";
    const validate = "function (nd, od) { if (!nd.kind) throw({forbidden:'kind'}); }";
    const earlyV21 = {
      _id: "_design/acl",
      _rev: "2-early",
      version: "2.1.0",
      type: "ddoc",
      acl: [],
      options: { local_seq: true },
      views: { acl: { map } },
      validate_doc_update: validate,
    };

    await (
      cache as unknown as {
        maybeMigrateStamp: (db: string, response: Response) => Promise<void>;
      }
    ).maybeMigrateStamp(
      "partitioned",
      new Response(JSON.stringify(earlyV21), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(written).toBeDefined();
    const upgraded = written!;
    expect(upgraded.options).toMatchObject({ local_seq: true, partitioned: false });
    expect((upgraded.views as { acl: { map: string } }).acl.map).toBe(map);
    expect(upgraded.validate_doc_update).toBe(validate);
  });

  it("upgrades generated v2.2 ACL policy while preserving custom views", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
      }),
    );
    let written: Record<string, unknown> | undefined;
    cache.adminClient.fetch = vi.fn(async (_path: string, init?: RequestInit) => {
      written = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response("{}", { status: 201 });
    }) as typeof cache.adminClient.fetch;
    const old = {
      _id: "_design/acl",
      _rev: "5-old",
      version: "2.2.0",
      type: "ddoc",
      acl: [],
      options: { local_seq: true, partitioned: false },
      views: {
        acl: {
          map: "function (doc) { var cr = doc.creator, acl = doc.acl, ow = doc.owners; emit(doc._id, {}); }",
        },
        custom: { map: "function (doc) { emit(doc.kind, 1); }" },
      },
      validate_doc_update:
        "function (nd, od) { var odc = od.creator; var ndc = nd.creator; if (odc && odc != ndc) throw({forbidden:'Creator can not be changed.'}); }",
    };

    await (
      cache as unknown as {
        maybeMigrateStamp: (db: string, response: Response) => Promise<void>;
      }
    ).maybeMigrateStamp(
      "docs",
      new Response(JSON.stringify(old), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(written).toMatchObject({
      _id: "_design/acl",
      _rev: "5-old",
      version: "2.3.0",
    });
    const views = written?.views as Record<string, unknown>;
    expect(views.custom).toEqual(old.views.custom);
    expect(String((views.acl as { map: string }).map)).toContain("hasCr");
    expect(String(written?.validate_doc_update)).toContain("Creator must be a non-empty string");
  });
});
