import { describe, expect, it, vi } from "vitest";
import { AclCache } from "../../src/acl/cache.js";
import {
  ACL_DDOC_VERSION_DEFAULT,
  ACL_DDOC_VERSION_REQUIRE_CREATOR,
  REQUIRE_CREATOR_FORBIDDEN,
  VALIDATE_DOC_UPDATE_SOURCE,
  buildAclDesignDoc,
  buildValidateDocUpdateSource,
} from "../../src/acl/ddoc.js";
import { loadConfig } from "../../src/config.js";

type ValidateFn = (
  next: Record<string, unknown>,
  old: Record<string, unknown> | null,
  user: { name: string; roles: string[] },
  security: Record<string, unknown>,
) => void;

function loadValidate(source: string): ValidateFn {
  return Function(`return (${source});`)() as ValidateFn;
}

describe("generated ACL design document", () => {
  it("leaves delete authorization to proxy r/w/d resolution", () => {
    const ddoc = buildAclDesignDoc();
    expect(ddoc.version).toBe(ACL_DDOC_VERSION_DEFAULT);
    expect(ddoc.version).toBe("2.3.0");
    expect(ddoc.options.partitioned).toBe(false);
    expect(VALIDATE_DOC_UPDATE_SOURCE).not.toContain("You can't delete doc");
    expect(VALIDATE_DOC_UPDATE_SOURCE).toContain("Creator can not be changed");
    expect(VALIDATE_DOC_UPDATE_SOURCE).not.toContain(REQUIRE_CREATOR_FORBIDDEN);
    expect(buildValidateDocUpdateSource(false)).toBe(VALIDATE_DOC_UPDATE_SOURCE);
  });

  it("prevents writers from claiming creator on an existing open document", () => {
    const validate = loadValidate(VALIDATE_DOC_UPDATE_SOURCE);
    const old = {
      _id: "open",
      body: "shared",
    };

    let denied: unknown;
    try {
      validate({ ...old, creator: "bob" }, old, { name: "bob", roles: [] }, {});
    } catch (err) {
      denied = err;
    }
    expect(denied).toEqual({ forbidden: "Creator can not be changed." });
  });

  it("lets role owners change readers but not retarget parent inheritance", () => {
    const validate = loadValidate(VALIDATE_DOC_UPDATE_SOURCE);
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
    const validate = loadValidate(VALIDATE_DOC_UPDATE_SOURCE);
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

  it("allows unstamped creates when ACL_REQUIRE_CREATOR is off", () => {
    const validate = loadValidate(buildValidateDocUpdateSource(false));
    expect(() =>
      validate({ _id: "open-create", body: "shared" }, null, { name: "bob", roles: [] }, {}),
    ).not.toThrow();
    expect(buildAclDesignDoc({ requireCreator: false }).version).toBe(ACL_DDOC_VERSION_DEFAULT);
    expect(buildAclDesignDoc({ requireCreator: false }).validate_doc_update).toBe(
      VALIDATE_DOC_UPDATE_SOURCE,
    );
  });

  describe("ACL_REQUIRE_CREATOR=true VDU", () => {
    const source = buildValidateDocUpdateSource(true);
    const validate = loadValidate(source);

    it("bumps ddoc version and embeds require-creator rule", () => {
      const ddoc = buildAclDesignDoc({ requireCreator: true });
      expect(ddoc.version).toBe(ACL_DDOC_VERSION_REQUIRE_CREATOR);
      expect(ddoc.version).toBe("2.4.0");
      expect(ddoc.validate_doc_update).toContain(REQUIRE_CREATOR_FORBIDDEN);
      expect(ddoc.views.acl.map).toBe(buildAclDesignDoc().views.acl.map);
    });

    it("forbids missing or empty creator on non-admin creates", () => {
      let missing: unknown;
      try {
        validate({ _id: "no-creator", body: "x" }, null, { name: "bob", roles: [] }, {});
      } catch (err) {
        missing = err;
      }
      expect(missing).toEqual({ forbidden: REQUIRE_CREATOR_FORBIDDEN });

      let empty: unknown;
      try {
        validate(
          { _id: "empty-creator", creator: "", body: "x" },
          null,
          {
            name: "bob",
            roles: [],
          },
          {},
        );
      } catch (err) {
        empty = err;
      }
      // Present-but-empty hits the type check first.
      expect(empty).toEqual({ forbidden: "Creator must be a non-empty string." });
    });

    it("allows create with own creator and rejects forge", () => {
      expect(() =>
        validate({ _id: "mine", creator: "bob", body: "ok" }, null, { name: "bob", roles: [] }, {}),
      ).not.toThrow();
      expect(() =>
        validate(
          { _id: "mine", creator: "u-bob", body: "ok" },
          null,
          { name: "bob", roles: [] },
          {},
        ),
      ).not.toThrow();

      let forged: unknown;
      try {
        validate(
          { _id: "spoof", creator: "alice", body: "nope" },
          null,
          { name: "bob", roles: [] },
          {},
        );
      } catch (err) {
        forged = err;
      }
      expect(forged).toEqual({ forbidden: "Can't create doc on behalf of other user." });
    });

    it("exempts _design docs and _admin from require-creator", () => {
      expect(() =>
        validate({ _id: "_design/app", views: {} }, null, { name: "bob", roles: [] }, {}),
      ).not.toThrow();
      expect(() =>
        validate(
          { _id: "admin-open", body: "unstamped" },
          null,
          { name: "admin", roles: ["_admin"] },
          {},
        ),
      ).not.toThrow();
    });

    it("still enforces immutable creator on updates", () => {
      const old = { _id: "owned", creator: "alice", body: "a" };
      expect(() =>
        validate({ ...old, creator: "bob" }, old, { name: "bob", roles: [] }, {}),
      ).toThrow();
      // Existing open docs remain updatable without adding creator.
      const open = { _id: "open", body: "before" };
      expect(() =>
        validate({ ...open, body: "after" }, open, { name: "bob", roles: [] }, {}),
      ).not.toThrow();
    });
  });

  it("compares owner arrays without comma-collision ambiguity", () => {
    const validate = loadValidate(VALIDATE_DOC_UPDATE_SOURCE);
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
      version: ACL_DDOC_VERSION_DEFAULT,
      acl: ["u-ops"],
      dbacl: { _r: ["r-support"] },
      restrict: { "*": ["r-members"] },
    });
    expect((upgraded.views as Record<string, unknown>).custom).toEqual(legacy.views.custom);
    expect(String(upgraded.validate_doc_update)).not.toContain("You can't delete doc");
    expect(String(upgraded.validate_doc_update)).not.toContain(REQUIRE_CREATOR_FORBIDDEN);
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
        acl: {
          map: "function (doc) { var cr = doc.creator, acl = doc.acl, ow = doc.owners; emit(doc._id, {}); }",
        },
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
      version: ACL_DDOC_VERSION_DEFAULT,
    });
    const views = written?.views as Record<string, unknown>;
    expect(views.custom).toEqual(old.views.custom);
    expect(String((views.acl as { map: string }).map)).toContain("hasCr");
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

  it("upgrades generated v2.2 policy while preserving bucket policy and custom views", async () => {
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
      dbacl: { _r: ["r-support"] },
      restrict: { "*": ["r-members"] },
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
      version: ACL_DDOC_VERSION_DEFAULT,
      dbacl: old.dbacl,
      restrict: old.restrict,
    });
    const views = written?.views as Record<string, unknown>;
    expect(views.custom).toEqual(old.views.custom);
    expect(String((views.acl as { map: string }).map)).toContain("hasCr");
    expect(String(written?.validate_doc_update)).toContain("Creator must be a non-empty string");
    expect(String(written?.validate_doc_update)).toContain('has(od, "creator")');
    expect(String(written?.validate_doc_update)).not.toContain("if (odc && odc != ndc)");
  });

  it("upgrades the v2.2 creator policy without replacing a custom ACL map", async () => {
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
    const customMap = "function (doc) { emit(doc._id, { custom: true }); }";
    const old = {
      _id: "_design/acl",
      _rev: "4-old",
      version: "2.2.0",
      type: "ddoc",
      acl: [],
      dbacl: { _r: ["r-support"] },
      views: { acl: { map: customMap } },
      validate_doc_update:
        "function (nd, od) { var odc = od.creator; var ndc = nd.creator; if (odc && odc != ndc) throw({forbidden:'Creator can not be changed.'}); }",
    };

    await (
      cache as unknown as {
        maybeMigrateStamp: (db: string, response: Response) => Promise<void>;
      }
    ).maybeMigrateStamp(
      "custom",
      new Response(JSON.stringify(old), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(written).toMatchObject({
      _id: "_design/acl",
      _rev: "4-old",
      version: ACL_DDOC_VERSION_DEFAULT,
      dbacl: old.dbacl,
      views: old.views,
    });
    expect(String(written?.validate_doc_update)).toContain('has(od, "creator")');
  });

  it("rewrites generated VDU when ACL_REQUIRE_CREATOR flips on", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
        ACL_REQUIRE_CREATOR: "true",
      }),
    );
    let written: Record<string, unknown> | undefined;
    cache.adminClient.fetch = vi.fn(async (_path: string, init?: RequestInit) => {
      written = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response("{}", { status: 201 });
    }) as typeof cache.adminClient.fetch;

    const current = buildAclDesignDoc({ requireCreator: false });
    const installed = {
      ...current,
      _rev: "7-cur",
      stamp: 1,
      dbacl: { _r: ["r-support"] },
      views: {
        ...current.views,
        custom: { map: "function (doc) { emit(doc.kind, 1); }" },
      },
    };

    await (
      cache as unknown as {
        maybeMigrateStamp: (db: string, response: Response) => Promise<void>;
      }
    ).maybeMigrateStamp(
      "docs",
      new Response(JSON.stringify(installed), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(written).toBeDefined();
    const upgraded = written!;
    expect(upgraded).toMatchObject({
      _id: "_design/acl",
      _rev: "7-cur",
      version: ACL_DDOC_VERSION_REQUIRE_CREATOR,
      dbacl: installed.dbacl,
    });
    expect(String(upgraded.validate_doc_update)).toContain(REQUIRE_CREATOR_FORBIDDEN);
    expect((upgraded.views as Record<string, unknown>).custom).toEqual(installed.views.custom);
  });

  it("rewrites generated VDU when ACL_REQUIRE_CREATOR flips off", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
        ACL_REQUIRE_CREATOR: "false",
      }),
    );
    let written: Record<string, unknown> | undefined;
    cache.adminClient.fetch = vi.fn(async (_path: string, init?: RequestInit) => {
      written = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response("{}", { status: 201 });
    }) as typeof cache.adminClient.fetch;

    const required = buildAclDesignDoc({ requireCreator: true });
    const installed = { ...required, _rev: "8-req", stamp: 1 };

    await (
      cache as unknown as {
        maybeMigrateStamp: (db: string, response: Response) => Promise<void>;
      }
    ).maybeMigrateStamp(
      "docs",
      new Response(JSON.stringify(installed), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(written).toMatchObject({
      _id: "_design/acl",
      _rev: "8-req",
      version: ACL_DDOC_VERSION_DEFAULT,
    });
    expect(String(written?.validate_doc_update)).not.toContain(REQUIRE_CREATOR_FORBIDDEN);
    expect(String(written?.validate_doc_update)).toBe(VALIDATE_DOC_UPDATE_SOURCE);
  });

  it("does not rewrite when require-creator flag already matches the VDU", async () => {
    const cache = new AclCache(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
        ACL_REQUIRE_CREATOR: "true",
      }),
    );
    const fetchMock = vi.fn(async () => new Response("{}", { status: 201 }));
    cache.adminClient.fetch = fetchMock as typeof cache.adminClient.fetch;

    const installed = { ...buildAclDesignDoc({ requireCreator: true }), _rev: "9-ok" };
    await (
      cache as unknown as {
        maybeMigrateStamp: (db: string, response: Response) => Promise<void>;
      }
    ).maybeMigrateStamp(
      "docs",
      new Response(JSON.stringify(installed), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("loadConfig ACL_REQUIRE_CREATOR", () => {
  it("defaults to false and accepts truthy env strings", () => {
    expect(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
      }).couch.aclRequireCreator,
    ).toBe(false);
    expect(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
        ACL_REQUIRE_CREATOR: "true",
      }).couch.aclRequireCreator,
    ).toBe(true);
    expect(
      loadConfig({
        COUCH_URL: "http://127.0.0.1:5984",
        RATE_LIMIT_ENABLED: "false",
        ACL_REQUIRE_CREATOR: "false",
      }).couch.aclRequireCreator,
    ).toBe(false);
  });
});
