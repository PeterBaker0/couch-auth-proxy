import { describe, expect, it, vi } from "vitest";
import { AclCache } from "../../src/acl/cache.js";
import { buildAclDesignDoc, VALIDATE_DOC_UPDATE_SOURCE } from "../../src/acl/ddoc.js";
import { loadConfig } from "../../src/config.js";

describe("generated ACL design document", () => {
  it("leaves delete authorization to proxy r/w/d resolution", () => {
    const ddoc = buildAclDesignDoc();
    expect(ddoc.version).toBe("2.1.0");
    expect(VALIDATE_DOC_UPDATE_SOURCE).not.toContain("You can't delete doc");
    expect(VALIDATE_DOC_UPDATE_SOURCE).toContain("Creator can not be changed");
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

    expect(written).toMatchObject({
      _id: "_design/acl",
      _rev: "4-old",
      version: "2.1.0",
      acl: ["u-ops"],
      dbacl: { _r: ["r-support"] },
      restrict: { "*": ["r-members"] },
    });
    expect((written?.views as Record<string, unknown>).custom).toEqual(legacy.views.custom);
    expect(String(written?.validate_doc_update)).not.toContain("You can't delete doc");
  });
});
