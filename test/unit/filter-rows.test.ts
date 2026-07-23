/**
 * Unit tests for view / `_all_docs` row filtering by read ACL.
 */
import { describe, expect, it } from "vitest";
import { filterRows } from "../../src/proxy/filterRows.js";
import {
  filterBulkDocs,
  filterRevsObject,
  mergeBulkResults,
  normalizeBulkResults,
} from "../../src/proxy/filterBulk.js";
import { filterFindDocs } from "../../src/proxy/filterFind.js";
import { aclRowFromDoc } from "../../src/acl/resolve.js";
import { isDocumentId } from "../../src/acl/names.js";
import { buildPrincipal } from "../../src/auth/principal.js";
import type { DbAclState } from "../../src/acl/cache.js";

function principal(name: string, roles: string[] = []) {
  return buildPrincipal({
    ok: true,
    userCtx: { name, roles },
    info: { authenticated: "jwt" },
  });
}

function stateWith(docs: Array<{ _id: string; creator?: string; acl?: string[] }>): DbAclState {
  const acl = new Map(docs.map((d) => [d._id, aclRowFromDoc(d)]));
  return {
    name: "test",
    acl,
    noacl: false,
    ready: true,
    followerUp: true,
  };
}

describe("filterRows", () => {
  const state = stateWith([
    { _id: "a", creator: "alice" },
    { _id: "b", creator: "alice", acl: ["u-bob"] },
  ]);

  it("strips unauthorized rows", () => {
    const out = filterRows(state, principal("bob"), {
      total_rows: 2,
      rows: [
        { id: "a", key: "a", value: { rev: "1" } },
        { id: "b", key: "b", value: { rev: "1" } },
      ],
    });
    expect(out.rows.map((r) => r.id)).toEqual(["b"]);
    expect(out.total_rows).toBe(2);
  });

  it("drops id-less reduce/group aggregate rows", () => {
    const out = filterRows(state, principal("bob"), {
      rows: [
        { key: null, value: 42 },
        { id: "b", key: "b", value: { rev: "1" } },
      ],
    });
    expect(out.rows).toEqual([{ id: "b", key: "b", value: { rev: "1" } }]);
  });

  it("preserveDenied emits not_found placeholders", () => {
    const out = filterRows(
      state,
      principal("bob"),
      {
        rows: [
          { id: "a", key: "a" },
          { id: "b", key: "b" },
        ],
      },
      { preserveDenied: true },
    );
    expect(out.rows).toEqual([
      { id: "a", error: "not_found" },
      { id: "b", key: "b" },
    ]);
  });

  it("drops linked-view rows when the embedded document is unreadable", () => {
    const out = filterRows(state, principal("bob"), {
      rows: [
        {
          id: "b",
          key: "linked",
          value: { _id: "a" },
          doc: { _id: "a", secret: "must-not-leak" },
        },
      ],
    });
    expect(out.rows).toEqual([]);
  });
});

describe("filterBulkDocs", () => {
  const state = stateWith([{ _id: "a", creator: "alice" }]);

  it("rejects unauthorized updates and merges results", () => {
    const filtered = filterBulkDocs(state, principal("bob"), {
      docs: [
        { _id: "a", x: 1 },
        { _id: "new", creator: "bob" },
      ],
    });
    expect(filtered.hadDenied).toBe(true);
    expect(filtered.allowed).toHaveLength(1);
    expect(filtered.allowed[0]?._id).toBe("new");
    const merged = mergeBulkResults(filtered.slots, [{ id: "new", ok: true, rev: "1-x" }]);
    expect(merged[0]).toEqual({ id: "a", error: "forbidden", reason: "ACL" });
    expect(merged[1]).toEqual({ id: "new", ok: true, rev: "1-x" });
  });

  it("merge tolerates empty Couch new_edits:false success when synthesized", () => {
    const filtered = filterBulkDocs(state, principal("alice"), {
      docs: [{ _id: "a", _rev: "2-xyz", body: "x" }],
    });
    const synthesized = filtered.allowed.map((d) => ({
      ok: true,
      id: d._id,
      rev: d._rev,
    }));
    const merged = mergeBulkResults(filtered.slots, synthesized);
    expect(merged).toEqual([{ ok: true, id: "a", rev: "2-xyz" }]);
  });

  it("aligns mixed new_edits:false errors by id instead of position", () => {
    const allowed = [
      { _id: "ok-first", _rev: "1-ok" },
      { _id: "bad-second", _rev: "2-bad" },
    ];
    const normalized = normalizeBulkResults(
      allowed,
      [{ id: "bad-second", error: "forbidden", reason: "validation" }],
      true,
    );
    expect(normalized).toEqual([
      { ok: true, id: "ok-first", rev: "1-ok" },
      { id: "bad-second", error: "forbidden", reason: "validation" },
    ]);

    const merged = mergeBulkResults(
      [{ id: "acl-denied", error: "forbidden" }, null, null],
      normalized,
    );
    expect(merged[1]?.id).toBe("ok-first");
    expect(merged[2]).toMatchObject({ id: "bad-second", error: "forbidden" });
  });

  it("rejects reserved or oversized ids before they reach Couch", () => {
    const filtered = filterBulkDocs(
      state,
      principal("bob"),
      {
        docs: [{ _id: "_purged_infos_limit" }, { _id: "long-document-id" }, { _id: "new" }],
      },
      (id) => isDocumentId(id, 5),
    );
    expect(filtered.allowed.map((doc) => doc._id)).toEqual(["new"]);
    expect(filtered.slots[0]?.error).toBe("forbidden");
    expect(filtered.slots[1]?.error).toBe("forbidden");
  });
});

describe("filterFindDocs", () => {
  it("filters mango docs by read ACL", () => {
    const state = stateWith([
      { _id: "a", creator: "alice" },
      { _id: "b", creator: "alice", acl: ["u-bob"] },
    ]);
    const out = filterFindDocs(state, principal("bob"), {
      docs: [{ _id: "a" }, { _id: "b" }],
    });
    expect(out.docs.map((d) => d._id)).toEqual(["b"]);
  });

  it("drops docs without _id (fail closed)", () => {
    const state = stateWith([{ _id: "b", creator: "alice", acl: ["u-bob"] }]);
    const out = filterFindDocs(state, principal("bob"), {
      docs: [{ body: "no-id" } as { _id?: string }, { _id: "b" }],
    });
    expect(out.docs.map((d) => d._id)).toEqual(["b"]);
  });
});

describe("filterRevsObject", () => {
  const state = stateWith([
    { _id: "a", creator: "alice" },
    { _id: "b", creator: "alice", acl: ["u-bob"] },
  ]);

  it("keeps readable ids and writable create ids; drops forbidden", () => {
    const out = filterRevsObject(state, principal("bob"), {
      a: ["1-x"],
      b: ["1-y"],
      brandNew: ["1-z"],
    });
    expect(out.a).toBeUndefined();
    expect(out.b).toEqual(["1-y"]);
    // unknown id → create/write allowed for push replication
    expect(out.brandNew).toEqual(["1-z"]);
  });
});
