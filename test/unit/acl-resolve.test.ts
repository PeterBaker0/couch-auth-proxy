/**
 * Unit tests for document ACL resolution (`resolveDocAcl` / `aclRowFromDoc`).
 */
import { describe, expect, it } from "vitest";
import { aclRowFromDoc, resolveDocAcl } from "../../src/acl/resolve.js";
import { buildPrincipal } from "../../src/auth/principal.js";

function principal(name: string, roles: string[] = []) {
  return buildPrincipal({
    ok: true,
    userCtx: { name, roles },
    info: { authenticated: "jwt" },
  });
}

describe("resolveDocAcl", () => {
  it("admins always get full access", () => {
    const row = aclRowFromDoc({
      _id: "doc1",
      creator: "alice",
      acl: ["u-bob"],
    });
    const flags = resolveDocAcl({
      principal: principal("anyone", ["_admin"]),
      docId: "doc1",
      row,
    });
    expect(flags).toEqual({ _r: true, _w: true, _d: true });
  });

  it("creator can read/write/delete", () => {
    const row = aclRowFromDoc({ _id: "doc1", creator: "alice" });
    expect(resolveDocAcl({ principal: principal("alice"), docId: "doc1", row })).toEqual({
      _r: true,
      _w: true,
      _d: true,
    });
  });

  it("acl readers can read but not write/delete", () => {
    const row = aclRowFromDoc({
      _id: "doc1",
      creator: "alice",
      acl: ["u-bob"],
    });
    expect(resolveDocAcl({ principal: principal("bob"), docId: "doc1", row })).toEqual({
      _r: true,
      _w: false,
      _d: false,
    });
  });

  it("owners can read/write but not delete", () => {
    const row = aclRowFromDoc({
      _id: "doc1",
      creator: "alice",
      owners: ["u-bob"],
    });
    expect(resolveDocAcl({ principal: principal("bob"), docId: "doc1", row })).toEqual({
      _r: true,
      _w: true,
      _d: false,
    });
  });

  it("inherits parent ACL (most permissive wins)", () => {
    const parent = aclRowFromDoc({
      _id: "parent",
      creator: "alice",
      acl: ["u-bob"],
    });
    const child = aclRowFromDoc({
      _id: "child",
      creator: "carol",
      parent: "parent",
    });
    expect(
      resolveDocAcl({
        principal: principal("bob"),
        docId: "child",
        row: child,
        parentRow: parent,
      }),
    ).toEqual({ _r: true, _w: false, _d: false });
  });

  it("inherits parent delete grants", () => {
    const parent = aclRowFromDoc({ _id: "parent", creator: "bob" });
    const child = aclRowFromDoc({
      _id: "child",
      creator: "alice",
      parent: "parent",
    });
    expect(
      resolveDocAcl({
        principal: principal("bob"),
        docId: "child",
        row: child,
        parentRow: parent,
      }),
    ).toEqual({ _r: true, _w: true, _d: true });
  });

  it("does not inherit grants from a deleted parent tombstone", () => {
    const parent = { ...aclRowFromDoc({ _id: "parent", creator: "bob" }), deleted: true as const };
    const child = aclRowFromDoc({
      _id: "child",
      creator: "alice",
      parent: "parent",
    });
    expect(
      resolveDocAcl({
        principal: principal("bob"),
        docId: "child",
        row: child,
        parentRow: parent,
      }),
    ).toEqual({ _r: false, _w: false, _d: false });
  });

  it("applies database-level delete grants", () => {
    const row = aclRowFromDoc({ _id: "doc", creator: "alice" });
    expect(
      resolveDocAcl({
        principal: principal("bob"),
        docId: "doc",
        row,
        dbacl: { _d: ["u-bob"] },
      }),
    ).toEqual({ _r: false, _w: false, _d: true });
  });

  it("treats bare dbacl grants as usernames, not role names", () => {
    const row = aclRowFromDoc({ _id: "doc", creator: "alice" });
    expect(
      resolveDocAcl({
        principal: principal("bob", ["writers"]),
        docId: "doc",
        row,
        dbacl: { _r: ["writers"] },
      })._r,
    ).toBe(false);
    expect(
      resolveDocAcl({
        principal: principal("writers"),
        docId: "doc",
        row,
        dbacl: { _r: ["writers"] },
      })._r,
    ).toBe(true);
  });

  it("open docs (no creator/owners/acl) allow r-*", () => {
    const row = aclRowFromDoc({ _id: "open" });
    expect(resolveDocAcl({ principal: principal("stranger"), docId: "open", row })).toEqual({
      _r: true,
      _w: true,
      _d: true,
    });
  });
});

describe("aclRowFromDoc map parity", () => {
  it("treats a role-prefixed creator as a username like the Couch map", () => {
    const row = aclRowFromDoc({ _id: "doc", creator: "r-editors" });
    expect(row._r).toEqual({ "u-r-editors": 1 });
    expect(row._w).toEqual({ "u-r-editors": 1 });
    expect(row._d).toEqual({ "u-r-editors": 1 });
  });

  it("uses document revision as the v2 freshness stamp", () => {
    const row = aclRowFromDoc({
      _id: "doc",
      _rev: "3-current",
      _local_seq: 17,
      creator: "alice",
    });
    expect(row.s).toBe("3-current");
  });

  it("fails closed when present ACL metadata has a malformed type", () => {
    for (const doc of [
      { _id: "bad-creator", creator: "" },
      { _id: "bad-acl", acl: "alice" },
      { _id: "bad-owners", owners: {} },
    ]) {
      const row = aclRowFromDoc(doc);
      expect(row._r).toEqual({});
      expect(row._w).toEqual({});
      expect(row._d).toEqual({});
    }
  });
});
