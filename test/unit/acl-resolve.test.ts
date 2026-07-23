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

  it("open docs (no creator/owners/acl) allow r-*", () => {
    const row = aclRowFromDoc({ _id: "open" });
    expect(resolveDocAcl({ principal: principal("stranger"), docId: "open", row })).toEqual({
      _r: true,
      _w: true,
      _d: true,
    });
  });
});
