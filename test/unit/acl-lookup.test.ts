/**
 * Unit tests for flagsForDoc missing-row / admin short-circuit semantics.
 */
import { describe, expect, it } from "vitest";
import { flagsForDoc } from "../../src/acl/lookup.js";
import { buildPrincipal } from "../../src/auth/principal.js";
import type { DbAclState } from "../../src/acl/cache.js";

function principal(name: string, roles: string[] = []) {
  return buildPrincipal({
    ok: true,
    userCtx: { name, roles },
    info: { authenticated: "jwt" },
  });
}

function emptyState(): DbAclState {
  return {
    name: "test",
    acl: new Map(),
    noacl: false,
    ready: true,
    followerUp: true,
  };
}

describe("flagsForDoc", () => {
  it("admins get full access even when design-doc row is missing (create path)", () => {
    expect(flagsForDoc(emptyState(), principal("admin", ["_admin"]), "_design/app")).toEqual({
      _r: true,
      _w: true,
      _d: true,
    });
  });

  it("non-admins cannot create unknown design docs", () => {
    expect(flagsForDoc(emptyState(), principal("alice"), "_design/app")).toEqual({
      _r: false,
      _w: false,
      _d: false,
    });
  });

  it("non-admins may create unknown regular docs; read/delete denied until cached", () => {
    expect(flagsForDoc(emptyState(), principal("alice"), "new-doc")).toEqual({
      _r: false,
      _w: true,
      _d: false,
    });
  });

  it("uses retained tombstone grants for recreate/write (not universal create-path)", () => {
    const state = emptyState();
    state.acl.set("gone", {
      s: "2-deleted",
      p: "",
      deleted: true,
      _r: { "u-alice": 1, "u-bob": 1 },
      _w: { "u-alice": 1 },
      _d: { "u-alice": 1 },
    });
    expect(flagsForDoc(state, principal("alice"), "gone")).toEqual({
      _r: true,
      _w: true,
      _d: true,
    });
    expect(flagsForDoc(state, principal("bob"), "gone")).toEqual({
      _r: true,
      _w: false,
      _d: false,
    });
    expect(flagsForDoc(state, principal("carol"), "gone")).toEqual({
      _r: false,
      _w: false,
      _d: false,
    });
  });
});
