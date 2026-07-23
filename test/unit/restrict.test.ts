/**
 * Unit tests for `restrict` compilation and db/method access checks.
 */
import { describe, expect, it } from "vitest";
import {
  compileRestrict,
  dbAccessLevel,
  methodAllowed,
  restrictPatternToRegExp,
  unwindTokens,
} from "../../src/acl/restrict.js";
import { buildPrincipal } from "../../src/auth/principal.js";

function principal(name: string | null, roles: string[] = []) {
  return buildPrincipal({
    ok: true,
    userCtx: { name, roles },
    info: { authenticated: "cookie" },
  });
}

describe("restrictPatternToRegExp", () => {
  it("matches * as one or more chars", () => {
    const re = restrictPatternToRegExp("*attachments=true");
    expect(re.test("/_all_docs?attachments=true")).toBe(true);
    expect(re.test("/_all_docs")).toBe(false);
  });

  it("matches + as one path segment (substring, legacy-compatible)", () => {
    const re = restrictPatternToRegExp("_update/+");
    expect(re.test("/_design/x/_update/approve")).toBe(true);
    // `+` stops at `/`, so a multi-segment tail still matches the first segment
    expect(re.test("/_design/x/_update/a/b")).toBe(true);
    expect(re.test("/_all_docs")).toBe(false);
  });
});

describe("compileRestrict / dbAccessLevel / methodAllowed", () => {
  const compiled = compileRestrict({
    "*": ["r-marketing", "u-boss"],
    get: {
      "*attachments=true": ["u-cfo"],
    },
    put: {
      "*": [],
    },
  });

  it("unwinds bare usernames to u-", () => {
    expect([...unwindTokens(["alice", "r-readers"])].sort()).toEqual(["r-readers", "u-alice"]);
  });

  it("hides DB when restrict.* does not match", () => {
    expect(dbAccessLevel(principal("carol"), compiled, false)).toBe(0);
  });

  it("allows DB when role matches restrict.*", () => {
    expect(dbAccessLevel(principal("x", ["marketing"]), compiled, false)).toBe(1);
  });

  it("admins always see DB", () => {
    expect(dbAccessLevel(principal("a", ["_admin"]), compiled, false)).toBe(2);
  });

  it("enforces method path restrictions", () => {
    expect(methodAllowed(principal("cfo"), compiled, "GET", "/_all_docs?attachments=true")).toBe(
      true,
    );
    expect(methodAllowed(principal("boss"), compiled, "GET", "/_all_docs?attachments=true")).toBe(
      false,
    );
  });

  it("empty put:* denies everyone non-admin", () => {
    expect(methodAllowed(principal("boss"), compiled, "PUT", "/doc1")).toBe(false);
    expect(methodAllowed(principal("a", ["_admin"]), compiled, "PUT", "/doc1")).toBe(true);
  });
});
