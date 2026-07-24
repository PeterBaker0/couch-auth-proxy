/**
 * Ensures verbose ACL decision trails fire when LOG_LEVEL=verbose.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveDocAcl, aclRowFromDoc } from "../../src/acl/resolve.js";
import { flagsForDoc } from "../../src/acl/lookup.js";
import { dbAccessLevel, methodAllowed, compileRestrict } from "../../src/acl/restrict.js";
import { buildPrincipal } from "../../src/auth/principal.js";
import { setLogLevel } from "../../src/util/log.js";
import type { DbAclState } from "../../src/acl/cache.js";

afterEach(() => {
  setLogLevel(null);
  vi.restoreAllMocks();
});

function principal(name: string, roles: string[] = []) {
  return buildPrincipal({
    ok: true,
    userCtx: { name, roles },
    info: { authenticated: "cookie" },
  });
}

describe("verbose ACL logging", () => {
  it("logs resolveDocAcl decisions with matched tokens", () => {
    setLogLevel("verbose");
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const row = aclRowFromDoc({ _id: "doc1", creator: "alice", acl: ["u-bob"] });
    resolveDocAcl({ principal: principal("bob"), docId: "doc1", row });

    const lines = spy.mock.calls.map((call) => JSON.parse(String(call[0])));
    const resolveLine = lines.find((l) => l.component === "acl-resolve" && l.msg === "resolve");
    expect(resolveLine).toMatchObject({
      level: "verbose",
      docId: "doc1",
      user: "bob",
      reason: "row",
      flags: { _r: true, _w: false, _d: false },
    });
    expect(resolveLine.matchedRow._r).toContain("u-bob");
  });

  it("logs missing-row create path in flagsForDoc", () => {
    setLogLevel("verbose");
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const state = {
      name: "acldemo",
      acl: new Map(),
      noacl: false,
      ready: true,
      followerUp: true,
    } as DbAclState;

    expect(flagsForDoc(state, principal("alice"), "new-doc")).toEqual({
      _r: false,
      _w: true,
      _d: false,
    });

    const lines = spy.mock.calls.map((call) => JSON.parse(String(call[0])));
    expect(
      lines.some(
        (l) =>
          l.component === "acl-lookup" &&
          l.reason === "missing-row-create-path" &&
          l.docId === "new-doc",
      ),
    ).toBe(true);
  });

  it("logs restrict star deny/allow", () => {
    setLogLevel("verbose");
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const compiled = compileRestrict({ "*": ["u-alice"], get: { "/_all_docs*": ["r-readers"] } });

    expect(dbAccessLevel(principal("bob"), compiled, false)).toBe(0);
    expect(dbAccessLevel(principal("alice"), compiled, false)).toBe(1);
    expect(
      methodAllowed(principal("bob", ["readers"]), compiled, "GET", "/_all_docs?limit=1"),
    ).toBe(true);
    expect(methodAllowed(principal("bob"), compiled, "GET", "/_all_docs?limit=1")).toBe(false);

    const lines = spy.mock.calls.map((call) => JSON.parse(String(call[0])));
    expect(lines.some((l) => l.msg === "dbAccessLevel" && l.reason === "restrict-star-deny")).toBe(
      true,
    );
    expect(lines.some((l) => l.msg === "methodAllowed" && l.reason === "pattern-token-deny")).toBe(
      true,
    );
  });
});
