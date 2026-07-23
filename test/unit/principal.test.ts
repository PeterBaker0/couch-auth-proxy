/**
 * Unit tests for Principal construction and ACL token expansion.
 */
import { describe, expect, it } from "vitest";
import { anonymousPrincipal, buildPrincipal } from "../../src/auth/principal.js";

describe("buildPrincipal", () => {
  it("maps name and roles into ACL tokens", () => {
    const p = buildPrincipal({
      ok: true,
      userCtx: { name: "alice", roles: ["readers", "_admin"] },
      info: { authenticated: "jwt" },
    });
    expect(p.admin).toBe(true);
    expect(p.aclTokens).toEqual(
      expect.arrayContaining([
        "alice",
        "u-alice",
        "readers",
        "r-readers",
        "r-*",
        "_admin",
        "r-_admin",
      ]),
    );
    expect(p.authenticatedBy).toBe("jwt");
  });

  it("does not grant r-* to anonymous principals", () => {
    const p = anonymousPrincipal();
    expect(p.name).toBeNull();
    expect(p.aclTokens).not.toContain("r-*");
    expect(p.aclTokens).toEqual([]);
  });
});
