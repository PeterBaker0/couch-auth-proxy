/**
 * Unit tests for include/exclude pattern compilation.
 */
import { describe, expect, it } from "vitest";
import {
  allowedByIncludeExclude,
  compileMatchList,
  matchListHits,
  parsePatternEntry,
} from "../../src/acl/matchList.js";

describe("parsePatternEntry", () => {
  it("treats bare strings as exact matches", () => {
    expect(parsePatternEntry("data-app")).toEqual({ exact: "data-app" });
  });

  it("compiles /pattern/flags regexes", () => {
    const parsed = parsePatternEntry("/^data-/i");
    expect("regex" in parsed).toBe(true);
    if ("regex" in parsed) {
      expect(parsed.regex.test("DATA-foo")).toBe(true);
      expect(parsed.regex.test("other")).toBe(false);
    }
  });

  it("allows / inside the regex body (uses last / as delimiter)", () => {
    const parsed = parsePatternEntry("/^GET \\/data-[^/]+\\/_changes$/");
    expect("regex" in parsed).toBe(true);
    if ("regex" in parsed) {
      expect(parsed.regex.test("GET /data-app/_changes")).toBe(true);
      expect(parsed.regex.test("GET /acldemo/_changes")).toBe(false);
    }
  });

  it("rejects unterminated regexes", () => {
    expect(() => parsePatternEntry("/^data-")).toThrow(/unterminated/);
  });

  it("rejects invalid regex bodies", () => {
    expect(() => parsePatternEntry("/(/")).toThrow(/invalid regex/);
  });
});

describe("compileMatchList / matchListHits", () => {
  it("is empty for no entries (opt-in off)", () => {
    const list = compileMatchList([]);
    expect(list.empty).toBe(true);
    expect(matchListHits(list, "anything")).toBe(false);
  });

  it("matches exact and regex entries", () => {
    const list = compileMatchList(["acldemo", "/^data-/"]);
    expect(matchListHits(list, "acldemo")).toBe(true);
    expect(matchListHits(list, "data-users")).toBe(true);
    expect(matchListHits(list, "meta")).toBe(false);
  });
});

describe("allowedByIncludeExclude", () => {
  it("allows everything when both lists are empty", () => {
    expect(allowedByIncludeExclude(compileMatchList([]), compileMatchList([]), "any")).toBe(true);
  });

  it("requires include hits when include is set", () => {
    const include = compileMatchList(["/^data-/"]);
    const exclude = compileMatchList([]);
    expect(allowedByIncludeExclude(include, exclude, "data-1")).toBe(true);
    expect(allowedByIncludeExclude(include, exclude, "acldemo")).toBe(false);
  });

  it("lets exclude win over include", () => {
    const include = compileMatchList(["/^data-/"]);
    const exclude = compileMatchList(["data-secret"]);
    expect(allowedByIncludeExclude(include, exclude, "data-secret")).toBe(false);
    expect(allowedByIncludeExclude(include, exclude, "data-ok")).toBe(true);
  });
});
