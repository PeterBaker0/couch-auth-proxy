/**
 * Unit tests for the tiny LRU map used by the session cache.
 */
import { describe, expect, it } from "vitest";
import { LruMap } from "../../src/util/lru.js";

describe("LruMap", () => {
  it("evicts oldest when over capacity", () => {
    const m = new LruMap<number>(2);
    m.set("a", 1);
    m.set("b", 2);
    m.set("c", 3);
    expect(m.get("a")).toBeUndefined();
    expect(m.get("b")).toBe(2);
    expect(m.get("c")).toBe(3);
  });

  it("refreshes recency on get", () => {
    const m = new LruMap<number>(2);
    m.set("a", 1);
    m.set("b", 2);
    expect(m.get("a")).toBe(1);
    m.set("c", 3);
    expect(m.get("b")).toBeUndefined();
    expect(m.get("a")).toBe(1);
  });
});
