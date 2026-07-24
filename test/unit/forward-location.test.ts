/**
 * Location rewrite must happen once in toClientResponse — not in fetchFromCouch.
 * Double-wrapping the upstream body can throw undici's
 * "Response body object should not be disturbed or locked".
 */
import { Hono } from "hono";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../../src/config.js";
import {
  fetchFromCouch,
  toClientResponse,
  toClientResponseFromCouch,
} from "../../src/proxy/forward.js";

const COUCH_ORIGIN = "http://couchdb:5984";

function testConfig() {
  return loadConfig({
    COUCH_URL: COUCH_ORIGIN,
    COUCH_ADMIN_URL: "http://admin:password@couchdb:5984",
    RATE_LIMIT_ENABLED: "false",
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("toClientResponse Location rewrite", () => {
  it("rewrites absolute same-origin Location to a relative path and keeps the body", async () => {
    const upstream = new Response(JSON.stringify({ ok: true, id: "doc1", rev: "1-abc" }), {
      status: 201,
      statusText: "Created",
      headers: {
        "Content-Type": "application/json",
        Location: `${COUCH_ORIGIN}/db/doc1`,
      },
    });

    const client = toClientResponse(upstream, {
      rewriteLocation: { fromOrigin: COUCH_ORIGIN },
    });

    expect(client.status).toBe(201);
    expect(client.headers.get("location")).toBe("/db/doc1");
    expect(await client.json()).toEqual({ ok: true, id: "doc1", rev: "1-abc" });
  });

  it("toClientResponseFromCouch applies Couch-origin rewrite by default", async () => {
    const config = testConfig();
    const upstream = new Response("{}", {
      status: 201,
      headers: { Location: `${COUCH_ORIGIN}/acldemo/rec-1?rev=1-x` },
    });

    const client = toClientResponseFromCouch(upstream, config);
    expect(client.headers.get("location")).toBe("/acldemo/rec-1?rev=1-x");
    expect(await client.text()).toBe("{}");
  });
});

describe("fetchFromCouch Location handling", () => {
  it("returns the raw upstream Response without rewriting Location", async () => {
    const config = testConfig();
    const bodyJson = JSON.stringify({ ok: true, id: "doc1" });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        return new Response(bodyJson, {
          status: 201,
          headers: {
            "Content-Type": "application/json",
            Location: `${COUCH_ORIGIN}/db/doc1`,
          },
        });
      }),
    );

    const app = new Hono();
    let upstream!: Response;
    app.put("/db/doc1", async (c) => {
      upstream = await fetchFromCouch(c, config);
      // Single client wrap — must not throw even when Location was absolute.
      return toClientResponseFromCouch(upstream, config);
    });

    const res = await app.request("http://proxy.test/db/doc1", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: bodyJson,
    });

    // fetchFromCouch must leave Location absolute (no intermediate Response wrap).
    expect(upstream.headers.get("location")).toBe(`${COUCH_ORIGIN}/db/doc1`);
    expect(res.status).toBe(201);
    expect(res.headers.get("location")).toBe("/db/doc1");
    expect(await res.json()).toEqual({ ok: true, id: "doc1" });
  });
});
