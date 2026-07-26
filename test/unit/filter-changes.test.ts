import { describe, expect, it, vi } from "vitest";
import { AclUnavailableError, type AclCache, type DbAclState } from "../../src/acl/cache.js";
import { aclRowFromDoc } from "../../src/acl/resolve.js";
import { buildPrincipal } from "../../src/auth/principal.js";
import { filterChangesStream } from "../../src/proxy/filterChanges.js";

const encoder = new TextEncoder();

function principal(name: string, roles: string[] = []) {
  return buildPrincipal({
    ok: true,
    userCtx: { name, roles },
    info: { authenticated: "jwt" },
  });
}

function state(overrides?: Partial<DbAclState>): DbAclState {
  return {
    name: "docs",
    acl: new Map([
      ["private", aclRowFromDoc({ _id: "private", creator: "alice" })],
      ["shared", aclRowFromDoc({ _id: "shared", creator: "alice", acl: ["u-bob"] })],
    ]),
    noacl: false,
    ready: true,
    followerUp: true,
    ...overrides,
  };
}

/** Minimal AclCache stub — `ensureDocRows` only needs `ensureDocs`. */
function mockCache(
  dbState: DbAclState,
  ensureDocs: AclCache["ensureDocs"] = async () => undefined,
): AclCache {
  return { ensureDocs } as unknown as AclCache;
}

function stream(...chunks: string[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

async function text(body: ReadableStream<Uint8Array>): Promise<string> {
  return new Response(body).text();
}

describe("filterChangesStream", () => {
  it("filters normal feeds while preserving opaque sequence metadata", async () => {
    const dbState = state();
    const upstream = stream(
      JSON.stringify({
        results: [
          { id: "private", seq: "2-g1AAA", doc: { _id: "private", secret: true } },
          { id: "shared", seq: "3-g1AAB", doc: { _id: "shared", visible: true } },
          { seq: "4-idless" },
        ],
        last_seq: "4-g1AAC",
        pending: 7,
      }),
    );

    const output = JSON.parse(
      await text(
        filterChangesStream(upstream, mockCache(dbState), dbState, principal("bob"), "normal"),
      ),
    ) as {
      results: Array<{ id: string; seq: string }>;
      last_seq: string;
      pending: number;
    };
    expect(output.results).toEqual([
      {
        id: "shared",
        seq: "3-g1AAB",
        doc: { _id: "shared", visible: true },
      },
    ]);
    expect(output.last_seq).toBe("4-g1AAC");
    expect(output.pending).toBe(7);
  });

  it("filters split continuous-feed lines and preserves heartbeats/control rows", async () => {
    const dbState = state();
    const upstream = stream(
      '{"id":"pri',
      'vate","seq":"1-a"}\n\n{"id":"shared","seq":"2-b"}\n',
      '{"last_seq":"2-b","pending":0}\nnot-json\n',
    );

    const output = await text(
      filterChangesStream(upstream, mockCache(dbState), dbState, principal("bob"), "continuous"),
    );
    expect(output).not.toContain("private");
    expect(output).not.toContain("not-json");
    expect(output).toContain('{"id":"shared","seq":"2-b"}');
    expect(output).toContain('{"last_seq":"2-b","pending":0}');
  });

  it("keeps SSE metadata only for allowed data events", async () => {
    const dbState = state();
    const upstream = stream(
      'data: {"id":"private","seq":"1-a"}\nid: 1-a\n\n',
      'event: message\ndata: {"id":"shared","seq":"2-b"}\nid: 2-b\n\n',
      ": heartbeat\n",
    );

    const output = await text(
      filterChangesStream(upstream, mockCache(dbState), dbState, principal("bob"), "eventsource"),
    );
    expect(output).not.toContain("private");
    expect(output).not.toContain("id: 1-a");
    expect(output).toContain('data: {"id":"shared","seq":"2-b"}');
    expect(output).toContain("id: 2-b");
    expect(output).toContain(": heartbeat");
  });

  it("does not let last_seq turn a denied change into control metadata", async () => {
    const dbState = state();
    const continuous = await text(
      filterChangesStream(
        stream(
          '{"id":"private","seq":"1-a","last_seq":"1-a"}\n',
          '{"id":"shared","seq":"2-b","last_seq":"2-b"}\n',
          '{"last_seq":"2-b","pending":0}\n',
        ),
        mockCache(dbState),
        dbState,
        principal("bob"),
        "continuous",
      ),
    );
    expect(continuous).not.toContain("private");
    expect(continuous).toContain('"id":"shared"');
    expect(continuous).toContain('{"last_seq":"2-b","pending":0}');

    const eventsource = await text(
      filterChangesStream(
        stream(
          'data: {"id":"private","seq":"1-a","last_seq":"1-a"}\nid: 1-a\n\n',
          'data: {"last_seq":"2-b"}\n\n',
        ),
        mockCache(dbState),
        dbState,
        principal("bob"),
        "eventsource",
      ),
    );
    expect(eventsource).not.toContain("private");
    expect(eventsource).not.toContain("id: 1-a");
    expect(eventsource).toContain('data: {"last_seq":"2-b"}');
  });

  it("rejects oversized buffered normal feeds", async () => {
    const dbState = state();
    const filtered = filterChangesStream(
      stream(JSON.stringify({ results: [], padding: "x".repeat(200) })),
      mockCache(dbState),
      dbState,
      principal("bob"),
      "longpoll",
      { maxBufferBytes: 64 },
    );
    await expect(text(filtered)).rejects.toThrow(/64 bytes/);
  });

  describe("cold ACL cache miss warm", () => {
    it("normal feed: warms missing row then forwards when readable", async () => {
      const dbState = state({
        acl: new Map(),
        dbacl: { _r: ["r-writers"], _w: [], _d: [] },
      });
      const ensureDocs = vi.fn(async (_db: string, ids: readonly string[]) => {
        for (const id of ids) {
          dbState.acl.set(id, aclRowFromDoc({ _id: id, creator: "guest" }));
        }
      });
      const upstream = stream(
        JSON.stringify({
          results: [{ id: "rec-1", seq: "9-a", doc: { _id: "rec-1", creator: "guest" } }],
          last_seq: "9-a",
        }),
      );

      const output = JSON.parse(
        await text(
          filterChangesStream(
            upstream,
            mockCache(dbState, ensureDocs),
            dbState,
            principal("bob", ["writers"]),
            "normal",
          ),
        ),
      ) as { results: Array<{ id: string }> };

      expect(ensureDocs).toHaveBeenCalledWith("docs", ["rec-1"]);
      expect(output.results.map((r) => r.id)).toEqual(["rec-1"]);
    });

    it("continuous feed: warms missing row then forwards when readable", async () => {
      const dbState = state({ acl: new Map() });
      const ensureDocs = vi.fn(async (_db: string, ids: readonly string[]) => {
        for (const id of ids) {
          dbState.acl.set(id, aclRowFromDoc({ _id: id, creator: "alice", acl: ["u-bob"] }));
        }
      });

      const output = await text(
        filterChangesStream(
          stream('{"id":"rec-1","seq":"1-a"}\n{"last_seq":"1-a"}\n'),
          mockCache(dbState, ensureDocs),
          dbState,
          principal("bob"),
          "continuous",
        ),
      );

      expect(ensureDocs).toHaveBeenCalledWith("docs", ["rec-1"]);
      expect(output).toContain('{"id":"rec-1","seq":"1-a"}');
      expect(output).toContain('{"last_seq":"1-a"}');
    });

    it("eventsource feed: warms missing row then forwards when readable", async () => {
      const dbState = state({ acl: new Map() });
      const ensureDocs = vi.fn(async (_db: string, ids: readonly string[]) => {
        for (const id of ids) {
          dbState.acl.set(id, aclRowFromDoc({ _id: id, creator: "alice", acl: ["u-bob"] }));
        }
      });

      const output = await text(
        filterChangesStream(
          stream('data: {"id":"rec-1","seq":"1-a"}\nid: 1-a\n\n'),
          mockCache(dbState, ensureDocs),
          dbState,
          principal("bob"),
          "eventsource",
        ),
      );

      expect(ensureDocs).toHaveBeenCalledWith("docs", ["rec-1"]);
      expect(output).toContain('data: {"id":"rec-1","seq":"1-a"}');
      expect(output).toContain("id: 1-a");
    });

    it("still drops after ensure when principal cannot read", async () => {
      const dbState = state({ acl: new Map() });
      const ensureDocs = vi.fn(async (_db: string, ids: readonly string[]) => {
        for (const id of ids) {
          // Creator-only; carol has no grant and no dbacl.
          dbState.acl.set(id, aclRowFromDoc({ _id: id, creator: "alice" }));
        }
      });

      const normal = JSON.parse(
        await text(
          filterChangesStream(
            stream(JSON.stringify({ results: [{ id: "rec-1", seq: "1-a" }], last_seq: "1-a" })),
            mockCache(dbState, ensureDocs),
            dbState,
            principal("carol"),
            "normal",
          ),
        ),
      ) as { results: unknown[] };
      expect(ensureDocs).toHaveBeenCalledWith("docs", ["rec-1"]);
      expect(normal.results).toEqual([]);

      const continuousState = state({ acl: new Map() });
      const ensureContinuous = vi.fn(async (_db: string, ids: readonly string[]) => {
        for (const id of ids) {
          continuousState.acl.set(id, aclRowFromDoc({ _id: id, creator: "alice" }));
        }
      });
      const continuous = await text(
        filterChangesStream(
          stream('{"id":"rec-1","seq":"1-a"}\n'),
          mockCache(continuousState, ensureContinuous),
          continuousState,
          principal("carol"),
          "continuous",
        ),
      );
      expect(ensureContinuous).toHaveBeenCalledWith("docs", ["rec-1"]);
      expect(continuous).not.toContain("rec-1");
    });

    it("keeps create-path deny when ensure finds no row (doc absent)", async () => {
      const dbState = state({ acl: new Map() });
      const ensureDocs = vi.fn(async () => {
        // Doc does not exist — leave cache empty (create-path semantics).
      });

      const output = JSON.parse(
        await text(
          filterChangesStream(
            stream(JSON.stringify({ results: [{ id: "ghost", seq: "1-a" }], last_seq: "1-a" })),
            mockCache(dbState, ensureDocs),
            dbState,
            principal("bob"),
            "normal",
          ),
        ),
      ) as { results: unknown[] };

      expect(ensureDocs).toHaveBeenCalledWith("docs", ["ghost"]);
      expect(output.results).toEqual([]);
    });

    it("fail-closed: AclUnavailableError does not forward the change", async () => {
      const dbState = state({ acl: new Map() });
      const ensureDocs = vi.fn(async () => {
        throw new AclUnavailableError("view failed");
      });

      await expect(
        text(
          filterChangesStream(
            stream(JSON.stringify({ results: [{ id: "rec-1", seq: "1-a" }], last_seq: "1-a" })),
            mockCache(dbState, ensureDocs),
            dbState,
            principal("bob"),
            "normal",
          ),
        ),
      ).rejects.toBeInstanceOf(AclUnavailableError);

      await expect(
        text(
          filterChangesStream(
            stream('{"id":"rec-1","seq":"1-a"}\n'),
            mockCache(dbState, ensureDocs),
            dbState,
            principal("bob"),
            "continuous",
          ),
        ),
      ).rejects.toBeInstanceOf(AclUnavailableError);

      expect(ensureDocs).toHaveBeenCalled();
    });

    it("batches multiple missing ids on a continuous chunk", async () => {
      const dbState = state({ acl: new Map() });
      const ensureDocs = vi.fn(async (_db: string, ids: readonly string[]) => {
        for (const id of ids) {
          dbState.acl.set(id, aclRowFromDoc({ _id: id, creator: "alice", acl: ["u-bob"] }));
        }
      });

      const output = await text(
        filterChangesStream(
          stream('{"id":"rec-1","seq":"1-a"}\n{"id":"rec-2","seq":"2-b"}\n'),
          mockCache(dbState, ensureDocs),
          dbState,
          principal("bob"),
          "continuous",
        ),
      );

      expect(ensureDocs).toHaveBeenCalledTimes(1);
      expect(ensureDocs).toHaveBeenCalledWith("docs", ["rec-1", "rec-2"]);
      expect(output).toContain("rec-1");
      expect(output).toContain("rec-2");
    });

    it("does not call ensureDocs when rows are already cached", async () => {
      const dbState = state();
      const ensureDocs = vi.fn(async () => undefined);

      await text(
        filterChangesStream(
          stream('{"id":"shared","seq":"2-b"}\n'),
          mockCache(dbState, ensureDocs),
          dbState,
          principal("bob"),
          "continuous",
        ),
      );

      expect(ensureDocs).not.toHaveBeenCalled();
    });
  });
});
