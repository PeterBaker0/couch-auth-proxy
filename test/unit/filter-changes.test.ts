import { describe, expect, it } from "vitest";
import type { DbAclState } from "../../src/acl/cache.js";
import { aclRowFromDoc } from "../../src/acl/resolve.js";
import { buildPrincipal } from "../../src/auth/principal.js";
import { filterChangesStream } from "../../src/proxy/filterChanges.js";

const encoder = new TextEncoder();

function principal(name: string) {
  return buildPrincipal({
    ok: true,
    userCtx: { name, roles: [] },
    info: { authenticated: "jwt" },
  });
}

function state(): DbAclState {
  return {
    name: "docs",
    acl: new Map([
      ["private", aclRowFromDoc({ _id: "private", creator: "alice" })],
      ["shared", aclRowFromDoc({ _id: "shared", creator: "alice", acl: ["u-bob"] })],
    ]),
    noacl: false,
    ready: true,
    followerUp: true,
  };
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
      await text(filterChangesStream(upstream, state(), principal("bob"), "normal")),
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
    const upstream = stream(
      '{"id":"pri',
      'vate","seq":"1-a"}\n\n{"id":"shared","seq":"2-b"}\n',
      '{"last_seq":"2-b","pending":0}\nnot-json\n',
    );

    const output = await text(
      filterChangesStream(upstream, state(), principal("bob"), "continuous"),
    );
    expect(output).not.toContain("private");
    expect(output).not.toContain("not-json");
    expect(output).toContain('{"id":"shared","seq":"2-b"}');
    expect(output).toContain('{"last_seq":"2-b","pending":0}');
  });

  it("keeps SSE metadata only for allowed data events", async () => {
    const upstream = stream(
      'data: {"id":"private","seq":"1-a"}\nid: 1-a\n\n',
      'event: message\ndata: {"id":"shared","seq":"2-b"}\nid: 2-b\n\n',
      ": heartbeat\n",
    );

    const output = await text(
      filterChangesStream(upstream, state(), principal("bob"), "eventsource"),
    );
    expect(output).not.toContain("private");
    expect(output).not.toContain("id: 1-a");
    expect(output).toContain('data: {"id":"shared","seq":"2-b"}');
    expect(output).toContain("id: 2-b");
    expect(output).toContain(": heartbeat");
  });

  it("does not let last_seq turn a denied change into control metadata", async () => {
    const continuous = await text(
      filterChangesStream(
        stream(
          '{"id":"private","seq":"1-a","last_seq":"1-a"}\n',
          '{"id":"shared","seq":"2-b","last_seq":"2-b"}\n',
          '{"last_seq":"2-b","pending":0}\n',
        ),
        state(),
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
        state(),
        principal("bob"),
        "eventsource",
      ),
    );
    expect(eventsource).not.toContain("private");
    expect(eventsource).not.toContain("id: 1-a");
    expect(eventsource).toContain('data: {"last_seq":"2-b"}');
  });

  it("rejects oversized buffered normal feeds", async () => {
    const filtered = filterChangesStream(
      stream(JSON.stringify({ results: [], padding: "x".repeat(200) })),
      state(),
      principal("bob"),
      "longpoll",
      { maxBufferBytes: 64 },
    );
    await expect(text(filtered)).rejects.toThrow(/64 bytes/);
  });
});
