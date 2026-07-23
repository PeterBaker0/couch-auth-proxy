/**
 * Real CouchDB 3.5 partitioned-database coverage. These routes have different
 * upstream implementations from their global counterparts and must still
 * enforce per-document ACLs.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  PROXY,
  adminHeaders,
  authHeaders,
  createUserIfMissing,
  mintJwt,
  putDoc,
  waitForReadable,
  waitForReady,
  waitUntil,
} from "./helpers.js";

const suiteId = Date.now().toString(36);
const DB = `partitioned-${suiteId}`;
const ids = {
  private: `team-a:private-${suiteId}`,
  shared: `team-a:shared-${suiteId}`,
  otherPartition: `team-b:shared-${suiteId}`,
};

let aliceJwt: string;
let bobJwt: string;

describe("partitioned CouchDB 3.5 APIs", () => {
  beforeAll(async () => {
    await waitForReady();
    await createUserIfMissing("alice", "alice-pass", ["readers"]);
    await createUserIfMissing("bob", "bob-pass", ["writers"]);
    aliceJwt = await mintJwt("alice", ["readers"]);
    bobJwt = await mintJwt("bob", ["writers"]);

    const create = await fetch(`${PROXY}/${DB}?partitioned=true`, {
      method: "PUT",
      headers: adminHeaders(),
    });
    expect([201, 202, 412]).toContain(create.status);

    const security = await fetch(`${PROXY}/${DB}/_security`, {
      method: "PUT",
      headers: { ...adminHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        admins: { names: [], roles: ["_admin"] },
        members: {
          names: ["alice", "bob"],
          roles: ["readers", "writers"],
        },
      }),
    });
    expect(security.ok, `_security: ${security.status} ${await security.text()}`).toBe(true);

    await waitUntil(
      "partitioned ACL cache ready",
      async () => (await fetch(`${PROXY}/${DB}`, { headers: adminHeaders() })).ok,
      30_000,
    );
    const infoRes = await fetch(`${PROXY}/${DB}`, { headers: adminHeaders() });
    const info = (await infoRes.json()) as { props?: { partitioned?: boolean } };
    expect(info.props?.partitioned).toBe(true);

    const ddoc = await fetch(`${PROXY}/${DB}/_design/app`, {
      method: "PUT",
      headers: { ...adminHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        _id: "_design/app",
        acl: [],
        language: "javascript",
        options: { partitioned: true },
        views: {
          by_kind: {
            map: "function (doc) { if (doc.kind) emit(doc.kind, null); }",
          },
        },
      }),
    });
    expect(ddoc.ok, `partition view: ${ddoc.status} ${await ddoc.text()}`).toBe(true);

    for (const [id, doc] of [
      [ids.private, { creator: "alice", kind: "private" }],
      [ids.shared, { creator: "alice", acl: ["u-bob"], kind: "shared" }],
      [ids.otherPartition, { creator: "alice", acl: ["u-bob"], kind: "other-partition" }],
    ] as Array<[string, Record<string, unknown>]>) {
      const put = await putDoc(DB, id, doc, authHeaders("jwt", aliceJwt));
      expect(put.ok, `seed ${id}: ${put.status} ${await put.text()}`).toBe(true);
    }
    await waitForReadable(DB, ids.shared, authHeaders("jwt", bobJwt));
  }, 180_000);

  afterAll(async () => {
    await fetch(`${PROXY}/${DB}`, { method: "DELETE", headers: adminHeaders() }).catch(
      () => undefined,
    );
  });

  it("filters partition _all_docs without leaking another partition", async () => {
    const res = await fetch(`${PROXY}/${DB}/_partition/team-a/_all_docs?include_docs=true`, {
      headers: authHeaders("jwt", bobJwt),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { rows: Array<{ id: string }> };
    const seen = body.rows.map((row) => row.id);
    expect(seen).toContain(ids.shared);
    expect(seen).not.toContain(ids.private);
    expect(seen).not.toContain(ids.otherPartition);
  });

  it("filters partition Mango when fields omits _id", async () => {
    const res = await fetch(`${PROXY}/${DB}/_partition/team-a/_find`, {
      method: "POST",
      headers: {
        ...authHeaders("jwt", bobJwt),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        selector: { kind: { $exists: true } },
        fields: ["kind"],
        limit: 100,
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { docs: Array<{ _id?: string; kind?: string }> };
    expect(body.docs).toEqual([{ kind: "shared" }]);
    expect(body.docs.every((doc) => doc._id === undefined)).toBe(true);
  });

  it("filters partitioned view rows", async () => {
    const res = await fetch(
      `${PROXY}/${DB}/_partition/team-a/_design/app/_view/by_kind?reduce=false&include_docs=true`,
      { headers: authHeaders("jwt", bobJwt) },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { rows: Array<{ id?: string }> };
    const seen = body.rows.map((row) => row.id);
    expect(seen).toContain(ids.shared);
    expect(seen).not.toContain(ids.private);
    expect(seen).not.toContain(ids.otherPartition);
  });

  it("keeps partition metadata admin-only", async () => {
    const res = await fetch(`${PROXY}/${DB}/_partition/team-a`, {
      headers: authHeaders("jwt", bobJwt),
    });
    expect(res.status).toBe(403);
  });
});
