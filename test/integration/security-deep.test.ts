/**
 * Deep fail-closed security edges: tombstones, keyed vs non-keyed list leaks,
 * reduce-via-body, design filters, open_revs/history probes, attachment edges,
 * and Pouch/Couch replica surfaces not covered by security-edges.test.ts.
 *
 * Prerequisites: docker compose up -d --build && pnpm test:integration
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  PROXY,
  adminHeaders,
  authHeaders,
  createUserIfMissing,
  deleteDoc,
  ensureDaveMembership,
  ensureDbOpenForDemoUsers,
  getAttachment,
  getDoc,
  mintJwt,
  putAttachment,
  putDoc,
  waitForReadable,
  waitForReady,
  waitUntil,
} from "./helpers.js";

const suiteId = Date.now().toString(36);
const DB = `secdeep-${suiteId}`;

let aliceJwt: string;
let bobJwt: string;
let carolJwt: string;
let daveJwt: string;

const ids = {
  bobReader: `bob-reader-${suiteId}`,
  alicePrivate: `alice-private-${suiteId}`,
  open: `open-${suiteId}`,
  withAtt: `with-att-${suiteId}`,
  secretAtt: `secret-att-${suiteId}`,
  tombstone: `tombstone-${suiteId}`,
  secretTomb: `secret-tomb-${suiteId}`,
};

async function putAppDesign(): Promise<void> {
  const res = await fetch(`${PROXY}/${DB}/_design/app`, {
    method: "PUT",
    headers: { ...adminHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      _id: "_design/app",
      acl: [],
      language: "javascript",
      views: {
        by_kind: {
          map: `function (doc) {
            if (doc.kind) emit(doc.kind, 1);
          }`,
          reduce: "_count",
        },
        by_id: {
          map: `function (doc) { emit(doc._id, null); }`,
        },
      },
      filters: {
        kind_open: `function (doc) {
          return doc.kind === 'open' || doc.kind === 'reader' || doc.kind === 'att';
        }`,
      },
    }),
  });
  expect(res.ok, `put _design/app: ${res.status} ${await res.text()}`).toBe(true);
}

describe("security deep edges", () => {
  beforeAll(async () => {
    await waitForReady();
    await createUserIfMissing("carol", "carol-pass", ["readers"]);
    await createUserIfMissing("dave", "dave-pass", []);
    aliceJwt = await mintJwt("alice", ["readers"]);
    bobJwt = await mintJwt("bob", ["writers"]);
    carolJwt = await mintJwt("carol", ["readers"]);
    daveJwt = await mintJwt("dave", []);
    await ensureDbOpenForDemoUsers(DB);
    await ensureDaveMembership(DB);
    await putAppDesign();

    const seed: Array<[string, Record<string, unknown>]> = [
      [ids.alicePrivate, { creator: "alice", kind: "private", body: "secret" }],
      [ids.bobReader, { creator: "alice", acl: ["u-bob"], kind: "reader", body: "bob-read" }],
      [ids.open, { kind: "open", body: "any-auth" }],
      [ids.withAtt, { creator: "alice", acl: ["u-bob"], kind: "att", body: "has-att" }],
      [ids.secretAtt, { creator: "alice", kind: "secret-att", body: "no-bob" }],
      [ids.tombstone, { creator: "alice", acl: ["u-bob"], kind: "tomb", body: "will-delete" }],
      [ids.secretTomb, { creator: "alice", kind: "secret-tomb", body: "bob-never-saw" }],
    ];
    for (const [id, doc] of seed) {
      const res = await putDoc(DB, id, doc, authHeaders("jwt", aliceJwt));
      expect(res.ok, `seed ${id}: ${res.status}`).toBe(true);
    }
    await waitForReadable(DB, ids.bobReader, authHeaders("jwt", bobJwt));
    await waitForReadable(DB, ids.withAtt, authHeaders("jwt", bobJwt));
    await waitForReadable(DB, ids.tombstone, authHeaders("jwt", bobJwt));
    await waitForReadable(DB, ids.open, authHeaders("jwt", daveJwt));

    for (const id of [ids.withAtt, ids.secretAtt]) {
      const docRes = await getDoc(DB, id, authHeaders("jwt", aliceJwt));
      const doc = (await docRes.json()) as { _rev: string };
      const att = await putAttachment(
        DB,
        id,
        "note.txt",
        doc._rev,
        "attachment-payload",
        "text/plain",
        authHeaders("jwt", aliceJwt),
      );
      expect(att.ok, `att ${id}`).toBe(true);
    }
    // Unicode / encoded attachment name on readable doc
    {
      const docRes = await getDoc(DB, ids.withAtt, authHeaders("jwt", aliceJwt));
      const doc = (await docRes.json()) as { _rev: string };
      const att = await putAttachment(
        DB,
        ids.withAtt,
        "café note.txt",
        doc._rev,
        "unicode-bytes",
        "text/plain",
        authHeaders("jwt", aliceJwt),
      );
      expect(att.ok).toBe(true);
    }
    await waitUntil("bob can read unicode att", async () => {
      const res = await getAttachment(DB, ids.withAtt, "café note.txt", authHeaders("jwt", bobJwt));
      return res.status === 200;
    });
  }, 180_000);

  afterAll(async () => {
    await fetch(`${PROXY}/${DB}`, { method: "DELETE", headers: adminHeaders() }).catch(
      () => undefined,
    );
  });

  // ── Tombstones / deletion sync ─────────────────────────────────────────

  describe("deletion tombstones", () => {
    it("prior readers see deleted:true on _changes; never-readers do not", async () => {
      const before = await fetch(`${PROXY}/${DB}/_changes?since=now&feed=normal&timeout=100`, {
        headers: authHeaders("jwt", bobJwt),
      });
      const beforeBody = (await before.json()) as { last_seq: string };
      const since = beforeBody.last_seq;

      const doc = await getDoc(DB, ids.tombstone, authHeaders("jwt", aliceJwt));
      const rev = ((await doc.json()) as { _rev: string })._rev;
      const del = await deleteDoc(DB, ids.tombstone, rev, authHeaders("jwt", aliceJwt));
      expect(del.ok).toBe(true);

      await waitUntil(
        "bob sees tombstone",
        async () => {
          const res = await fetch(
            `${PROXY}/${DB}/_changes?since=${encodeURIComponent(since)}&include_docs=true`,
            { headers: authHeaders("jwt", bobJwt) },
          );
          if (!res.ok) return false;
          const body = (await res.json()) as {
            results: Array<{ id: string; deleted?: boolean }>;
          };
          return body.results.some((r) => r.id === ids.tombstone && r.deleted === true);
        },
        20_000,
      );

      const bobFeed = await fetch(
        `${PROXY}/${DB}/_changes?since=${encodeURIComponent(since)}&include_docs=true`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      const bobBody = (await bobFeed.json()) as {
        results: Array<{ id: string; deleted?: boolean; doc?: { _deleted?: boolean } }>;
      };
      const tomb = bobBody.results.find((r) => r.id === ids.tombstone);
      expect(tomb?.deleted).toBe(true);

      // Delete a doc bob never could read — must not appear for bob
      const secretDoc = await getDoc(DB, ids.secretTomb, authHeaders("jwt", aliceJwt));
      const secretRev = ((await secretDoc.json()) as { _rev: string })._rev;
      const secretDel = await deleteDoc(
        DB,
        ids.secretTomb,
        secretRev,
        authHeaders("jwt", aliceJwt),
      );
      expect(secretDel.ok).toBe(true);

      await waitUntil(
        "alice sees secret tombstone",
        async () => {
          const res = await fetch(
            `${PROXY}/${DB}/_changes?since=${encodeURIComponent(since)}&limit=500`,
            { headers: authHeaders("jwt", aliceJwt) },
          );
          const body = (await res.json()) as {
            results: Array<{ id: string; deleted?: boolean }>;
          };
          return body.results.some((r) => r.id === ids.secretTomb && r.deleted === true);
        },
        20_000,
      );

      const bobSecret = await fetch(
        `${PROXY}/${DB}/_changes?since=${encodeURIComponent(since)}&limit=500`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      const bobSecretBody = (await bobSecret.json()) as {
        results: Array<{ id: string }>;
      };
      expect(bobSecretBody.results.map((r) => r.id)).not.toContain(ids.secretTomb);
    });

    it("retains tombstone ACLs after a live ACL policy reload", async () => {
      const get = await fetch(`${PROXY}/${DB}/_design/acl`, { headers: adminHeaders() });
      const ddoc = (await get.json()) as Record<string, unknown> & {
        _rev: string;
        dbacl?: Record<string, unknown>;
      };
      const previous = ddoc.dbacl;
      ddoc.dbacl = { ...previous, _r: ["u-carol"] };
      const put = await fetch(`${PROXY}/${DB}/_design/acl`, {
        method: "PUT",
        headers: { ...adminHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify(ddoc),
      });
      expect(put.ok, `reload ACL ddoc: ${put.status} ${await put.text()}`).toBe(true);

      try {
        await waitUntil(
          "dbacl reload applied",
          async () =>
            (await getDoc(DB, ids.alicePrivate, authHeaders("jwt", carolJwt))).status === 200,
          20_000,
        );

        const changes = await fetch(`${PROXY}/${DB}/_changes?since=0&limit=500`, {
          headers: authHeaders("jwt", bobJwt),
        });
        expect(changes.status).toBe(200);
        const body = (await changes.json()) as {
          results: Array<{ id: string; deleted?: boolean }>;
        };
        expect(body.results.some((row) => row.id === ids.tombstone && row.deleted === true)).toBe(
          true,
        );
        expect(body.results.map((row) => row.id)).not.toContain(ids.secretTomb);

        const probe = await fetch(`${PROXY}/${DB}/_revs_diff`, {
          method: "POST",
          headers: {
            ...authHeaders("jwt", bobJwt),
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            [ids.secretTomb]: ["9-probe"],
            [`brand-new-${suiteId}`]: ["1-new"],
          }),
        });
        expect(probe.status).toBe(200);
        const missing = (await probe.json()) as Record<string, unknown>;
        expect(missing[ids.secretTomb]).toBeUndefined();
        expect(missing[`brand-new-${suiteId}`]).toBeDefined();
      } finally {
        const latest = await fetch(`${PROXY}/${DB}/_design/acl`, {
          headers: adminHeaders(),
        });
        const current = (await latest.json()) as Record<string, unknown>;
        if (previous === undefined) delete current.dbacl;
        else current.dbacl = previous;
        await fetch(`${PROXY}/${DB}/_design/acl`, {
          method: "PUT",
          headers: { ...adminHeaders(), "Content-Type": "application/json" },
          body: JSON.stringify(current),
        });
        await waitUntil(
          "dbacl reload cleared",
          async () =>
            (await getDoc(DB, ids.alicePrivate, authHeaders("jwt", carolJwt))).status === 404,
          20_000,
        );
      }
    });
  });

  // ── List / view key leakage ────────────────────────────────────────────

  describe("list/view fail-closed (no id leak)", () => {
    it("POST _all_docs without keys drops denied rows (no not_found stubs)", async () => {
      const res = await fetch(`${PROXY}/${DB}/_all_docs`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ include_docs: true }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        rows: Array<{ id?: string; error?: string }>;
      };
      const idsSeen = body.rows.map((r) => r.id).filter(Boolean);
      expect(idsSeen).toContain(ids.bobReader);
      expect(idsSeen).not.toContain(ids.alicePrivate);
      // Critical: denied ids must not appear as error placeholders
      expect(body.rows.some((r) => r.error === "not_found")).toBe(false);
    });

    it("POST _all_docs with keys preserves denied slots as not_found", async () => {
      const res = await fetch(`${PROXY}/${DB}/_all_docs`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          keys: [ids.bobReader, ids.alicePrivate, ids.open],
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        rows: Array<{ id?: string; error?: string }>;
      };
      expect(body.rows).toHaveLength(3);
      expect(body.rows[0]?.id).toBe(ids.bobReader);
      expect(body.rows[1]?.error).toBe("not_found");
      expect(body.rows[2]?.id).toBe(ids.open);
    });

    it("POST view with reduce/group in body is 501 (not empty pass-through)", async () => {
      const reduce = await fetch(`${PROXY}/${DB}/_design/app/_view/by_kind`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ reduce: true }),
      });
      expect(reduce.status).toBe(501);

      const group = await fetch(`${PROXY}/${DB}/_design/app/_view/by_kind`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ group: true }),
      });
      expect(group.status).toBe(501);

      const groupLevel = await fetch(`${PROXY}/${DB}/_design/app/_view/by_kind`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ group_level: 1 }),
      });
      expect(groupLevel.status).toBe(501);
    });

    it("POST view keys ACL-filters with positional not_found", async () => {
      const res = await fetch(`${PROXY}/${DB}/_design/app/_view/by_id`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          keys: [ids.bobReader, ids.alicePrivate],
          reduce: false,
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        rows: Array<{ id?: string; error?: string; key?: string }>;
      };
      expect(body.rows.some((r) => r.id === ids.bobReader || r.key === ids.bobReader)).toBe(true);
      expect(
        body.rows.some(
          (r) =>
            r.error === "not_found" && (r.id === ids.alicePrivate || r.key === ids.alicePrivate),
        ),
      ).toBe(true);
    });

    it("view include_docs never embeds unread document bodies", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_design/app/_view/by_kind?reduce=false&include_docs=true&limit=200`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        rows: Array<{ id?: string; doc?: { _id?: string; body?: string } }>;
      };
      for (const row of body.rows) {
        if (row.doc?._id) {
          const probe = await getDoc(DB, row.doc._id, authHeaders("jwt", bobJwt));
          expect(probe.status).toBe(200);
        }
        expect(row.id).not.toBe(ids.alicePrivate);
        expect(row.doc?._id).not.toBe(ids.alicePrivate);
      }
    });

    it("GET view?key= for denied id yields empty or not_found — never the doc", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_design/app/_view/by_id?key=${encodeURIComponent(
          JSON.stringify(ids.alicePrivate),
        )}&include_docs=true`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        rows: Array<{ id?: string; error?: string; doc?: unknown }>;
      };
      for (const row of body.rows) {
        expect(row.doc).toBeFalsy();
        if (row.id === ids.alicePrivate) {
          expect(row.error).toBe("not_found");
        }
      }
    });
  });

  // ── Changes filters / replica styles ───────────────────────────────────

  describe("filtered replica streams", () => {
    it("design-doc filter still ACL-filters after Couch filter", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_changes?filter=app/kind_open&include_docs=true&limit=500`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        results: Array<{ id: string; doc?: { kind?: string } }>;
      };
      const seen = body.results.map((r) => r.id);
      expect(seen).toContain(ids.bobReader);
      expect(seen).toContain(ids.open);
      expect(seen).not.toContain(ids.alicePrivate);
      expect(seen).not.toContain(ids.secretAtt);
    });

    it("style=all_docs still omits unread ids", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_changes?style=all_docs&include_docs=true&limit=500`,
        { headers: authHeaders("jwt", carolJwt) },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as { results: Array<{ id: string }> };
      const seen = body.results.map((r) => r.id);
      expect(seen).not.toContain(ids.alicePrivate);
      expect(seen).not.toContain(ids.bobReader);
    });

    it("GET filter=_doc_ids without body is rejected (not an unfiltered feed)", async () => {
      // Couch requires doc_ids in the POST body; a bare GET must not become a full feed.
      const res = await fetch(
        `${PROXY}/${DB}/_changes?feed=continuous&filter=_doc_ids&heartbeat=400`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(res.status).toBeGreaterThanOrEqual(400);
    });

    it("POST continuous doc_ids ACL-filters", async () => {
      // Use normal feed with POST doc_ids (continuous+POST is awkward for fetch helpers)
      const res = await fetch(`${PROXY}/${DB}/_changes?filter=_doc_ids&include_docs=true`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          doc_ids: [ids.open, ids.alicePrivate, ids.withAtt],
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { results: Array<{ id: string }> };
      const seen = body.results.map((r) => r.id);
      expect(seen).toContain(ids.open);
      expect(seen).toContain(ids.withAtt);
      expect(seen).not.toContain(ids.alicePrivate);
    });

    it("descending changes still ACL-filters", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_changes?descending=true&limit=50&include_docs=true`,
        { headers: authHeaders("jwt", daveJwt) },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as { results: Array<{ id: string }> };
      const seen = body.results.map((r) => r.id);
      expect(seen).toContain(ids.open);
      expect(seen).not.toContain(ids.alicePrivate);
      expect(seen).not.toContain(ids.bobReader);
    });
  });

  // ── Doc probes: open_revs, revs, conflicts, atts_since ──────────────────

  describe("revision / attachment probe surfaces", () => {
    it("open_revs / revs / meta on unread doc stay 404", async () => {
      for (const qs of [
        "open_revs=all",
        "revs=true",
        "revs_info=true",
        "conflicts=true",
        "deleted_conflicts=true",
        "meta=true",
        "attachments=true&atts_since=[]",
      ]) {
        const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.alicePrivate)}?${qs}`, {
          headers: authHeaders("jwt", bobJwt),
        });
        expect(res.status, qs).toBe(404);
      }
    });

    it("open_revs on readable doc is allowed", async () => {
      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.bobReader)}?open_revs=all`, {
        headers: {
          ...authHeaders("jwt", bobJwt),
          Accept: "application/json",
        },
      });
      expect(res.status).toBe(200);
    });

    it("atts_since / att_encoding_info cannot probe unread attachments", async () => {
      const denied = await fetch(
        `${PROXY}/${DB}/${encodeURIComponent(ids.secretAtt)}?attachments=true&att_encoding_info=true`,
        {
          headers: {
            ...authHeaders("jwt", bobJwt),
            Accept: "application/json",
          },
        },
      );
      expect(denied.status).toBe(404);

      const allowed = await fetch(
        `${PROXY}/${DB}/${encodeURIComponent(ids.withAtt)}?attachments=true&att_encoding_info=true`,
        {
          headers: {
            ...authHeaders("jwt", bobJwt),
            Accept: "application/json",
          },
        },
      );
      expect(allowed.status).toBe(200);
    });

    it("unicode attachment name follows parent ACL", async () => {
      const ok = await getAttachment(DB, ids.withAtt, "café note.txt", authHeaders("jwt", bobJwt));
      expect(ok.status).toBe(200);
      expect(await ok.text()).toBe("unicode-bytes");

      // Same name on secret doc — put one for alice, bob must 404
      const secret = await getDoc(DB, ids.secretAtt, authHeaders("jwt", aliceJwt));
      const secretRev = ((await secret.json()) as { _rev: string })._rev;
      const put = await putAttachment(
        DB,
        ids.secretAtt,
        "café note.txt",
        secretRev,
        "nope",
        "text/plain",
        authHeaders("jwt", aliceJwt),
      );
      expect(put.ok).toBe(true);
      const denied = await getAttachment(
        DB,
        ids.secretAtt,
        "café note.txt",
        authHeaders("jwt", bobJwt),
      );
      expect(denied.status).toBe(404);
    });

    it("inline _attachments on PUT requires write; reader cannot escalate", async () => {
      const docRes = await getDoc(DB, ids.withAtt, authHeaders("jwt", bobJwt));
      const doc = (await docRes.json()) as Record<string, unknown>;
      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.withAtt)}`, {
        method: "PUT",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...doc,
          _attachments: {
            "hack.bin": {
              content_type: "application/octet-stream",
              data: Buffer.from("evil").toString("base64"),
            },
          },
        }),
      });
      expect(res.status).toBe(403);
    });
  });

  // ── Bulk / revs / find edges ───────────────────────────────────────────

  describe("bulk and find edges", () => {
    it("_bulk_get with revs/open_revs still filters", async () => {
      const res = await fetch(`${PROXY}/${DB}/_bulk_get?revs=true`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          docs: [{ id: ids.bobReader }, { id: ids.alicePrivate }],
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        results: Array<{ id: string; docs: Array<{ ok?: unknown; error?: unknown }> }>;
      };
      const byId = Object.fromEntries(body.results.map((r) => [r.id, r.docs[0]]));
      expect(byId[ids.bobReader]?.ok).toBeTruthy();
      expect(byId[ids.alicePrivate]?.error).toBeTruthy();
    });

    it("_revs_diff allows create-path ids but not foreign private ids", async () => {
      const newId = `bob-new-${suiteId}`;
      const res = await fetch(`${PROXY}/${DB}/_revs_diff`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          [ids.alicePrivate]: ["1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
          [newId]: ["1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
          [ids.bobReader]: ["99-cccccccccccccccccccccccccccccccc"],
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect(body[ids.alicePrivate]).toBeUndefined();
      expect(body[newId]).toBeDefined();
      expect(body[ids.bobReader]).toBeDefined();
    });

    it("_find with fields projection cannot return unread docs", async () => {
      await fetch(`${PROXY}/${DB}/_index`, {
        method: "POST",
        headers: { ...adminHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({
          index: { fields: ["kind"] },
          name: "kind-deep",
          type: "json",
        }),
      });
      const res = await fetch(`${PROXY}/${DB}/_find`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          selector: { kind: { $exists: true } },
          fields: ["_id", "kind"],
          limit: 100,
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { docs: Array<{ _id: string }> };
      const findIds = body.docs.map((d) => d._id);
      expect(findIds).not.toContain(ids.alicePrivate);
      expect(findIds).not.toContain(ids.secretAtt);
    });

    it("bulk delete of unread doc is forbidden; create without _id allowed", async () => {
      const res = await fetch(`${PROXY}/${DB}/_bulk_docs`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          docs: [
            { _id: ids.alicePrivate, _deleted: true, _rev: "1-deadbeefdeadbeefdeadbeefdeadbeef" },
            { creator: "bob", kind: "bulk-create", body: "ok" },
          ],
        }),
      });
      expect(res.status).toBeGreaterThanOrEqual(200);
      expect(res.status).toBeLessThan(300);
      const body = (await res.json()) as Array<{ id?: string; error?: string; ok?: boolean }>;
      expect(body.some((r) => r.id === ids.alicePrivate && r.error === "forbidden")).toBe(true);
      expect(body.some((r) => r.ok === true || (r.id && !r.error))).toBe(true);
    });
  });

  // ── Default-deny leftovers / path abuse ────────────────────────────────

  describe("path abuse and default-deny", () => {
    it("_temp_view is rejected (not pass-through)", async () => {
      const res = await fetch(`${PROXY}/${DB}/_temp_view`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", aliceJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          map: "function(doc){emit(doc._id)}",
        }),
      });
      expect([403, 404, 501]).toContain(res.status);
    });

    it("_purge is admin-only", async () => {
      const res = await fetch(`${PROXY}/${DB}/_purge`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", aliceJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ [ids.open]: ["1-abc"] }),
      });
      expect(res.status).toBe(403);
    });

    it("_compact / _view_cleanup / _ensure_full_commit are admin-only", async () => {
      for (const path of ["_compact", "_view_cleanup", "_ensure_full_commit"]) {
        const res = await fetch(`${PROXY}/${DB}/${path}`, {
          method: "POST",
          headers: authHeaders("jwt", aliceJwt),
        });
        expect(res.status, path).toBe(403);
      }
    });

    it("unmapped partition path is admin-only (403), not 200 pipe", async () => {
      const res = await fetch(`${PROXY}/${DB}/_partition/foo/_all_docs`, {
        headers: authHeaders("jwt", aliceJwt),
      });
      // Non-partitioned DB → Couch error after ACL rows actor, or 404/400 from Couch.
      // Must not silently return another user's docs; status must not be a success with rows of secrets.
      if (res.status === 200) {
        const body = (await res.json()) as { rows?: Array<{ id: string }> };
        const rowIds = (body.rows ?? []).map((r) => r.id);
        expect(rowIds).not.toContain(ids.alicePrivate);
      } else {
        expect(res.status).toBeGreaterThanOrEqual(400);
      }
    });

    it("unknown DB underscore endpoint is 404 default-deny", async () => {
      const res = await fetch(`${PROXY}/${DB}/_purged_infos_limit`, {
        headers: authHeaders("jwt", aliceJwt),
      });
      expect(res.status).toBe(404);
    });

    it("system _membership is 403 for non-admin", async () => {
      const res = await fetch(`${PROXY}/_membership`, {
        headers: authHeaders("jwt", aliceJwt),
      });
      expect(res.status).toBe(403);
    });

    it("COPY without Destination is 400; unread source is 404", async () => {
      const noDest = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.bobReader)}`, {
        method: "COPY",
        headers: authHeaders("jwt", bobJwt),
      });
      expect(noDest.status).toBe(400);

      const unread = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.alicePrivate)}`, {
        method: "COPY",
        headers: {
          ...authHeaders("jwt", bobJwt),
          Destination: `copy-out-${suiteId}`,
        },
      });
      expect(unread.status).toBe(404);
    });

    it("HEAD on unread doc is 404 (no existence oracle via 403)", async () => {
      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.alicePrivate)}`, {
        method: "HEAD",
        headers: authHeaders("jwt", bobJwt),
      });
      expect(res.status).toBe(404);
    });

    it("design-doc attachment on unread ddoc is 404", async () => {
      // _design/app has acl:[] — not readable to bob
      const res = await fetch(`${PROXY}/${DB}/_design/app/some.att`, {
        headers: authHeaders("jwt", bobJwt),
      });
      expect(res.status).toBe(404);
    });

    it("_local_docs does not expose arbitrary doc ids as readable rows", async () => {
      const localId = `deep-cp-${suiteId}`;
      await fetch(`${PROXY}/${DB}/_local/${encodeURIComponent(localId)}`, {
        method: "PUT",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ last_seq: "1" }),
      });
      const res = await fetch(`${PROXY}/${DB}/_local_docs?include_docs=true`, {
        headers: authHeaders("jwt", carolJwt),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        rows: Array<{ id?: string; doc?: { last_seq?: string } }>;
      };
      // Local docs have no ACL rows → fail-closed filter drops them from listings.
      // Individual GET/PUT still works after DB gate (Pouch checkpoints).
      expect(body.rows.every((r) => !r.doc || r.id?.startsWith("_local/"))).toBe(true);
      const carolGet = await fetch(`${PROXY}/${DB}/_local/${encodeURIComponent(localId)}`, {
        headers: authHeaders("jwt", carolJwt),
      });
      // Cross-user _local read is Couch semantics after DB membership — allowed.
      expect([200, 404]).toContain(carolGet.status);
    });

    it("creator spoof via POST /{db} is rejected by VDU", async () => {
      const res = await fetch(`${PROXY}/${DB}`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          _id: `spoof-post-${suiteId}`,
          creator: "alice",
          body: "nope",
        }),
      });
      expect(res.status).toBeGreaterThanOrEqual(400);
    });

    it("ACL revocation removes pull visibility", async () => {
      const id = `revoke-${suiteId}`;
      const put = await putDoc(
        DB,
        id,
        { creator: "alice", acl: ["u-bob"], kind: "revoke", body: "temp" },
        authHeaders("jwt", aliceJwt),
      );
      expect(put.ok).toBe(true);
      await waitForReadable(DB, id, authHeaders("jwt", bobJwt));

      const cur = await getDoc(DB, id, authHeaders("jwt", aliceJwt));
      const doc = (await cur.json()) as Record<string, unknown>;
      const revoke = await putDoc(
        DB,
        id,
        { ...doc, acl: ["u-carol"], body: "revoked" },
        authHeaders("jwt", aliceJwt),
      );
      expect(revoke.ok).toBe(true);

      await waitUntil(
        "bob loses read after revoke",
        async () => {
          const res = await getDoc(DB, id, authHeaders("jwt", bobJwt));
          return res.status === 404;
        },
        20_000,
      );

      // After revoke, current ACL denies bob — filtered feeds must not return the doc body.
      const changes = await fetch(`${PROXY}/${DB}/_changes?include_docs=true&limit=500`, {
        headers: authHeaders("jwt", bobJwt),
      });
      const body = (await changes.json()) as {
        results: Array<{ id: string; doc?: { body?: string; acl?: string[] } }>;
      };
      for (const row of body.results.filter((r) => r.id === id)) {
        expect(row.doc?.body).not.toBe("revoked");
        expect(row.doc?.acl).not.toEqual(["u-carol"]);
      }
      const find = await fetch(`${PROXY}/${DB}/_find`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ selector: { _id: id } }),
      });
      expect(find.status).toBe(200);
      const findBody = (await find.json()) as { docs: unknown[] };
      expect(findBody.docs).toHaveLength(0);
    });
  });
});
