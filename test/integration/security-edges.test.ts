/**
 * Broad fail-closed security edge cases against docker compose.
 *
 * Covers attachments, custom views, filtered/replica `_changes`, bulk edges,
 * design-doc surfaces, `_local` checkpoints, restrict rules, and rejection of
 * unfilterable / weird endpoints (never silent pass-through).
 *
 * Prerequisites: docker compose up -d --build && pnpm test:integration
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  PROXY,
  adminHeaders,
  authHeaders,
  collectChangesFeed,
  createUserIfMissing,
  deleteDoc,
  ensureDaveMembership,
  ensureDbOpenForDemoUsers,
  getAttachment,
  getDoc,
  mintJwt,
  putAttachment,
  putDoc,
  sleep,
  waitForReadable,
  waitForReady,
  waitUntil,
} from "./helpers.js";

const suiteId = Date.now().toString(36);
const DB = `secedges-${suiteId}`;

let aliceJwt: string;
let bobJwt: string;
let carolJwt: string;
let daveJwt: string;

const ids = {
  alicePrivate: `alice-private-${suiteId}`,
  bobReader: `bob-reader-${suiteId}`,
  bobOwner: `bob-owner-${suiteId}`,
  roleOwner: `role-owner-${suiteId}`,
  open: `open-${suiteId}`,
  withAtt: `with-att-${suiteId}`,
  secretAtt: `secret-att-${suiteId}`,
};

async function putAppView(): Promise<void> {
  const res = await fetch(`${PROXY}/${DB}/_design/app`, {
    method: "PUT",
    headers: { ...adminHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      _id: "_design/app",
      // Hide from non-admins via empty acl (same pattern as _design/acl).
      acl: [],
      language: "javascript",
      views: {
        by_kind: {
          map: `function (doc) {
            if (doc.kind) emit(doc.kind, 1);
          }`,
          reduce: "_count",
        },
      },
      shows: {
        echo: `function (doc, req) {
          return { body: JSON.stringify({ id: doc ? doc._id : null, ok: true }) };
        }`,
      },
      updates: {
        touch: `function (doc, req) {
          if (!doc) {
            return [{ _id: req.uuid, creator: 'evil', body: 'created-via-update' }, 'created'];
          }
          doc.touched = true;
          return [doc, 'touched'];
        }`,
      },
    }),
  });
  expect(res.ok, `put _design/app: ${res.status} ${await res.text()}`).toBe(true);

  // A readable design doc is common and must not turn encoded route
  // separators into an unfiltered attachment passthrough.
  const publicRes = await fetch(`${PROXY}/${DB}/_design/public-app`, {
    method: "PUT",
    headers: { ...adminHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      _id: "_design/public-app",
      language: "javascript",
      views: {
        by_kind: {
          map: `function (doc) {
            if (doc.kind) emit(doc.kind, 1);
          }`,
        },
      },
    }),
  });
  expect(
    publicRes.ok,
    `put _design/public-app: ${publicRes.status} ${await publicRes.text()}`,
  ).toBe(true);
}

describe("security edge cases", () => {
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
    await putAppView();

    const seed: Array<[string, Record<string, unknown>, string]> = [
      [ids.alicePrivate, { creator: "alice", kind: "private", body: "secret" }, aliceJwt],
      [
        ids.bobReader,
        { creator: "alice", acl: ["u-bob"], kind: "reader", body: "bob-read" },
        aliceJwt,
      ],
      [
        ids.bobOwner,
        { creator: "alice", owners: ["u-bob"], kind: "owner", body: "bob-own" },
        aliceJwt,
      ],
      [
        ids.roleOwner,
        { creator: "alice", owners: ["r-writers"], kind: "role-owner", body: "team-edit" },
        aliceJwt,
      ],
      [ids.open, { kind: "open", body: "any-auth" }, aliceJwt],
      [ids.withAtt, { creator: "alice", acl: ["u-bob"], kind: "att", body: "has-att" }, aliceJwt],
      [ids.secretAtt, { creator: "alice", kind: "secret-att", body: "no-bob" }, aliceJwt],
    ];
    for (const [id, doc, jwt] of seed) {
      const res = await putDoc(DB, id, doc, authHeaders("jwt", jwt));
      expect(res.ok, `seed ${id}: ${res.status}`).toBe(true);
    }
    await waitForReadable(DB, ids.bobReader, authHeaders("jwt", bobJwt));
    await waitForReadable(DB, ids.withAtt, authHeaders("jwt", bobJwt));
    await waitForReadable(DB, ids.open, authHeaders("jwt", daveJwt));

    // Attachments on readable + secret docs
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
      expect(att.ok, `att ${id}: ${att.status} ${await att.text()}`).toBe(true);
    }
    await waitUntil("attachment readable for bob", async () => {
      const res = await getAttachment(DB, ids.withAtt, "note.txt", authHeaders("jwt", bobJwt));
      return res.status === 200;
    });
  }, 180_000);

  afterAll(async () => {
    await fetch(`${PROXY}/${DB}`, { method: "DELETE", headers: adminHeaders() }).catch(
      () => undefined,
    );
  });

  // ── Attachments ────────────────────────────────────────────────────────

  describe("attachments", () => {
    it("GET attachment allowed when parent doc is readable", async () => {
      const res = await getAttachment(DB, ids.withAtt, "note.txt", authHeaders("jwt", bobJwt));
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("attachment-payload");
    });

    it("GET attachment denied when parent doc is not readable", async () => {
      const res = await getAttachment(DB, ids.secretAtt, "note.txt", authHeaders("jwt", bobJwt));
      expect(res.status).toBe(404);
    });

    it("HEAD attachment follows parent-doc ACL", async () => {
      const ok = await getAttachment(DB, ids.withAtt, "note.txt", authHeaders("jwt", bobJwt), {
        method: "HEAD",
      });
      expect(ok.status).toBe(200);
      const denied = await getAttachment(
        DB,
        ids.secretAtt,
        "note.txt",
        authHeaders("jwt", bobJwt),
        { method: "HEAD" },
      );
      expect(denied.status).toBe(404);
    });

    it("reader cannot PUT/DELETE attachment; owner/creator can", async () => {
      const bobDoc = await getDoc(DB, ids.withAtt, authHeaders("jwt", bobJwt));
      const rev = ((await bobDoc.json()) as { _rev: string })._rev;

      const readerPut = await putAttachment(
        DB,
        ids.withAtt,
        "hack.txt",
        rev,
        "nope",
        "text/plain",
        authHeaders("jwt", bobJwt),
      );
      // bob is acl reader only on withAtt — write denied
      expect(readerPut.status).toBe(403);

      const ownerDoc = await getDoc(DB, ids.bobOwner, authHeaders("jwt", bobJwt));
      const ownerRev = ((await ownerDoc.json()) as { _rev: string })._rev;
      const ownerPut = await putAttachment(
        DB,
        ids.bobOwner,
        "owner.txt",
        ownerRev,
        "owner-bytes",
        "text/plain",
        authHeaders("jwt", bobJwt),
      );
      expect(ownerPut.ok).toBe(true);

      const aliceDoc = await getDoc(DB, ids.withAtt, authHeaders("jwt", aliceJwt));
      const aliceRev = ((await aliceDoc.json()) as { _rev: string })._rev;
      const alicePut = await putAttachment(
        DB,
        ids.withAtt,
        "alice.txt",
        aliceRev,
        "alice-bytes",
        "text/plain",
        authHeaders("jwt", aliceJwt),
      );
      expect(alicePut.ok).toBe(true);
      const afterPut = (await alicePut.json()) as { rev: string };

      const readerDel = await fetch(
        `${PROXY}/${DB}/${ids.withAtt}/${encodeURIComponent("alice.txt")}?rev=${encodeURIComponent(afterPut.rev)}`,
        { method: "DELETE", headers: authHeaders("jwt", bobJwt) },
      );
      expect(readerDel.status).toBe(403);
    });

    it("inline ?attachments=true never leaks unread docs", async () => {
      const denied = await getDoc(DB, ids.secretAtt, {
        ...authHeaders("jwt", bobJwt),
      });
      // even with query flag, unread parent stays 404
      const deniedAtt = await fetch(
        `${PROXY}/${DB}/${encodeURIComponent(ids.secretAtt)}?attachments=true`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(denied.status).toBe(404);
      expect(deniedAtt.status).toBe(404);

      const allowed = await fetch(
        `${PROXY}/${DB}/${encodeURIComponent(ids.withAtt)}?attachments=true`,
        {
          headers: {
            ...authHeaders("jwt", bobJwt),
            // Force JSON+base64 rather than multipart/related.
            Accept: "application/json",
          },
        },
      );
      expect(allowed.status).toBe(200);
      const body = (await allowed.json()) as {
        _attachments?: Record<string, { data?: string }>;
      };
      expect(body._attachments?.["note.txt"]?.data).toBeTruthy();
    });

    it("_all_docs?attachments=true strips unread docs (no stub leak)", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_all_docs?include_docs=true&attachments=true&keys=${encodeURIComponent(
          JSON.stringify([ids.withAtt, ids.secretAtt]),
        )}`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        rows: Array<{ id?: string; error?: string; doc?: { _attachments?: unknown } }>;
      };
      const byId = Object.fromEntries(body.rows.filter((r) => r.id).map((r) => [r.id!, r]));
      expect(byId[ids.withAtt]?.doc?._attachments).toBeTruthy();
      // keyed query preserves slot as not_found — must not include attachment bytes
      expect(byId[ids.secretAtt]?.error).toBe("not_found");
      expect(byId[ids.secretAtt]?.doc).toBeUndefined();
    });

    it("_bulk_get with attachments filters denied ids", async () => {
      const res = await fetch(`${PROXY}/${DB}/_bulk_get?attachments=true`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
          Accept: "multipart/related",
        },
        body: JSON.stringify({
          docs: [{ id: ids.withAtt }, { id: ids.secretAtt }],
        }),
      });
      expect(res.status).toBe(200);
      const ct = res.headers.get("content-type") || "";
      expect(ct).toMatch(/application\/json/);
      const body = (await res.json()) as {
        results: Array<{
          id: string;
          docs: Array<{ ok?: { _attachments?: unknown }; error?: unknown }>;
        }>;
      };
      const byId = Object.fromEntries(body.results.map((r) => [r.id, r.docs[0]]));
      expect(byId[ids.withAtt]?.ok?._attachments).toBeTruthy();
      expect(byId[ids.secretAtt]?.error).toBeTruthy();
    });

    it("_changes include_docs+attachments never emits unread docs", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_changes?include_docs=true&attachments=true&limit=500`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        results: Array<{ id: string; doc?: { _attachments?: unknown } }>;
      };
      const idsSeen = body.results.map((r) => r.id);
      expect(idsSeen).toContain(ids.withAtt);
      expect(idsSeen).not.toContain(ids.secretAtt);
      expect(idsSeen).not.toContain(ids.alicePrivate);
      const attRow = body.results.find((r) => r.id === ids.withAtt);
      expect(attRow?.doc?._attachments).toBeTruthy();
    });

    it("supports CouchDB attachment names containing path segments", async () => {
      const docRes = await getDoc(DB, ids.withAtt, authHeaders("jwt", aliceJwt));
      const rev = ((await docRes.json()) as { _rev: string })._rev;
      const put = await fetch(
        `${PROXY}/${DB}/${encodeURIComponent(ids.withAtt)}/nested/path.txt?rev=${encodeURIComponent(rev)}`,
        {
          method: "PUT",
          headers: {
            ...authHeaders("jwt", aliceJwt),
            "Content-Type": "text/plain",
          },
          body: "nested-attachment",
        },
      );
      expect(put.ok, `nested attachment PUT: ${put.status} ${await put.text()}`).toBe(true);

      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.withAtt)}/nested/path.txt`, {
        headers: authHeaders("jwt", bobJwt),
      });
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("nested-attachment");
    });

    it("Range request on readable attachment is allowed after ACL", async () => {
      const res = await getAttachment(DB, ids.withAtt, "note.txt", {
        ...authHeaders("jwt", bobJwt),
        Range: "bytes=0-3",
      });
      // Couch may return 206 or full 200 depending on config; never 404 for bob.
      expect([200, 206]).toContain(res.status);
      const text = await res.text();
      expect(text.length).toBeGreaterThan(0);
      expect("attachment-payload".startsWith(text) || text === "attachment-payload").toBe(true);
    });

    it("Range request cannot probe unread attachment", async () => {
      const res = await getAttachment(DB, ids.secretAtt, "note.txt", {
        ...authHeaders("jwt", bobJwt),
        Range: "bytes=0-3",
      });
      expect(res.status).toBe(404);
    });
  });

  // ── Custom views / reduce ──────────────────────────────────────────────

  describe("custom views", () => {
    it("filters custom map view rows by ACL", async () => {
      const res = await fetch(`${PROXY}/${DB}/_design/app/_view/by_kind?reduce=false&limit=100`, {
        headers: authHeaders("jwt", bobJwt),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { rows: Array<{ id?: string }> };
      const rowIds = body.rows.map((r) => r.id).filter(Boolean);
      expect(rowIds).toContain(ids.bobReader);
      expect(rowIds).toContain(ids.withAtt);
      expect(rowIds).not.toContain(ids.alicePrivate);
      expect(rowIds).not.toContain(ids.secretAtt);
    });

    it("rejects encoded design separators instead of piping an unfiltered view", async () => {
      const canonical = await fetch(
        `${PROXY}/${DB}/_design/public-app/_view/by_kind?include_docs=true`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(canonical.status).toBe(200);
      const canonicalBody = (await canonical.json()) as {
        rows: Array<{ id?: string; doc?: { body?: string } }>;
      };
      expect(canonicalBody.rows.map((row) => row.id)).toContain(ids.bobReader);
      expect(canonicalBody.rows.map((row) => row.id)).not.toContain(ids.alicePrivate);

      for (const path of [
        `/${DB}/_design%2Fpublic-app/_view/by_kind?include_docs=true`,
        `/${DB}/_design/public-app/_view%2Fby_kind?include_docs=true`,
      ]) {
        const encoded = await fetch(`${PROXY}${path}`, {
          headers: authHeaders("jwt", bobJwt),
          redirect: "manual",
        });
        expect(encoded.status, path).toBe(404);
        expect(await encoded.text()).not.toContain("secret");
        expect(encoded.headers.get("location")).toBeNull();
      }
    });

    it("reduce=true / group are 501 for non-admins (not aggregate leak)", async () => {
      const reduce = await fetch(`${PROXY}/${DB}/_design/app/_view/by_kind?reduce=true`, {
        headers: authHeaders("jwt", bobJwt),
      });
      expect(reduce.status).toBe(501);

      const group = await fetch(`${PROXY}/${DB}/_design/app/_view/by_kind?group=true`, {
        headers: authHeaders("jwt", bobJwt),
      });
      expect(group.status).toBe(501);
    });

    it("admin may run reduce", async () => {
      const res = await fetch(`${PROXY}/${DB}/_design/app/_view/by_kind?reduce=true`, {
        headers: adminHeaders(),
      });
      expect(res.status).toBe(200);
    });

    it("POST _all_docs keys preserve denied slots as not_found", async () => {
      const res = await fetch(`${PROXY}/${DB}/_all_docs`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ keys: [ids.bobReader, ids.alicePrivate, ids.open] }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        rows: Array<{ id?: string; error?: string; key?: string }>;
      };
      expect(body.rows).toHaveLength(3);
      expect(body.rows[0]?.id).toBe(ids.bobReader);
      expect(body.rows[1]?.error).toBe("not_found");
      expect(body.rows[2]?.id).toBe(ids.open);
    });

    it("_design_docs hides unread design docs from non-admins", async () => {
      const res = await fetch(`${PROXY}/${DB}/_design_docs`, {
        headers: authHeaders("jwt", bobJwt),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { rows: Array<{ id: string }> };
      const ddocIds = body.rows.map((r) => r.id);
      // app + acl ddocs use acl:[] → not readable
      expect(ddocIds).not.toContain("_design/acl");
      expect(ddocIds).not.toContain("_design/app");
    });
  });

  // ── Changes / filtered replica streams ─────────────────────────────────

  describe("changes feeds + filters", () => {
    it("POST _changes with doc_ids still ACL-filters", async () => {
      const res = await fetch(`${PROXY}/${DB}/_changes?include_docs=true&filter=_doc_ids`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          doc_ids: [ids.bobReader, ids.alicePrivate, ids.secretAtt],
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { results: Array<{ id: string }> };
      const seen = body.results.map((r) => r.id);
      expect(seen).toContain(ids.bobReader);
      expect(seen).not.toContain(ids.alicePrivate);
      expect(seen).not.toContain(ids.secretAtt);
    });

    it("POST _changes with mango selector still ACL-filters", async () => {
      const res = await fetch(`${PROXY}/${DB}/_changes?include_docs=true&filter=_selector`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          selector: { kind: { $exists: true } },
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { results: Array<{ id: string }> };
      const seen = new Set(body.results.map((r) => r.id));
      expect(seen.has(ids.bobReader)).toBe(true);
      expect(seen.has(ids.alicePrivate)).toBe(false);
    });

    it("longpoll feed ACL-filters results", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_changes?feed=longpoll&since=0&limit=50&include_docs=true&timeout=100`,
        { headers: authHeaders("jwt", carolJwt) },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        results: Array<{ id: string }>;
        last_seq?: unknown;
      };
      const seen = body.results.map((r) => r.id);
      expect(seen).not.toContain(ids.alicePrivate);
      expect(seen).not.toContain(ids.bobReader);
      if (body.last_seq != null) {
        expect(typeof body.last_seq === "string" || typeof body.last_seq === "number").toBe(true);
      }
    });

    it("eventsource feed omits unread docs", async () => {
      const lines = await collectChangesFeed(
        `${PROXY}/${DB}/_changes?feed=eventsource&since=0&heartbeat=500&include_docs=true`,
        authHeaders("jwt", carolJwt),
        2500,
        30,
      );
      const idsSeen = lines.map((l) => l.id).filter(Boolean);
      expect(idsSeen).not.toContain(ids.alicePrivate);
      expect(idsSeen).not.toContain(ids.withAtt);
    });

    it("continuous feed with attachments omits unread docs", async () => {
      const lines = await collectChangesFeed(
        `${PROXY}/${DB}/_changes?feed=continuous&since=0&heartbeat=500&include_docs=true&attachments=true`,
        authHeaders("jwt", bobJwt),
        2500,
        40,
      );
      const idsSeen = lines.map((l) => l.id).filter(Boolean) as string[];
      expect(idsSeen).toContain(ids.withAtt);
      expect(idsSeen).not.toContain(ids.secretAtt);
      expect(idsSeen).not.toContain(ids.alicePrivate);
    });

    it("unknown feed style is rejected (400), not passed through", async () => {
      const res = await fetch(`${PROXY}/${DB}/_changes?feed=evil`, {
        headers: authHeaders("jwt", bobJwt),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error?: string };
      expect(body.error).toBe("bad_request");
    });
  });

  // ── Bulk edges ─────────────────────────────────────────────────────────

  describe("bulk edges", () => {
    it("all_or_nothing rejects whole transaction when any doc denied", async () => {
      const res = await fetch(`${PROXY}/${DB}/_bulk_docs`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          all_or_nothing: true,
          docs: [
            { _id: ids.alicePrivate, creator: "alice", body: "hack" },
            { creator: "bob", body: "should-not-commit" },
          ],
        }),
      });
      expect(res.status).toBe(403);
    });

    it("new_edits:false replication bulk still ACL-filters", async () => {
      const res = await fetch(`${PROXY}/${DB}/_bulk_docs`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          new_edits: false,
          docs: [
            {
              _id: ids.alicePrivate,
              _rev: "99-deadbeef",
              creator: "alice",
              body: "replay",
            },
            {
              _id: `bob-repl-${suiteId}`,
              _rev: "1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              creator: "bob",
              body: "ok",
            },
          ],
        }),
      });
      expect(res.status).toBeGreaterThanOrEqual(200);
      expect(res.status).toBeLessThan(300);
      const body = (await res.json()) as Array<{ id?: string; error?: string; ok?: boolean }>;
      expect(body.some((r) => r.id === ids.alicePrivate && r.error === "forbidden")).toBe(true);
      // bob create via new_edits:false should be allowed through ACL write path
      expect(
        body.some((r) => r.id === `bob-repl-${suiteId}` && (r.ok === true || r.error == null)),
      ).toBe(true);
    });

    it("malformed _bulk_docs JSON is rejected", async () => {
      const res = await fetch(`${PROXY}/${DB}/_bulk_docs`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: "{not-json",
      });
      expect(res.status).toBe(400);
    });

    it("malformed _find JSON does not pass an unfiltered body", async () => {
      const res = await fetch(`${PROXY}/${DB}/_find`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: "{not-json",
      });
      // Couch or proxy error — never 200 with docs
      expect(res.status).not.toBe(200);
    });
  });

  // ── Show / update / explain fail-closed ────────────────────────────────

  describe("unfilterable design surfaces", () => {
    it("_show without docId is 501 (not pass-through)", async () => {
      const res = await fetch(`${PROXY}/${DB}/_design/app/_show/echo`, {
        headers: authHeaders("jwt", bobJwt),
      });
      expect(res.status).toBe(501);
    });

    it("_update without docId is 501 (blocks create-via-update bypass)", async () => {
      const res = await fetch(`${PROXY}/${DB}/_design/app/_update/touch`, {
        method: "POST",
        headers: authHeaders("jwt", bobJwt),
      });
      expect(res.status).toBe(501);
    });

    it("_show with unread docId is 404", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_design/app/_show/echo/${encodeURIComponent(ids.alicePrivate)}`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(res.status).toBe(404);
    });

    it("_show with readable docId works", async () => {
      const res = await fetch(
        `${PROXY}/${DB}/_design/app/_show/echo/${encodeURIComponent(ids.bobReader)}`,
        { headers: authHeaders("jwt", bobJwt) },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as { id?: string; ok?: boolean };
      expect(body.id).toBe(ids.bobReader);
    });

    it("_update with unread docId is 404; reader cannot invoke mutating handler", async () => {
      const denied = await fetch(
        `${PROXY}/${DB}/_design/app/_update/touch/${encodeURIComponent(ids.alicePrivate)}`,
        { method: "POST", headers: authHeaders("jwt", bobJwt) },
      );
      expect(denied.status).toBe(404);

      const allowed = await fetch(
        `${PROXY}/${DB}/_design/app/_update/touch/${encodeURIComponent(ids.bobReader)}`,
        { method: "POST", headers: authHeaders("jwt", bobJwt) },
      );
      // Update handlers may write or delete arbitrary output, so read alone is insufficient.
      expect(allowed.status).toBe(403);
    });

    it("_explain is admin-only (no index metadata leak)", async () => {
      const denied = await fetch(`${PROXY}/${DB}/_explain`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ selector: { kind: "open" } }),
      });
      expect(denied.status).toBe(403);

      const admin = await fetch(`${PROXY}/${DB}/_explain`, {
        method: "POST",
        headers: {
          ...adminHeaders(),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ selector: { kind: "open" } }),
      });
      expect(admin.status).toBe(200);
    });

    it("non-admin cannot manage mango indexes", async () => {
      const res = await fetch(`${PROXY}/${DB}/_index`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", aliceJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          index: { fields: ["body"] },
          name: "should-fail",
          type: "json",
        }),
      });
      expect(res.status).toBe(403);
    });
  });

  // ── _local checkpoints ─────────────────────────────────────────────────

  describe("_local docs (Pouch checkpoints)", () => {
    it("DB members can read/write _local checkpoints after DB gate", async () => {
      const localId = `checkpoint-${suiteId}`;
      const put = await fetch(`${PROXY}/${DB}/_local/${encodeURIComponent(localId)}`, {
        method: "PUT",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ last_seq: "1-abc", session_id: "bob" }),
      });
      expect(put.ok).toBe(true);

      // Cross-user read of _local is intentional Couch/Pouch checkpoint semantics
      // (no per-doc ACL rows). Still requires DB membership.
      const cross = await fetch(`${PROXY}/${DB}/_local/${encodeURIComponent(localId)}`, {
        headers: authHeaders("jwt", aliceJwt),
      });
      expect(cross.status).toBe(200);
    });

    it("anonymous cannot use _local on member DB", async () => {
      const res = await fetch(`${PROXY}/${DB}/_local/anon-${suiteId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ x: 1 }),
      });
      expect([401, 403, 404]).toContain(res.status);
    });
  });

  // ── Restrict / anonymous / VDU / design writes ─────────────────────────

  describe("restrict, anonymity, and VDU", () => {
    it("anonymous cannot read open docs (no r-* token)", async () => {
      const res = await getDoc(DB, ids.open, {});
      expect([401, 403, 404]).toContain(res.status);
    });

    it("authenticated dave can read open docs but not private", async () => {
      expect((await getDoc(DB, ids.open, authHeaders("jwt", daveJwt))).status).toBe(200);
      expect((await getDoc(DB, ids.alicePrivate, authHeaders("jwt", daveJwt))).status).toBe(404);
    });

    it("a writer cannot claim creator ownership of an existing open doc", async () => {
      const current = await getDoc(DB, ids.open, authHeaders("jwt", bobJwt));
      expect(current.status).toBe(200);
      const doc = (await current.json()) as Record<string, unknown>;
      const claim = await putDoc(
        DB,
        ids.open,
        { ...doc, creator: "bob" },
        authHeaders("jwt", bobJwt),
      );
      expect(claim.status).toBe(403);
      const after = (await (
        await getDoc(DB, ids.open, authHeaders("jwt", daveJwt))
      ).json()) as Record<string, unknown>;
      expect(after.creator).toBeUndefined();
    });

    it("owner cannot escalate by rewriting acl/owners (VDU)", async () => {
      const docRes = await getDoc(DB, ids.bobOwner, authHeaders("jwt", bobJwt));
      const doc = (await docRes.json()) as Record<string, unknown>;
      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.bobOwner)}`, {
        method: "PUT",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...doc,
          acl: ["u-carol"],
          owners: ["u-bob", "u-carol"],
        }),
      });
      expect(res.status).toBeGreaterThanOrEqual(400);
      const carol = await getDoc(DB, ids.bobOwner, authHeaders("jwt", carolJwt));
      expect(carol.status).toBe(404);
    });

    it("role owner can change readers but cannot retarget parent inheritance", async () => {
      const current = await getDoc(DB, ids.roleOwner, authHeaders("jwt", bobJwt));
      expect(current.status).toBe(200);
      const doc = (await current.json()) as Record<string, unknown>;
      const share = await putDoc(
        DB,
        ids.roleOwner,
        { ...doc, acl: ["u-carol"] },
        authHeaders("jwt", bobJwt),
      );
      expect(share.ok, `role owner share: ${share.status} ${await share.text()}`).toBe(true);
      await waitForReadable(DB, ids.roleOwner, authHeaders("jwt", carolJwt));

      const latest = await getDoc(DB, ids.roleOwner, authHeaders("jwt", bobJwt));
      const latestDoc = (await latest.json()) as Record<string, unknown>;
      const retarget = await putDoc(
        DB,
        ids.roleOwner,
        { ...latestDoc, parent: ids.open },
        authHeaders("jwt", bobJwt),
      );
      expect(retarget.status).toBeGreaterThanOrEqual(400);
    });

    it("owner cannot bypass delete ACL with a PUT tombstone", async () => {
      const docRes = await getDoc(DB, ids.bobOwner, authHeaders("jwt", bobJwt));
      const doc = (await docRes.json()) as Record<string, unknown>;
      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.bobOwner)}`, {
        method: "PUT",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ...doc, _deleted: true }),
      });
      expect(res.status).toBe(403);
      expect((await getDoc(DB, ids.bobOwner, authHeaders("jwt", bobJwt))).status).toBe(200);
    });

    it("non-admin cannot PUT design docs", async () => {
      const res = await fetch(`${PROXY}/${DB}/_design/evil`, {
        method: "PUT",
        headers: {
          ...authHeaders("jwt", aliceJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          views: { all: { map: "function(d){emit(d._id)}" } },
        }),
      });
      expect([403, 404]).toContain(res.status);
    });

    it("COPY to existing unread destination is forbidden", async () => {
      // Destination already exists as alice-private — bob cannot write it.
      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.bobReader)}`, {
        method: "COPY",
        headers: {
          ...authHeaders("jwt", bobJwt),
          Destination: ids.alicePrivate,
        },
      });
      expect(res.status).toBe(403);
    });

    it("COPY authorizes the destination id before its rev query", async () => {
      const existing = await getDoc(DB, ids.alicePrivate, authHeaders("jwt", aliceJwt));
      const rev = ((await existing.json()) as { _rev: string })._rev;
      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.bobReader)}`, {
        method: "COPY",
        headers: {
          ...authHeaders("jwt", bobJwt),
          Destination: `${encodeURIComponent(ids.alicePrivate)}?rev=${encodeURIComponent(rev)}`,
        },
      });
      expect(res.status).toBe(403);
    });

    it("COPY rejects absolute and cross-database destinations", async () => {
      for (const destination of [
        `${DB}-other/copied`,
        `/${DB}/copied`,
        `https://example.test/${DB}/copied`,
      ]) {
        const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.bobReader)}`, {
          method: "COPY",
          headers: {
            ...authHeaders("jwt", bobJwt),
            Destination: destination,
          },
        });
        expect(res.status, destination).toBe(400);
      }
    });

    it("parent-inherited delete is enforced by the proxy and accepted by Couch", async () => {
      const parentId = `delete-parent-${suiteId}`;
      const childId = `delete-child-${suiteId}`;
      const parent = await putDoc(
        DB,
        parentId,
        { creator: "bob", kind: "delete-parent" },
        authHeaders("jwt", bobJwt),
      );
      expect(parent.ok).toBe(true);
      const child = await putDoc(
        DB,
        childId,
        { creator: "alice", parent: parentId, kind: "delete-child" },
        authHeaders("jwt", aliceJwt),
      );
      expect(child.ok).toBe(true);
      await waitForReadable(DB, childId, authHeaders("jwt", bobJwt));

      const current = await getDoc(DB, childId, authHeaders("jwt", aliceJwt));
      const rev = ((await current.json()) as { _rev: string })._rev;
      const deleted = await deleteDoc(DB, childId, rev, authHeaders("jwt", bobJwt));
      expect(deleted.ok, `inherited delete: ${deleted.status} ${await deleted.text()}`).toBe(true);
    });

    it("restrict.* hides DB from _all_dbs and returns 404 on access", async () => {
      const get = await fetch(`${PROXY}/${DB}/_design/acl`, { headers: adminHeaders() });
      const ddoc = (await get.json()) as Record<string, unknown> & { _rev: string };
      const prev = ddoc.restrict;
      ddoc.restrict = { "*": ["u-alice"] };
      const put = await fetch(`${PROXY}/${DB}/_design/acl`, {
        method: "PUT",
        headers: { ...adminHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify(ddoc),
      });
      expect(put.ok).toBe(true);

      try {
        await waitUntil(
          "restrict applied for bob",
          async () => {
            const probe = await fetch(`${PROXY}/${DB}`, {
              headers: authHeaders("jwt", bobJwt),
            });
            return probe.status === 404;
          },
          20_000,
        );

        const bobDb = await fetch(`${PROXY}/${DB}`, {
          headers: authHeaders("jwt", bobJwt),
        });
        expect(bobDb.status).toBe(404);

        const all = await fetch(`${PROXY}/_all_dbs`, {
          headers: authHeaders("jwt", bobJwt),
        });
        expect(all.status).toBe(200);
        const dbs = (await all.json()) as string[];
        expect(dbs).not.toContain(DB);

        const aliceDb = await fetch(`${PROXY}/${DB}`, {
          headers: authHeaders("jwt", aliceJwt),
        });
        expect(aliceDb.status).toBe(200);
      } finally {
        const again = await fetch(`${PROXY}/${DB}/_design/acl`, {
          headers: adminHeaders(),
        });
        const cur = (await again.json()) as Record<string, unknown>;
        if (prev === undefined) delete cur.restrict;
        else cur.restrict = prev;
        await fetch(`${PROXY}/${DB}/_design/acl`, {
          method: "PUT",
          headers: { ...adminHeaders(), "Content-Type": "application/json" },
          body: JSON.stringify(cur),
        });
        await waitUntil(
          "restrict cleared for bob",
          async () => {
            const probe = await fetch(`${PROXY}/${DB}`, {
              headers: authHeaders("jwt", bobJwt),
            });
            return probe.status === 200;
          },
          20_000,
        );
      }
    });

    it("method restrict can block attachments=true query", async () => {
      const get = await fetch(`${PROXY}/${DB}/_design/acl`, { headers: adminHeaders() });
      const ddoc = (await get.json()) as Record<string, unknown> & { _rev: string };
      const prev = ddoc.restrict;
      ddoc.restrict = {
        get: {
          // Trailing * is wrong: restrict `*` is `.+` (one or more), so
          // `*attachments=true` matches `...?attachments=true` exactly.
          "*attachments=true": ["u-alice"],
        },
        put: {
          "*": [],
        },
      };
      const put = await fetch(`${PROXY}/${DB}/_design/acl`, {
        method: "PUT",
        headers: { ...adminHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify(ddoc),
      });
      expect(put.ok).toBe(true);

      try {
        await waitUntil(
          "method restrict applied",
          async () => {
            const probe = await fetch(
              `${PROXY}/${DB}/${encodeURIComponent(ids.withAtt)}?attachments=true`,
              { headers: authHeaders("jwt", bobJwt) },
            );
            return probe.status === 403;
          },
          20_000,
        );

        const bob = await fetch(
          `${PROXY}/${DB}/${encodeURIComponent(ids.withAtt)}?attachments=true`,
          { headers: authHeaders("jwt", bobJwt) },
        );
        expect(bob.status).toBe(403);

        const alice = await fetch(
          `${PROXY}/${DB}/${encodeURIComponent(ids.withAtt)}?attachments=true`,
          { headers: authHeaders("jwt", aliceJwt) },
        );
        expect(alice.status).toBe(200);

        const copy = await fetch(`${PROXY}/${DB}/${encodeURIComponent(ids.bobReader)}`, {
          method: "COPY",
          headers: {
            ...authHeaders("jwt", bobJwt),
            Destination: `copy-blocked-${suiteId}`,
          },
        });
        expect(copy.status).toBe(403);
      } finally {
        const again = await fetch(`${PROXY}/${DB}/_design/acl`, {
          headers: adminHeaders(),
        });
        const cur = (await again.json()) as Record<string, unknown>;
        if (prev === undefined) delete cur.restrict;
        else cur.restrict = prev;
        await fetch(`${PROXY}/${DB}/_design/acl`, {
          method: "PUT",
          headers: { ...adminHeaders(), "Content-Type": "application/json" },
          body: JSON.stringify(cur),
        });
        await sleep(500);
      }
    });
  });

  // ── Misc default-deny / admin surfaces ─────────────────────────────────

  describe("default-deny leftovers", () => {
    it("search/nouveau paths are admin-only", async () => {
      const search = await fetch(`${PROXY}/${DB}/_design/app/_search/foo`, {
        headers: authHeaders("jwt", aliceJwt),
      });
      expect(search.status).toBe(403);

      const nouveau = await fetch(`${PROXY}/${DB}/_design/app/_nouveau/foo`, {
        headers: authHeaders("jwt", aliceJwt),
      });
      expect(nouveau.status).toBe(403);
    });

    it("_all_dbs does not auto-install ACL design docs as a listing side effect", async () => {
      const freshDb = `list-only-${suiteId}`;
      const create = await fetch(`${PROXY}/${freshDb}`, {
        method: "PUT",
        headers: adminHeaders(),
      });
      expect(create.ok).toBe(true);
      try {
        const listed = await fetch(`${PROXY}/_all_dbs`, {
          headers: authHeaders("jwt", bobJwt),
        });
        expect(listed.status).toBe(200);

        const info = await fetch(`${PROXY}/_dbs_info`, {
          method: "POST",
          headers: {
            ...adminHeaders(),
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ keys: [freshDb] }),
        });
        expect(info.status).toBe(200);
        const dbs = (await info.json()) as Array<{ info?: { doc_count?: number } }>;
        expect(dbs[0]?.info?.doc_count).toBe(0);
      } finally {
        await fetch(`${PROXY}/${freshDb}`, {
          method: "DELETE",
          headers: adminHeaders(),
        });
      }
    });

    it("_replicate is admin-only", async () => {
      const res = await fetch(`${PROXY}/_replicate`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", aliceJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ source: DB, target: `${DB}-clone` }),
      });
      expect(res.status).toBe(403);
    });

    it("_missing_revs omits unauthorized ids", async () => {
      const res = await fetch(`${PROXY}/${DB}/_missing_revs`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          [ids.alicePrivate]: ["1-abc"],
          [ids.bobReader]: ["1-def"],
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { [ids: string]: unknown } & {
        missing_revs?: Record<string, unknown>;
      };
      // Couch wraps as { missing_revs: { id: [...] } } on some versions
      const missing = (body.missing_revs ?? body) as Record<string, unknown>;
      expect(missing[ids.alicePrivate]).toBeUndefined();
      expect(missing[ids.bobReader]).toBeDefined();
    });

    it("system _users is reachable for session users but not ACL-auto-mutated", async () => {
      // noacl pass-through: members/admins use Couch _security only
      const res = await fetch(`${PROXY}/_users`, {
        headers: authHeaders("jwt", aliceJwt),
      });
      // alice is not necessarily a _users member — 401/403/404 all fine; not 500
      expect(res.status).toBeLessThan(500);
    });
  });
});
