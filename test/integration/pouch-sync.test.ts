/**
 * Realistic PouchDB (memory) ↔ couch-auth-proxy sync scenarios.
 *
 * Covers auth modes for sync and ACL filter combinations on pull/push
 * surfaces (_changes, _bulk_get, _revs_diff, _bulk_docs).
 *
 * Prerequisites: docker compose up -d --build && pnpm test:integration
 */
import PouchDB from "pouchdb";
import memoryAdapter from "pouchdb-adapter-memory";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  PROXY,
  adminHeaders,
  authHeaders,
  createUserIfMissing,
  ensureDbOpenForDemoUsers,
  getDoc,
  mintJwt,
  putDoc,
  sleep,
  waitForReadable,
  waitForReady,
  waitUntil,
} from "./helpers.js";

PouchDB.plugin(memoryAdapter);

type Doc = Record<string, unknown> & { _id: string; _rev?: string };

const suiteId = Date.now().toString(36);
const DB = `pouchsync-${suiteId}`;

let aliceJwt: string;
let bobJwt: string;
let carolJwt: string;
let daveJwt: string; // authenticated, no special roles beyond r-*

function memoryDb(name: string): PouchDB.Database {
  return new PouchDB(`mem-${name}-${Math.random().toString(36).slice(2)}`, {
    adapter: "memory",
  });
}

function remoteWithJwt(jwt: string): PouchDB.Database {
  return new PouchDB(`${PROXY}/${DB}`, {
    // couch-auth-proxy DBs are provisioned by tests/ops — never auto-PUT /db
    skip_setup: true,
    fetch(url: string | Request, opts: RequestInit = {}) {
      const headers = new Headers(opts.headers);
      headers.set("Authorization", `Bearer ${jwt}`);
      return PouchDB.fetch(url, { ...opts, headers });
    },
  });
}

function remoteWithBasic(user: string, pass: string): PouchDB.Database {
  return new PouchDB(`${PROXY}/${DB}`, {
    skip_setup: true,
    auth: { username: user, password: pass },
  });
}

async function remoteWithCookie(user: string, pass: string): Promise<PouchDB.Database> {
  const login = await fetch(`${PROXY}/_session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: user, password: pass }),
  });
  expect(login.status).toBe(200);
  const setCookie = login.headers.getSetCookie?.()?.[0] ?? login.headers.get("set-cookie") ?? "";
  const cookie = setCookie.split(";")[0]!;
  expect(cookie).toMatch(/^AuthSession=/);

  return new PouchDB(`${PROXY}/${DB}`, {
    skip_setup: true,
    fetch(url: string | Request, opts: RequestInit = {}) {
      const headers = new Headers(opts.headers);
      headers.set("Cookie", cookie);
      return PouchDB.fetch(url, { ...opts, headers });
    },
  });
}

async function idsInLocal(db: PouchDB.Database): Promise<Set<string>> {
  const all = await db.allDocs();
  return new Set(all.rows.map((r) => r.id).filter((id) => !id.startsWith("_design/")));
}

async function seedAclCorpus(): Promise<Record<string, string>> {
  const alice = authHeaders("jwt", aliceJwt);
  const ids = {
    alicePrivate: `alice-private-${suiteId}`,
    bobReader: `bob-reader-${suiteId}`,
    bobOwner: `bob-owner-${suiteId}`,
    roleReaders: `role-readers-${suiteId}`,
    parent: `parent-${suiteId}`,
    child: `child-${suiteId}`,
    open: `open-${suiteId}`,
    carolOnly: `carol-only-${suiteId}`,
  };

  const puts: Array<[string, Record<string, unknown>]> = [
    [ids.alicePrivate, { creator: "alice", kind: "alice-private", body: "secret" }],
    [ids.bobReader, { creator: "alice", acl: ["u-bob"], kind: "bob-reader", body: "bob may read" }],
    [
      ids.bobOwner,
      { creator: "alice", owners: ["u-bob"], kind: "bob-owner", body: "bob may write" },
    ],
    [
      ids.roleReaders,
      {
        creator: "alice",
        acl: ["r-readers"],
        kind: "role-readers",
        body: "role grant",
      },
    ],
    [ids.parent, { creator: "alice", acl: ["u-bob"], kind: "parent", body: "parent" }],
    [ids.child, { creator: "carol", parent: ids.parent, kind: "child", body: "inherits bob read" }],
    [ids.open, { kind: "open", body: "any authenticated user" }],
    [ids.carolOnly, { creator: "carol", kind: "carol-only", body: "carol private" }],
  ];

  for (const [id, doc] of puts) {
    // carol-only created by carol; others by alice
    const headers = id === ids.carolOnly || id === ids.child ? authHeaders("jwt", carolJwt) : alice;
    // child creator carol — use carol for VDU
    const res = await putDoc(DB, id, doc, headers);
    expect(res.ok, `seed ${id}: ${res.status} ${await res.text()}`).toBe(true);
  }

  await waitForReadable(DB, ids.bobReader, authHeaders("jwt", bobJwt));
  await waitForReadable(DB, ids.child, authHeaders("jwt", bobJwt));
  await waitForReadable(DB, ids.open, authHeaders("jwt", daveJwt));
  return ids;
}

describe("PouchDB memory sync + ACL", () => {
  let ids: Record<string, string>;
  const remotes: PouchDB.Database[] = [];
  const locals: PouchDB.Database[] = [];

  beforeAll(async () => {
    await waitForReady();
    await createUserIfMissing("carol", "carol-pass", ["readers"]);
    await createUserIfMissing("dave", "dave-pass", []);
    aliceJwt = await mintJwt("alice", ["readers"]);
    bobJwt = await mintJwt("bob", ["writers"]);
    carolJwt = await mintJwt("carol", ["readers"]);
    daveJwt = await mintJwt("dave", []);
    await ensureDbOpenForDemoUsers(DB);
    // dave needs membership — add by name
    const secRes = await fetch(`${PROXY}/${DB}/_security`, { headers: adminHeaders() });
    const sec = (await secRes.json()) as {
      admins: unknown;
      members: { names: string[]; roles: string[] };
    };
    if (!sec.members.names.includes("dave")) {
      sec.members.names.push("dave");
      await fetch(`${PROXY}/${DB}/_security`, {
        method: "PUT",
        headers: { ...adminHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify(sec),
      });
    }
    ids = await seedAclCorpus();
  }, 120_000);

  afterAll(async () => {
    await Promise.allSettled([...locals, ...remotes].map((db) => db.close()));
    // Best-effort cleanup of temp DB
    await fetch(`${PROXY}/${DB}`, { method: "DELETE", headers: adminHeaders() }).catch(
      () => undefined,
    );
  });

  function trackLocal(name: string): PouchDB.Database {
    const db = memoryDb(name);
    locals.push(db);
    return db;
  }

  function trackRemote(db: PouchDB.Database): PouchDB.Database {
    remotes.push(db);
    return db;
  }

  // ── Auth behaviour for sync ───────────────────────────────────────────

  describe("sync authentication", () => {
    it("JWT pull succeeds for a member user", async () => {
      const local = trackLocal("jwt-pull");
      const remote = trackRemote(remoteWithJwt(aliceJwt));
      const result = await local.replicate.from(remote);
      expect(result.ok).toBe(true);
      expect(result.docs_written).toBeGreaterThan(0);
      const have = await idsInLocal(local);
      expect(have.has(ids.alicePrivate)).toBe(true);
      expect(have.has(ids.open)).toBe(true);
    });

    it("Basic auth pull succeeds", async () => {
      const local = trackLocal("basic-pull");
      const remote = trackRemote(remoteWithBasic("bob", "bob-pass"));
      const result = await local.replicate.from(remote);
      expect(result.ok).toBe(true);
      const have = await idsInLocal(local);
      expect(have.has(ids.bobReader)).toBe(true);
      expect(have.has(ids.alicePrivate)).toBe(false);
    });

    it("cookie AuthSession pull succeeds", async () => {
      const local = trackLocal("cookie-pull");
      const remote = trackRemote(await remoteWithCookie("alice", "alice-pass"));
      const result = await local.replicate.from(remote);
      expect(result.ok).toBe(true);
      const have = await idsInLocal(local);
      expect(have.has(ids.alicePrivate)).toBe(true);
    });

    it("expired JWT cannot sync", async () => {
      const expired = await mintJwt("alice", ["readers"], "0s");
      await sleep(50);
      const local = trackLocal("expired");
      const remote = trackRemote(remoteWithJwt(expired));
      await expect(local.replicate.from(remote)).rejects.toBeTruthy();
    });

    it("wrong Basic password cannot sync", async () => {
      // Use a throwaway identity so failed attempts do not lock demo users.
      const local = trackLocal("bad-basic");
      const remote = trackRemote(remoteWithBasic("nosuch-user", "wrong-pass"));
      await expect(local.replicate.from(remote)).rejects.toBeTruthy();
    });

    it("anonymous remote cannot pull member DB content", async () => {
      const local = trackLocal("anon");
      const remote = trackRemote(new PouchDB(`${PROXY}/${DB}`, { skip_setup: true }));
      remotes.push(remote);
      await expect(local.replicate.from(remote)).rejects.toBeTruthy();
    });
  });

  // ── ACL pull filter matrix ─────────────────────────────────────────────

  describe("pull filtering (ACL matrix)", () => {
    async function pullAs(jwt: string): Promise<Set<string>> {
      const local = trackLocal(`pull-${jwt.slice(-8)}`);
      const remote = trackRemote(remoteWithJwt(jwt));
      const result = await local.replicate.from(remote);
      expect(result.ok).toBe(true);
      return idsInLocal(local);
    }

    it("creator pulls private docs; non-readers do not", async () => {
      const alice = await pullAs(aliceJwt);
      const bob = await pullAs(bobJwt);
      const carol = await pullAs(carolJwt);
      expect(alice.has(ids.alicePrivate)).toBe(true);
      expect(bob.has(ids.alicePrivate)).toBe(false);
      expect(carol.has(ids.alicePrivate)).toBe(false);
      expect(carol.has(ids.carolOnly)).toBe(true);
      expect(alice.has(ids.carolOnly)).toBe(false);
    });

    it("acl[] grants read-only visibility on pull", async () => {
      const bob = await pullAs(bobJwt);
      expect(bob.has(ids.bobReader)).toBe(true);
      expect(bob.has(ids.bobOwner)).toBe(true);
    });

    it("role token r-readers grants pull to alice/carol not bob", async () => {
      const alice = await pullAs(aliceJwt);
      const bob = await pullAs(bobJwt);
      const carol = await pullAs(carolJwt);
      expect(alice.has(ids.roleReaders)).toBe(true);
      expect(carol.has(ids.roleReaders)).toBe(true);
      expect(bob.has(ids.roleReaders)).toBe(false);
    });

    it("parent inheritance exposes child on pull", async () => {
      const bob = await pullAs(bobJwt);
      const dave = await pullAs(daveJwt);
      expect(bob.has(ids.child)).toBe(true);
      expect(bob.has(ids.parent)).toBe(true);
      expect(dave.has(ids.child)).toBe(false);
      expect(dave.has(ids.parent)).toBe(false);
    });

    it("open docs (no creator/owners/acl) pull for any authenticated user", async () => {
      const dave = await pullAs(daveJwt);
      expect(dave.has(ids.open)).toBe(true);
      // dave should not see restricted corpus
      expect(dave.has(ids.alicePrivate)).toBe(false);
      expect(dave.has(ids.bobReader)).toBe(false);
      expect(dave.has(ids.carolOnly)).toBe(false);
    });

    it("_design/acl body stays hidden from non-admin pull when acl:[]", async () => {
      const bob = await pullAs(bobJwt);
      const local = trackLocal("ddoc-check");
      const remote = trackRemote(remoteWithJwt(bobJwt));
      await local.replicate.from(remote);
      await expect(local.get("_design/acl")).rejects.toMatchObject({ status: 404 });
      // allDocs also omits it for bob
      expect(bob.has("_design/acl")).toBe(false);
    });
  });

  // ── Push / write ACL via sync ──────────────────────────────────────────

  describe("push filtering (write ACL)", () => {
    it("creator can push updates to own doc", async () => {
      const local = trackLocal("push-creator");
      const remote = trackRemote(remoteWithJwt(aliceJwt));
      await local.replicate.from(remote);
      const doc = (await local.get(ids.alicePrivate)) as Doc;
      doc.body = "updated-by-alice";
      await local.put(doc);
      const push = await local.replicate.to(remote);
      expect(push.ok).toBe(true);
      expect(push.docs_written).toBeGreaterThanOrEqual(1);
      const remoteDoc = await getDoc(DB, ids.alicePrivate, authHeaders("jwt", aliceJwt));
      expect(remoteDoc.status).toBe(200);
      expect((await remoteDoc.json()).body).toBe("updated-by-alice");
    });

    it("acl reader cannot push updates (forbidden)", async () => {
      const local = trackLocal("push-reader");
      const remote = trackRemote(remoteWithJwt(bobJwt));
      await local.replicate.from(remote);
      const doc = (await local.get(ids.bobReader)) as Doc;
      doc.body = "bob-hack";
      await local.put(doc);
      // Pouch may surface errors or write 0 docs depending on bulk reply handling
      try {
        const push = await local.replicate.to(remote);
        expect(push.docs_written).toBe(0);
        expect((push.errors ?? []).length + (push.doc_write_failures ?? 0)).toBeGreaterThan(0);
      } catch {
        // reject is also acceptable fail-closed behaviour
      }
      const remoteDoc = await getDoc(DB, ids.bobReader, authHeaders("jwt", aliceJwt));
      const body = await remoteDoc.json();
      expect(body.body).not.toBe("bob-hack");
    });

    it("owner can push updates but cannot delete", async () => {
      const local = trackLocal("push-owner");
      const remote = trackRemote(remoteWithJwt(bobJwt));
      await local.replicate.from(remote);
      const doc = (await local.get(ids.bobOwner)) as Doc;
      doc.body = "owner-edit";
      await local.put(doc);
      const push = await local.replicate.to(remote);
      expect(push.ok).toBe(true);
      expect(push.docs_written).toBeGreaterThanOrEqual(1);

      const updated = (await local.get(ids.bobOwner)) as Doc;
      await local.remove(updated);
      try {
        const delPush = await local.replicate.to(remote);
        expect(delPush.docs_written).toBe(0);
      } catch {
        // ok
      }
      const still = await getDoc(DB, ids.bobOwner, authHeaders("jwt", aliceJwt));
      expect(still.status).toBe(200);
    });

    it("new doc push as authenticated user succeeds (create path)", async () => {
      const local = trackLocal("push-create");
      const remote = trackRemote(remoteWithJwt(bobJwt));
      const id = `bob-created-${suiteId}`;
      await local.put({ _id: id, creator: "bob", kind: "created", body: "from-pouch" });
      const push = await local.replicate.to(remote);
      expect(push.ok).toBe(true);
      await waitForReadable(DB, id, authHeaders("jwt", bobJwt));
      const denied = await getDoc(DB, id, authHeaders("jwt", carolJwt));
      expect(denied.status).toBe(404);
    });

    it("cannot create doc on behalf of another user (VDU)", async () => {
      const local = trackLocal("push-spoof-creator");
      const remote = trackRemote(remoteWithJwt(bobJwt));
      const id = `spoof-${suiteId}`;
      await local.put({ _id: id, creator: "alice", body: "nope" });
      try {
        const push = await local.replicate.to(remote);
        expect(push.docs_written).toBe(0);
      } catch {
        // ok
      }
      const remoteDoc = await getDoc(DB, id, authHeaders("jwt", aliceJwt));
      expect(remoteDoc.status).toBe(404);
    });

    it("pull receives deletion tombstones for previously readable docs", async () => {
      const id = `pouch-tomb-${suiteId}`;
      await putDoc(
        DB,
        id,
        { creator: "alice", acl: ["u-bob"], kind: "pouch-tomb", body: "temp" },
        authHeaders("jwt", aliceJwt),
      );
      await waitForReadable(DB, id, authHeaders("jwt", bobJwt));

      const local = trackLocal("pull-tomb");
      const remote = trackRemote(remoteWithJwt(bobJwt));
      await local.replicate.from(remote);
      expect(await local.get(id)).toMatchObject({ body: "temp" });

      const cur = await getDoc(DB, id, authHeaders("jwt", aliceJwt));
      const rev = ((await cur.json()) as { _rev: string })._rev;
      const del = await fetch(
        `${PROXY}/${DB}/${encodeURIComponent(id)}?rev=${encodeURIComponent(rev)}`,
        { method: "DELETE", headers: authHeaders("jwt", aliceJwt) },
      );
      expect(del.ok).toBe(true);

      await waitUntil(
        "pouch pull tombstone",
        async () => {
          await local.replicate.from(remote);
          try {
            await local.get(id);
            return false;
          } catch (err) {
            return (err as { status?: number }).status === 404;
          }
        },
        20_000,
      );
      await expect(local.get(id)).rejects.toMatchObject({ status: 404 });
    });
  });

  // ── Bidirectional + live sync ──────────────────────────────────────────

  describe("bidirectional and live sync", () => {
    it("sync() pulls allowed and pushes allowed only", async () => {
      const local = trackLocal("bidi");
      const remote = trackRemote(remoteWithJwt(bobJwt));
      const result = await local.sync(remote);
      expect(result.pull.ok).toBe(true);
      const have = await idsInLocal(local);
      expect(have.has(ids.bobReader)).toBe(true);
      expect(have.has(ids.alicePrivate)).toBe(false);

      const id = `bidi-new-${suiteId}`;
      await local.put({ _id: id, creator: "bob", body: "bidi" });
      const again = await local.sync(remote);
      expect(again.push.docs_written).toBeGreaterThanOrEqual(1);
      await waitForReadable(DB, id, authHeaders("jwt", bobJwt));
    });

    it("live sync delivers newly readable remote docs", async () => {
      const local = trackLocal("live");
      const remote = trackRemote(remoteWithJwt(bobJwt));
      await local.replicate.from(remote);

      const liveId = `live-${suiteId}`;
      let sawLive = false;
      const sync = local.sync(remote, { live: true, retry: false });
      const onChange = () => {
        void local
          .get(liveId)
          .then(() => {
            sawLive = true;
          })
          .catch(() => undefined);
      };
      sync.on("change", onChange);

      await putDoc(
        DB,
        liveId,
        { creator: "alice", acl: ["u-bob"], kind: "live", body: "ping" },
        authHeaders("jwt", aliceJwt),
      );
      await waitUntil(
        "live sync saw doc",
        async () => {
          try {
            await local.get(liveId);
            return true;
          } catch {
            return sawLive;
          }
        },
        20_000,
      );
      sync.cancel();
      expect(await local.get(liveId)).toMatchObject({ body: "ping" });
    });
  });

  // ── HTTP ACL matrix on sync-adjacent endpoints ─────────────────────────

  describe("sync-adjacent HTTP ACL surfaces", () => {
    it("_bulk_get filters unauthorized docs", async () => {
      const res = await fetch(`${PROXY}/${DB}/_bulk_get`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          docs: [{ id: ids.alicePrivate }, { id: ids.bobReader }, { id: ids.open }],
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        results: Array<{ id: string; docs: Array<{ ok?: unknown; error?: unknown }> }>;
      };
      const byId = Object.fromEntries(body.results.map((r) => [r.id, r.docs[0]]));
      expect(byId[ids.alicePrivate]?.error).toBeTruthy();
      expect(byId[ids.bobReader]?.ok).toBeTruthy();
      expect(byId[ids.open]?.ok).toBeTruthy();
    });

    it("_revs_diff omits unauthorized ids", async () => {
      const res = await fetch(`${PROXY}/${DB}/_revs_diff`, {
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
      const body = (await res.json()) as Record<string, unknown>;
      expect(body[ids.alicePrivate]).toBeUndefined();
      expect(body[ids.bobReader]).toBeDefined();
    });

    it("_changes normal feed matches pull visibility", async () => {
      const res = await fetch(`${PROXY}/${DB}/_changes?include_docs=true&limit=500`, {
        headers: authHeaders("jwt", daveJwt),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { results: Array<{ id: string }> };
      const changeIds = new Set(body.results.map((r) => r.id));
      expect(changeIds.has(ids.open)).toBe(true);
      expect(changeIds.has(ids.alicePrivate)).toBe(false);
      expect(changeIds.has(ids.bobReader)).toBe(false);
    });

    it("_all_docs and _find agree with pull ACL", async () => {
      const all = await fetch(`${PROXY}/${DB}/_all_docs`, {
        headers: authHeaders("jwt", bobJwt),
      });
      const allBody = (await all.json()) as { rows: Array<{ id: string }> };
      const allIds = new Set(allBody.rows.map((r) => r.id));
      expect(allIds.has(ids.bobReader)).toBe(true);
      expect(allIds.has(ids.alicePrivate)).toBe(false);

      await fetch(`${PROXY}/${DB}/_index`, {
        method: "POST",
        headers: { ...adminHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({
          index: { fields: ["kind"] },
          name: "kind-idx",
          type: "json",
        }),
      });
      const find = await fetch(`${PROXY}/${DB}/_find`, {
        method: "POST",
        headers: {
          ...authHeaders("jwt", bobJwt),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ selector: { kind: { $exists: true } }, limit: 100 }),
      });
      expect(find.status).toBe(200);
      const findBody = (await find.json()) as { docs: Array<{ _id: string }> };
      const findIds = new Set(findBody.docs.map((d) => d._id));
      expect(findIds.has(ids.bobReader)).toBe(true);
      expect(findIds.has(ids.alicePrivate)).toBe(false);
    });

    it("dbacl overlay grants extra read on pull", async () => {
      // Overlay: writers role can read everything
      const get = await fetch(`${PROXY}/${DB}/_design/acl`, { headers: adminHeaders() });
      expect(get.status).toBe(200);
      const ddoc = (await get.json()) as Record<string, unknown> & { _rev: string };
      const prevDbacl = ddoc.dbacl;
      ddoc.dbacl = { _r: ["r-writers"], _w: [], _d: [] };
      const put = await fetch(`${PROXY}/${DB}/_design/acl`, {
        method: "PUT",
        headers: { ...adminHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify(ddoc),
      });
      expect(put.ok).toBe(true);

      try {
        await waitForReadable(DB, ids.alicePrivate, authHeaders("jwt", bobJwt));
        const local = trackLocal("dbacl");
        const remote = trackRemote(remoteWithJwt(bobJwt));
        await local.replicate.from(remote);
        const have = await idsInLocal(local);
        expect(have.has(ids.alicePrivate)).toBe(true);
      } finally {
        const again = await fetch(`${PROXY}/${DB}/_design/acl`, { headers: adminHeaders() });
        const cur = (await again.json()) as Record<string, unknown>;
        if (prevDbacl === undefined) delete cur.dbacl;
        else cur.dbacl = prevDbacl;
        await fetch(`${PROXY}/${DB}/_design/acl`, {
          method: "PUT",
          headers: { ...adminHeaders(), "Content-Type": "application/json" },
          body: JSON.stringify(cur),
        });
      }
    });
  });
});
