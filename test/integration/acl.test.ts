/**
 * End-to-end ACL + auth integration against docker compose.
 *
 * Prerequisites: docker compose up -d --build && pnpm test:integration
 */
import { SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

const PROXY = process.env.COUCH_AUTH_PROXY_URL ?? "http://127.0.0.1:8000";
const SECRET = process.env.JWT_HMAC_SECRET ?? "couch-auth-proxy-dev-secret";
const DB = "acldemo";

async function mintJwt(sub: string, roles: string[] = [], expiresIn = "1h") {
  const key = new TextEncoder().encode(SECRET);
  return new SignJWT({ "_couchdb.roles": roles })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(sub)
    .setExpirationTime(expiresIn)
    .sign(key);
}

async function waitForReady(timeoutMs = 120_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${PROXY}/_couch-auth-proxy/ready`);
      if (res.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`couch-auth-proxy not ready at ${PROXY}`);
}

function authHeaders(kind: "jwt" | "basic", tokenOrUser: string, pass?: string): HeadersInit {
  if (kind === "jwt") return { Authorization: `Bearer ${tokenOrUser}` };
  const b64 = Buffer.from(`${tokenOrUser}:${pass}`).toString("base64");
  return { Authorization: `Basic ${b64}` };
}

async function putDoc(
  id: string,
  doc: Record<string, unknown>,
  headers: HeadersInit,
): Promise<Response> {
  return fetch(`${PROXY}/${DB}/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ _id: id, ...doc }),
  });
}

async function getDoc(id: string, headers: HeadersInit): Promise<Response> {
  return fetch(`${PROXY}/${DB}/${encodeURIComponent(id)}`, { headers });
}

describe("integration ACL", () => {
  const suffix = Date.now().toString(36);
  const docId = `msg-${suffix}`;
  const childId = `comment-${suffix}`;
  let aliceJwt: string;
  let bobJwt: string;
  let carolJwt: string;

  beforeAll(async () => {
    await waitForReady();
    aliceJwt = await mintJwt("alice", ["readers"]);
    bobJwt = await mintJwt("bob", ["writers"]);
    carolJwt = await mintJwt("carol", ["readers"]);
  });

  it("JWT with empty roles claim authenticates with no role ACL grants", async () => {
    // Couch requires the roles claim key when roles_claim_path is configured;
    // an empty array means authenticated but no r-role tokens.
    const key = new TextEncoder().encode(SECRET);
    const noRoles = await new SignJWT({ "_couchdb.roles": [] })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject("noroles")
      .setExpirationTime("1h")
      .sign(key);
    const res = await fetch(`${PROXY}/_session`, {
      headers: { Authorization: `Bearer ${noRoles}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.userCtx.name).toBe("noroles");
    expect(body.userCtx.roles).toEqual([]);
  });

  it("cookie auth: POST /_session then read", async () => {
    const login = await fetch(`${PROXY}/_session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "alice", password: "alice-pass" }),
    });
    expect(login.status).toBe(200);
    const cookie = login.headers.getSetCookie?.()?.[0] ?? login.headers.get("set-cookie");
    expect(cookie).toBeTruthy();
    const openId = `open-${suffix}`;
    const put = await putDoc(
      openId,
      { creator: "alice", body: "hi" },
      authHeaders("jwt", aliceJwt),
    );
    expect(put.status).toBeGreaterThanOrEqual(200);
    expect(put.status).toBeLessThan(300);

    // wait briefly for ACL cache follower
    await new Promise((r) => setTimeout(r, 500));
    const read = await getDoc(openId, { Cookie: cookie!.split(";")[0]! });
    expect(read.status).toBe(200);
  });

  it("Basic auth works for alice", async () => {
    const res = await fetch(`${PROXY}/_session`, {
      headers: authHeaders("basic", "alice", "alice-pass"),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.userCtx.name).toBe("alice");
  });

  it("doc ACL: alice creates, bob reads, carol 404, bob cannot delete", async () => {
    const put = await putDoc(
      docId,
      { creator: "alice", acl: ["u-bob"], body: "fence?" },
      authHeaders("jwt", aliceJwt),
    );
    expect(put.ok).toBe(true);

    // Allow changes follower / view update
    for (let i = 0; i < 20; i++) {
      const bobRead = await getDoc(docId, authHeaders("jwt", bobJwt));
      if (bobRead.status === 200) break;
      await new Promise((r) => setTimeout(r, 250));
    }

    const bobRead = await getDoc(docId, authHeaders("jwt", bobJwt));
    expect(bobRead.status).toBe(200);

    const carolRead = await getDoc(docId, authHeaders("jwt", carolJwt));
    expect(carolRead.status).toBe(404);

    const bobDel = await fetch(`${PROXY}/${DB}/${docId}`, {
      method: "DELETE",
      headers: {
        ...authHeaders("jwt", bobJwt),
        "If-Match": (await bobRead.json())._rev,
      },
    });
    expect(bobDel.status).toBe(403);

    const aliceDoc = await getDoc(docId, authHeaders("jwt", aliceJwt));
    const rev = (await aliceDoc.json())._rev;
    const aliceDel = await fetch(`${PROXY}/${DB}/${docId}`, {
      method: "DELETE",
      headers: { ...authHeaders("jwt", aliceJwt), "If-Match": rev },
    });
    // recreate for later tests — deletion proves creator can delete
    expect(aliceDel.ok).toBe(true);

    // recreate
    await putDoc(
      docId,
      { creator: "alice", acl: ["u-bob"], body: "fence?" },
      authHeaders("jwt", aliceJwt),
    );
    await new Promise((r) => setTimeout(r, 500));
  });

  it("parent inherit: child readable via parent acl", async () => {
    await putDoc(
      docId,
      { creator: "alice", acl: ["u-bob"], body: "parent" },
      authHeaders("jwt", aliceJwt),
    );
    await putDoc(
      childId,
      { creator: "alice", parent: docId, body: "child" },
      authHeaders("jwt", aliceJwt),
    );
    await new Promise((r) => setTimeout(r, 800));
    const bobChild = await getDoc(childId, authHeaders("jwt", bobJwt));
    expect(bobChild.status).toBe(200);
    const carolChild = await getDoc(childId, authHeaders("jwt", carolJwt));
    expect(carolChild.status).toBe(404);
  });

  it("_all_docs strips unauthorized docs", async () => {
    await new Promise((r) => setTimeout(r, 500));
    const res = await fetch(`${PROXY}/${DB}/_all_docs?include_docs=true`, {
      headers: authHeaders("jwt", bobJwt),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const ids = (body.rows as Array<{ id: string }>).map((r) => r.id);
    expect(ids).toContain(docId);
    // carol-only docs shouldn't appear; ensure alice-private without bob acl not listed
    // (we didn't create one exclusive — just check carol's perspective)
    const carolRes = await fetch(`${PROXY}/${DB}/_all_docs`, {
      headers: authHeaders("jwt", carolJwt),
    });
    const carolBody = await carolRes.json();
    const carolIds = (carolBody.rows as Array<{ id: string }>).map((r) => r.id);
    expect(carolIds).not.toContain(docId);
  });

  it("_find filters mango results", async () => {
    // ensure mango index exists (admin via direct path through couch-auth-proxy)
    const admin = Buffer.from("admin:password").toString("base64");
    await fetch(`${PROXY}/${DB}/_index`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        index: { fields: ["body"] },
        name: "body-idx",
        type: "json",
      }),
    });

    const res = await fetch(`${PROXY}/${DB}/_find`, {
      method: "POST",
      headers: {
        ...authHeaders("jwt", bobJwt),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ selector: { body: { $exists: true } }, limit: 50 }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const ids = (body.docs as Array<{ _id: string }>).map((d) => d._id);
    expect(ids).toContain(docId);
    for (const id of ids) {
      // bob should be able to GET each returned doc
      const g = await getDoc(id, authHeaders("jwt", bobJwt));
      expect(g.status).toBe(200);
    }
  });

  it("_changes normal feed omits unread docs", async () => {
    const res = await fetch(`${PROXY}/${DB}/_changes?include_docs=true&limit=100`, {
      headers: authHeaders("jwt", carolJwt),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const ids = (body.results as Array<{ id: string }>).map((r) => r.id);
    expect(ids).not.toContain(docId);
    // seq is opaque string in Couch 3
    if (body.last_seq != null) {
      expect(typeof body.last_seq === "string" || typeof body.last_seq === "number").toBe(true);
    }
  });

  it("_bulk_docs strips unauthorized updates", async () => {
    const res = await fetch(`${PROXY}/${DB}/_bulk_docs`, {
      method: "POST",
      headers: {
        ...authHeaders("jwt", bobJwt),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        docs: [
          { _id: docId, creator: "alice", acl: ["u-bob"], body: "hacked" },
          { creator: "bob", body: "bob-new" },
        ],
      }),
    });
    expect(res.status).toBeGreaterThanOrEqual(200);
    const body = await res.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body.some((r: { error?: string }) => r.error === "forbidden")).toBe(true);
  });

  it("rejects forged X-Auth-CouchDB-* headers for non-admin elevation", async () => {
    const res = await getDoc(docId, {
      ...authHeaders("jwt", carolJwt),
      "X-Auth-CouchDB-Username": "admin",
      "X-Auth-CouchDB-Roles": "_admin",
    });
    expect(res.status).toBe(404);
  });

  it("admin-only routes forbidden for alice", async () => {
    const res = await fetch(`${PROXY}/_node/_local/_config`, {
      headers: authHeaders("jwt", aliceJwt),
    });
    expect(res.status).toBe(403);
  });

  it("_list returns 501", async () => {
    const res = await fetch(`${PROXY}/${DB}/_design/acl/_list/x/acl`, {
      headers: authHeaders("jwt", aliceJwt),
    });
    expect(res.status).toBe(501);
  });

  it("default-denies unmapped DB endpoints for non-admins", async () => {
    const res = await fetch(`${PROXY}/${DB}/_purged_infos_limit`, {
      headers: authHeaders("jwt", aliceJwt),
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe("not_found");
  });

  it("COPY requires source read and destination write", async () => {
    const src = `copy-src-${suffix}`;
    const dst = `copy-dst-${suffix}`;
    await putDoc(
      src,
      { creator: "alice", acl: ["u-bob"], body: "copy-me" },
      authHeaders("jwt", aliceJwt),
    );
    await new Promise((r) => setTimeout(r, 500));

    const denied = await fetch(`${PROXY}/${DB}/${src}`, {
      method: "COPY",
      headers: {
        ...authHeaders("jwt", carolJwt),
        Destination: dst,
      },
    });
    expect(denied.status).toBe(404);

    const ok = await fetch(`${PROXY}/${DB}/${src}`, {
      method: "COPY",
      headers: {
        ...authHeaders("jwt", aliceJwt),
        Destination: dst,
      },
    });
    expect(ok.ok).toBe(true);
    await new Promise((r) => setTimeout(r, 500));
    const bobDst = await getDoc(dst, authHeaders("jwt", bobJwt));
    expect(bobDst.status).toBe(200);
  });

  it("view rows strip unauthorized docs", async () => {
    const res = await fetch(`${PROXY}/${DB}/_design/acl/_view/acl?limit=50`, {
      headers: authHeaders("jwt", carolJwt),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const ids = (body.rows as Array<{ id?: string; key?: string }>).map((r) => r.id ?? r.key);
    expect(ids).not.toContain(docId);
  });

  it("continuous _changes omits unread docs", async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const seen: string[] = [];
    try {
      const res = await fetch(
        `${PROXY}/${DB}/_changes?feed=continuous&heartbeat=500&since=0&include_docs=true`,
        {
          headers: authHeaders("jwt", carolJwt),
          signal: controller.signal,
        },
      );
      expect(res.status).toBe(200);
      expect(res.body).toBeTruthy();
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let nl: number;
          while ((nl = buf.indexOf("\n")) >= 0) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line) continue;
            try {
              const obj = JSON.parse(line) as { id?: string };
              if (obj.id) seen.push(obj.id);
            } catch {
              // heartbeat / partial
            }
          }
          if (seen.length >= 20) break;
        }
      } catch (err) {
        if ((err as Error).name !== "AbortError") throw err;
      } finally {
        await reader.cancel().catch(() => {});
      }
    } finally {
      clearTimeout(timer);
    }
    expect(seen).not.toContain(docId);
  });
});
