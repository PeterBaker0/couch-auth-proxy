/**
 * Shared helpers for couch-auth-proxy docker integration tests.
 *
 * Talks to a running couch-auth-proxy + CouchDB compose stack (`COUCH_AUTH_PROXY_URL`).
 * Provides JWT minting, readiness waits, CRUD helpers, and demo DB/user setup
 * used by `acl.test.ts` and `pouch-sync.test.ts`.
 */
import { SignJWT } from "jose";

/** Base URL of the proxy under test. */
export const PROXY = process.env.COUCH_AUTH_PROXY_URL ?? "http://127.0.0.1:8000";
/** HS256 secret — must match Couch `[jwt_keys]` in the compose stack. */
export const SECRET = process.env.JWT_HMAC_SECRET ?? "couch-auth-proxy-dev-secret";
export const ADMIN_USER = process.env.COUCH_ADMIN_USER ?? "admin";
export const ADMIN_PASS = process.env.COUCH_ADMIN_PASSWORD ?? "password";

/** Mint a Couch-compatible JWT (`sub` + `_couchdb.roles`). */
export async function mintJwt(
  sub: string,
  roles: string[] = [],
  expiresIn = "1h",
): Promise<string> {
  const key = new TextEncoder().encode(SECRET);
  return new SignJWT({ "_couchdb.roles": roles })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(sub)
    .setExpirationTime(expiresIn)
    .sign(key);
}

/** Poll `/_couch-auth-proxy/ready` until 200 or timeout. */
export async function waitForReady(timeoutMs = 120_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${PROXY}/_couch-auth-proxy/ready`);
      if (res.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`couch-auth-proxy not ready at ${PROXY}`);
}

/** Build Authorization headers for JWT Bearer or HTTP Basic. */
export function authHeaders(
  kind: "jwt" | "basic",
  tokenOrUser: string,
  pass?: string,
): Record<string, string> {
  if (kind === "jwt") return { Authorization: `Bearer ${tokenOrUser}` };
  const b64 = Buffer.from(`${tokenOrUser}:${pass}`).toString("base64");
  return { Authorization: `Basic ${b64}` };
}

/** Admin Basic-auth headers for privileged setup operations. */
export function adminHeaders(): Record<string, string> {
  return authHeaders("basic", ADMIN_USER, ADMIN_PASS);
}

export async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

/** PUT a document (merges `_id` into the body). */
export async function putDoc(
  db: string,
  id: string,
  doc: Record<string, unknown>,
  headers: Record<string, string>,
): Promise<Response> {
  return fetch(`${PROXY}/${db}/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ _id: id, ...doc }),
  });
}

export async function getDoc(
  db: string,
  id: string,
  headers: Record<string, string>,
): Promise<Response> {
  return fetch(`${PROXY}/${db}/${encodeURIComponent(id)}`, { headers });
}

export async function deleteDoc(
  db: string,
  id: string,
  rev: string,
  headers: Record<string, string>,
): Promise<Response> {
  return fetch(`${PROXY}/${db}/${encodeURIComponent(id)}?rev=${encodeURIComponent(rev)}`, {
    method: "DELETE",
    headers,
  });
}

/**
 * Poll until `pred` returns true (ACL follower / view lag).
 * Throws with `label` on timeout for clearer test failures.
 */
export async function waitUntil(
  label: string,
  pred: () => Promise<boolean>,
  timeoutMs = 15_000,
  intervalMs = 200,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await pred()) return;
    await sleep(intervalMs);
  }
  throw new Error(`timeout waiting for: ${label}`);
}

/** Wait until GET returns 200 for the given doc (ACL cache caught up). */
export async function waitForReadable(
  db: string,
  id: string,
  headers: Record<string, string>,
): Promise<void> {
  await waitUntil(`readable ${db}/${id}`, async () => {
    const res = await getDoc(db, id, headers);
    return res.status === 200;
  });
}

/**
 * Create `db` if needed, open `_security` for demo users/roles, and wait until
 * couch-auth-proxy reports the ACL cache ready for that DB.
 */
export async function ensureDbOpenForDemoUsers(db: string): Promise<void> {
  const h = adminHeaders();
  const create = await fetch(`${PROXY}/${db}`, { method: "PUT", headers: h });
  if (![201, 202, 412].includes(create.status)) {
    throw new Error(`create db ${db}: ${create.status} ${await create.text()}`);
  }
  const sec = await fetch(`${PROXY}/${db}/_security`, {
    method: "PUT",
    headers: { ...h, "Content-Type": "application/json" },
    body: JSON.stringify({
      admins: { names: [], roles: ["_admin"] },
      members: {
        names: ["alice", "bob", "carol"],
        roles: ["readers", "writers"],
      },
    }),
  });
  if (!sec.ok) {
    throw new Error(`_security ${db}: ${sec.status} ${await sec.text()}`);
  }
  // Touch until ACL cache + changes follower are up.
  // First hits may 503 while the follower connects (followerUp stays false until onUp).
  await waitUntil(
    `acl ready ${db}`,
    async () => {
      const touch = await fetch(`${PROXY}/${db}`, { headers: h });
      return touch.ok;
    },
    30_000,
  );
}

/** Create a `_users` doc if missing (idempotent). */
export async function createUserIfMissing(
  name: string,
  password: string,
  roles: string[],
): Promise<void> {
  const id = `org.couchdb.user:${name}`;
  const h = adminHeaders();
  const existing = await fetch(`${PROXY}/_users/${encodeURIComponent(id)}`, { headers: h });
  if (existing.status === 200) return;
  const res = await fetch(`${PROXY}/_users/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { ...h, "Content-Type": "application/json" },
    body: JSON.stringify({ name, password, roles, type: "user" }),
  });
  if (![201, 409].includes(res.status)) {
    throw new Error(`create user ${name}: ${res.status} ${await res.text()}`);
  }
}

/** Ensure dave is a named member of `db` (for authenticated-but-unprivileged tests). */
export async function ensureDaveMembership(db: string): Promise<void> {
  await createUserIfMissing("dave", "dave-pass", []);
  const secRes = await fetch(`${PROXY}/${db}/_security`, { headers: adminHeaders() });
  const sec = (await secRes.json()) as {
    admins: unknown;
    members: { names: string[]; roles: string[] };
  };
  if (!sec.members.names.includes("dave")) {
    sec.members.names.push("dave");
    const put = await fetch(`${PROXY}/${db}/_security`, {
      method: "PUT",
      headers: { ...adminHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(sec),
    });
    if (!put.ok) {
      throw new Error(`_security dave ${db}: ${put.status} ${await put.text()}`);
    }
  }
}

/** PUT a standalone attachment on an existing doc (rev required). */
export async function putAttachment(
  db: string,
  id: string,
  name: string,
  rev: string,
  body: BodyInit,
  contentType: string,
  headers: Record<string, string>,
): Promise<Response> {
  return fetch(
    `${PROXY}/${db}/${encodeURIComponent(id)}/${encodeURIComponent(name)}?rev=${encodeURIComponent(rev)}`,
    {
      method: "PUT",
      headers: { "Content-Type": contentType, ...headers },
      body,
    },
  );
}

export async function getAttachment(
  db: string,
  id: string,
  name: string,
  headers: Record<string, string>,
  init?: RequestInit,
): Promise<Response> {
  return fetch(`${PROXY}/${db}/${encodeURIComponent(id)}/${encodeURIComponent(name)}`, {
    ...init,
    headers: { ...headers, ...(init?.headers as Record<string, string> | undefined) },
  });
}

/** Read continuous/eventsource `_changes` lines until timeout or `maxLines`. */
export async function collectChangesFeed(
  url: string,
  headers: Record<string, string>,
  timeoutMs = 2500,
  maxLines = 40,
): Promise<Array<Record<string, unknown>>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const seen: Array<Record<string, unknown>> = [];
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    if (!res.ok || !res.body) {
      throw new Error(`changes feed ${res.status}`);
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    try {
      while (seen.length < maxLines) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line || line.startsWith(":")) continue;
          const payload = line.startsWith("data:") ? line.slice(5).trim() : line;
          if (!payload) continue;
          try {
            seen.push(JSON.parse(payload) as Record<string, unknown>);
          } catch {
            // heartbeat / partial
          }
          if (seen.length >= maxLines) break;
        }
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") throw err;
    } finally {
      await reader.cancel().catch(() => {});
    }
  } finally {
    clearTimeout(timer);
  }
  return seen;
}
