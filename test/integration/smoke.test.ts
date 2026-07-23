/**
 * Integration smoke tests against docker compose stack.
 *
 * Prerequisites:
 *   docker compose up -d --build
 *   pnpm test:integration
 *
 * Env:
 *   COUCH_AUTH_PROXY_URL (default http://127.0.0.1:8000)
 *   COUCH_URL (default http://127.0.0.1:5984)
 *   JWT_HMAC_SECRET (default couch-auth-proxy-dev-secret)
 */
import { SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

const PROXY = process.env.COUCH_AUTH_PROXY_URL ?? "http://127.0.0.1:8000";
const SECRET = process.env.JWT_HMAC_SECRET ?? "couch-auth-proxy-dev-secret";

async function mintJwt(sub: string, roles: string[] = [], expiresIn = "1h") {
  const key = new TextEncoder().encode(SECRET);
  return new SignJWT({ "_couchdb.roles": roles })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(sub)
    .setExpirationTime(expiresIn)
    .sign(key);
}

async function waitForHealth(timeoutMs = 90_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${PROXY}/_couch-auth-proxy/health`);
      if (res.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`couch-auth-proxy health not ready at ${PROXY}`);
}

describe("integration smoke", () => {
  beforeAll(async () => {
    await waitForHealth();
  });

  it("reports health", async () => {
    const res = await fetch(`${PROXY}/_couch-auth-proxy/health`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
  });

  it("authenticates JWT via Couch parity (Bearer → /_session)", async () => {
    const token = await mintJwt("alice", ["readers"]);
    const res = await fetch(`${PROXY}/_session`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.userCtx.name).toBe("alice");
    expect(body.info.authenticated).toBe("jwt");
    expect(body.userCtx.roles).toEqual(expect.arrayContaining(["readers"]));
  });

  it("rejects expired JWT", async () => {
    const token = await mintJwt("alice", ["readers"], "0s");
    // tiny delay so exp is in the past
    await new Promise((r) => setTimeout(r, 50));
    const res = await fetch(`${PROXY}/_session`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});
