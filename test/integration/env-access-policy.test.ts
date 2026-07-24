/**
 * Integration tests for env DB/route access policy.
 *
 * Spins a second couch-auth-proxy container on the compose network with
 * restrictive ACL_* lists, then exercises real CouchDB through that proxy.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { ADMIN_PASS, ADMIN_USER, authHeaders, mintJwt, PROXY, waitForReady } from "./helpers.js";

const execFileAsync = promisify(execFile);

const POLICY_PROXY = process.env.COUCH_AUTH_POLICY_PROXY_URL ?? "http://127.0.0.1:8001";
const CONTAINER = `couch-auth-proxy-policy-${process.pid}`;

async function docker(args: string[]): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync("docker", args, { maxBuffer: 10 * 1024 * 1024 });
}

async function waitForUrlReady(url: string, timeoutMs = 120_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${url}/_couch-auth-proxy/ready`);
      if (res.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`policy proxy not ready at ${url}`);
}

async function proxyContainerId(): Promise<string> {
  const { stdout } = await docker(["compose", "ps", "-q", "couch-auth-proxy"]);
  const id = stdout
    .trim()
    .split("\n")
    .map((s) => s.trim())
    .find(Boolean);
  if (!id) throw new Error("couch-auth-proxy container not running; start compose first");
  return id;
}

async function resolveComposeNetwork(): Promise<string> {
  const id = await proxyContainerId();
  const { stdout: nets } = await docker([
    "inspect",
    "-f",
    "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}",
    id,
  ]);
  const network = nets.trim();
  if (!network) throw new Error("could not resolve compose network for couch-auth-proxy");
  return network;
}

describe("env access policy integration", () => {
  let aliceJwt: string;
  let startedContainer = false;

  beforeAll(async () => {
    await waitForReady();
    aliceJwt = await mintJwt("alice", ["readers"]);

    // Create data-* DBs + a non-matching DB via the default (unrestricted) proxy as admin.
    const admin = authHeaders("basic", ADMIN_USER, ADMIN_PASS);
    for (const db of ["data-app", "data-other", "meta-internal"]) {
      const put = await fetch(`${PROXY}/${db}`, { method: "PUT", headers: admin });
      expect([201, 412]).toContain(put.status);
    }

    // Seed a readable doc for alice in data-app.
    const docRes = await fetch(`${PROXY}/data-app/note1`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...admin },
      body: JSON.stringify({ _id: "note1", type: "note", acl: ["r-readers"] }),
    });
    expect([201, 409]).toContain(docRes.status);

    const network = await resolveComposeNetwork();
    // Reuse image built by compose.
    const proxyId = await proxyContainerId();
    const { stdout: imageOut } = await docker(["inspect", "-f", "{{.Config.Image}}", proxyId]);
    const image = imageOut.trim();

    // Remove any leftover from a prior failed run.
    await docker(["rm", "-f", CONTAINER]).catch(() => undefined);

    await docker([
      "run",
      "-d",
      "--name",
      CONTAINER,
      "--network",
      network,
      "-p",
      "8001:8000",
      "-e",
      "HOST=0.0.0.0",
      "-e",
      "PORT=8000",
      "-e",
      "COUCH_URL=http://couchdb:5984",
      "-e",
      "COUCH_ADMIN_USER=admin",
      "-e",
      "COUCH_ADMIN_PASSWORD=password",
      "-e",
      "JWT_HMAC_SECRET=couch-auth-proxy-dev-secret",
      "-e",
      "AUTH_RESOLVE_VIA_COUCH_SESSION=true",
      "-e",
      "RATE_LIMIT_ENABLED=false",
      "-e",
      "ACL_DB_INCLUDE=/^data-/",
      "-e",
      "ACL_DB_EXCLUDE=data-other",
      "-e",
      "ACL_ROUTE_INCLUDE=pouch-sync",
      "-e",
      "ACL_ROUTE_EXCLUDE=admin",
      image,
    ]);
    startedContainer = true;
    await waitForUrlReady(POLICY_PROXY);
  }, 180_000);

  afterAll(async () => {
    if (startedContainer) {
      await docker(["rm", "-f", CONTAINER]).catch(() => undefined);
    }
  });

  it("hides non data-* databases and excluded data-other", async () => {
    const headers = authHeaders("jwt", aliceJwt);
    const list = await fetch(`${POLICY_PROXY}/_all_dbs`, { headers });
    expect(list.status).toBe(200);
    const dbs = (await list.json()) as string[];
    expect(dbs).toContain("data-app");
    expect(dbs).not.toContain("data-other");
    expect(dbs).not.toContain("meta-internal");
    expect(dbs).not.toContain("acldemo");
  });

  it("404s direct access to excluded / non-matching DBs", async () => {
    const headers = authHeaders("jwt", aliceJwt);
    expect((await fetch(`${POLICY_PROXY}/meta-internal`, { headers })).status).toBe(404);
    expect((await fetch(`${POLICY_PROXY}/data-other`, { headers })).status).toBe(404);
    expect((await fetch(`${POLICY_PROXY}/acldemo`, { headers })).status).toBe(404);
  });

  it("allows pouch-sync routes on included DBs", async () => {
    const headers = authHeaders("jwt", aliceJwt);
    const info = await fetch(`${POLICY_PROXY}/data-app`, { headers });
    expect(info.status).toBe(200);

    const doc = await fetch(`${POLICY_PROXY}/data-app/note1`, { headers });
    expect(doc.status).toBe(200);

    const changes = await fetch(`${POLICY_PROXY}/data-app/_changes?limit=1`, { headers });
    expect(changes.status).toBe(200);
  });

  it("blocks routes outside the pouch-sync include (e.g. Mango _find)", async () => {
    const headers = {
      "Content-Type": "application/json",
      ...authHeaders("jwt", aliceJwt),
    };
    const find = await fetch(`${POLICY_PROXY}/data-app/_find`, {
      method: "POST",
      headers,
      body: JSON.stringify({ selector: { type: "note" } }),
    });
    expect(find.status).toBe(403);
    expect(await find.json()).toEqual({
      error: "forbidden",
      reason: "Endpoint not allowed.",
    });
  });

  it("still allows session auth", async () => {
    const res = await fetch(`${POLICY_PROXY}/_session`, {
      headers: authHeaders("jwt", aliceJwt),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { userCtx?: { name?: string } };
    expect(body.userCtx?.name).toBe("alice");
  });

  it("lets admins bypass env route/DB policy", async () => {
    const headers = authHeaders("basic", ADMIN_USER, ADMIN_PASS);
    expect((await fetch(`${POLICY_PROXY}/acldemo`, { headers })).status).toBe(200);
    const find = await fetch(`${POLICY_PROXY}/data-app/_find`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify({ selector: { type: "note" } }),
    });
    // Admin bypasses route policy; Mango may still run through find actor.
    expect([200, 400, 404]).toContain(find.status);
    expect(find.status).not.toBe(403);
  });
});
