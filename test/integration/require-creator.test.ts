/**
 * Integration tests for ACL_REQUIRE_CREATOR.
 *
 * Default compose proxy keeps the flag off (historical create semantics).
 * A second proxy container with ACL_REQUIRE_CREATOR=true exercises the
 * require-creator VDU against a dedicated DB so acldemo stays untouched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  ACL_DDOC_VERSION_DEFAULT,
  ACL_DDOC_VERSION_REQUIRE_CREATOR,
  REQUIRE_CREATOR_FORBIDDEN,
} from "../../src/acl/ddoc.js";
import {
  ADMIN_PASS,
  ADMIN_USER,
  PROXY,
  authHeaders,
  ensureDbOpenForDemoUsers,
  mintJwt,
  putDoc,
  waitForReady,
  waitUntil,
} from "./helpers.js";

const execFileAsync = promisify(execFile);

const REQUIRE_PROXY = process.env.COUCH_AUTH_REQUIRE_CREATOR_PROXY_URL ?? "http://127.0.0.1:8002";
const CONTAINER = `couch-auth-proxy-require-creator-${process.pid}`;
const DB = `reqcreator-${process.pid}`;

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
  throw new Error(`require-creator proxy not ready at ${url}`);
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

async function readAclDdoc(proxyBase: string): Promise<{
  version?: string;
  validate_doc_update?: string;
}> {
  const res = await fetch(`${proxyBase}/${DB}/_design/acl`, {
    headers: authHeaders("basic", ADMIN_USER, ADMIN_PASS),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { version?: string; validate_doc_update?: string };
}

describe("ACL_REQUIRE_CREATOR integration", () => {
  let aliceJwt: string;
  let bobJwt: string;
  let startedContainer = false;

  beforeAll(async () => {
    await waitForReady();
    aliceJwt = await mintJwt("alice", ["readers"]);
    bobJwt = await mintJwt("bob", ["writers"]);

    // Install historical (flag-off) ddoc via the default proxy first.
    await ensureDbOpenForDemoUsers(DB);
    const before = await readAclDdoc(PROXY);
    expect(before.version).toBe(ACL_DDOC_VERSION_DEFAULT);
    expect(before.validate_doc_update ?? "").not.toContain(REQUIRE_CREATOR_FORBIDDEN);

    const network = await resolveComposeNetwork();
    const proxyId = await proxyContainerId();
    const { stdout: imageOut } = await docker(["inspect", "-f", "{{.Config.Image}}", proxyId]);
    const image = imageOut.trim();

    await docker(["rm", "-f", CONTAINER]).catch(() => undefined);

    await docker([
      "run",
      "-d",
      "--name",
      CONTAINER,
      "--network",
      network,
      "-p",
      "8002:8000",
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
      "ACL_REQUIRE_CREATOR=true",
      image,
    ]);
    startedContainer = true;
    await waitForUrlReady(REQUIRE_PROXY);

    // Touch DB so ensure/migrate upgrades the VDU for require-creator.
    const admin = authHeaders("basic", ADMIN_USER, ADMIN_PASS);
    await waitUntil(
      `require-creator proxy acl ready ${DB}`,
      async () => {
        const touch = await fetch(`${REQUIRE_PROXY}/${DB}`, { headers: admin });
        return touch.ok;
      },
      60_000,
    );

    await waitUntil(
      "ddoc upgraded to require-creator",
      async () => {
        const ddoc = await readAclDdoc(REQUIRE_PROXY);
        return (
          ddoc.version === ACL_DDOC_VERSION_REQUIRE_CREATOR &&
          (ddoc.validate_doc_update ?? "").includes(REQUIRE_CREATOR_FORBIDDEN)
        );
      },
      30_000,
    );
  }, 180_000);

  afterAll(async () => {
    if (startedContainer) {
      await docker(["rm", "-f", CONTAINER]).catch(() => undefined);
    }
    // Best-effort cleanup of the dedicated DB.
    await fetch(`${PROXY}/${DB}`, {
      method: "DELETE",
      headers: authHeaders("basic", ADMIN_USER, ADMIN_PASS),
    }).catch(() => undefined);
  });

  it("flag off (default proxy): unstamped create still allowed on acldemo", async () => {
    const id = `open-default-${Date.now()}`;
    const res = await putDoc(
      "acldemo",
      id,
      { body: "intentionally open" },
      authHeaders("jwt", bobJwt),
    );
    expect(res.status).toBe(201);
  });

  it("flag on: create without creator is forbidden", async () => {
    const id = `no-creator-${Date.now()}`;
    const res = await fetch(`${REQUIRE_PROXY}/${DB}/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders("jwt", bobJwt),
      },
      body: JSON.stringify({ _id: id, body: "hole" }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { reason?: string; error?: string };
    expect(body.error).toBe("forbidden");
    expect(body.reason).toContain(REQUIRE_CREATOR_FORBIDDEN);
  });

  it("flag on: create with own creator succeeds", async () => {
    const id = `own-creator-${Date.now()}`;
    const res = await fetch(`${REQUIRE_PROXY}/${DB}/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders("jwt", aliceJwt),
      },
      body: JSON.stringify({ _id: id, creator: "alice", body: "private" }),
    });
    expect(res.status).toBe(201);
  });

  it("flag on: forging creator is still forbidden", async () => {
    const id = `forge-${Date.now()}`;
    const res = await fetch(`${REQUIRE_PROXY}/${DB}/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders("jwt", bobJwt),
      },
      body: JSON.stringify({ _id: id, creator: "alice", body: "spoof" }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { reason?: string };
    expect(body.reason).toMatch(/behalf of other user/i);
  });

  it("flag on: admin may still create unstamped docs", async () => {
    const id = `admin-open-${Date.now()}`;
    const res = await fetch(`${REQUIRE_PROXY}/${DB}/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders("basic", ADMIN_USER, ADMIN_PASS),
      },
      body: JSON.stringify({ _id: id, body: "admin hole" }),
    });
    expect(res.status).toBe(201);
  });
});
