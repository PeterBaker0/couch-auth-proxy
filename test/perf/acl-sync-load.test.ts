/**
 * ACL performance harness (docker compose stack).
 *
 * Simulates many concurrent PouchDB memory clients syncing through
 * couch-auth-proxy against a mixed ACL corpus, plus HTTP r/w ops.
 * Optionally compares the same HTTP workload against CouchDB directly
 * (`COUCH_DIRECT_URL`, default http://127.0.0.1:5985 with dev overlay).
 *
 * Primary success metric: ops/second (sync docs + HTTP r/w).
 *
 * Note: the proxy caches Couch `/_session` principals for
 * `SESSION_CACHE_TTL_MS` (default 5000). Direct Couch compares therefore mix
 * auth + ACL overhead, not ACL filtering alone. Set `SESSION_CACHE_TTL_MS=0`
 * on the proxy to force per-request session resolution.
 *
 * Prerequisites:
 *   docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
 *   pnpm test:perf
 *
 * Tunables (env):
 *   PERF_CLIENTS          concurrent syncing clients (default 8)
 *   PERF_SEED_DOCS        shared corpus size (default 400)
 *   PERF_ROUNDS           sync/write rounds per client (default 4)
 *   PERF_DOCS_PER_ROUND   new docs each client creates per round (default 10)
 *   PERF_HTTP_OPS         HTTP r/w ops per client in the HTTP phase (default 80)
 *   PERF_MIN_OPS_PER_SEC  soft floor for overall ops/sec (default 20)
 *   PERF_RESULTS_PATH     write JSON report (default test/perf/last-results.json)
 *   COUCH_DIRECT_URL      direct Couch for overhead compare (default http://127.0.0.1:5985)
 *
 * Profiling (optional — proxy must be started with PROFILE=true):
 *   docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.profile.yml up -d --build
 *   pnpm test:perf:profile
 * When available, each phase scrapes `/_couch-auth-proxy/profile` (auth/acl/aclMiss/upstream/filter).
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import PouchDB from "pouchdb";
import memoryAdapter from "pouchdb-adapter-memory";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  PROXY,
  adminHeaders,
  authHeaders,
  createUserIfMissing,
  ensureDbOpenForDemoUsers,
  mintJwt,
  sleep,
  waitForReady,
  waitUntil,
} from "../integration/helpers.js";
import {
  LatencyTracker,
  OpCounter,
  formatRate,
  rateReport,
  timed,
  type RateReport,
} from "./metrics.js";
import { measureServerProfile, profileEndpointAvailable, type ProfileSnapshot } from "./profile.js";

PouchDB.plugin(memoryAdapter);

type Principal = {
  name: string;
  pass: string;
  roles: string[];
  jwt: string;
};

type Doc = Record<string, unknown> & { _id: string; _rev?: string };

const suiteId = Date.now().toString(36);
const DB = `perfacl-${suiteId}`;

const CLIENTS = Math.max(1, Number(process.env.PERF_CLIENTS ?? 8));
const SEED_DOCS = Math.max(40, Number(process.env.PERF_SEED_DOCS ?? 400));
const ROUNDS = Math.max(1, Number(process.env.PERF_ROUNDS ?? 4));
const DOCS_PER_ROUND = Math.max(1, Number(process.env.PERF_DOCS_PER_ROUND ?? 10));
const HTTP_OPS = Math.max(10, Number(process.env.PERF_HTTP_OPS ?? 80));
const MIN_OPS_PER_SEC = Math.max(1, Number(process.env.PERF_MIN_OPS_PER_SEC ?? 20));
const DIRECT = process.env.COUCH_DIRECT_URL ?? "http://127.0.0.1:5985";
const RESULTS_PATH =
  process.env.PERF_RESULTS_PATH ??
  path.join(path.dirname(fileURLToPath(import.meta.url)), "last-results.json");

const principals: Principal[] = [];
const remotes: PouchDB.Database[] = [];
const locals: PouchDB.Database[] = [];
const reports: Record<string, RateReport | Record<string, unknown>> = {};
const profiles: Record<string, ProfileSnapshot> = {};
let profilingEnabled = false;

function memoryDb(name: string): PouchDB.Database {
  return new PouchDB(`mem-perf-${name}-${Math.random().toString(36).slice(2)}`, {
    adapter: "memory",
  });
}

function remoteWithJwt(baseUrl: string, db: string, jwt: string): PouchDB.Database {
  return new PouchDB(`${baseUrl}/${db}`, {
    skip_setup: true,
    fetch(url: string | Request, opts: RequestInit = {}) {
      const headers = new Headers(opts.headers);
      headers.set("Authorization", `Bearer ${jwt}`);
      return PouchDB.fetch(url, { ...opts, headers });
    },
  });
}

function trackLocal(name: string): PouchDB.Database {
  const db = memoryDb(name);
  locals.push(db);
  return db;
}

function trackRemote(db: PouchDB.Database): PouchDB.Database {
  remotes.push(db);
  return db;
}

function aclPattern(i: number, owner: Principal): Record<string, unknown> {
  // Mix that forces ACL filtering on every sync surface.
  switch (i % 5) {
    case 0:
      return { creator: owner.name, kind: "private" };
    case 1:
      return {
        creator: owner.name,
        acl: ["u-alice", "u-bob", "u-carol", "u-dave"].filter((u) => u !== `u-${owner.name}`),
        kind: "shared-readers",
      };
    case 2:
      return { creator: owner.name, acl: ["r-readers"], kind: "role-readers" };
    case 3:
      return { creator: owner.name, owners: ["u-bob", "u-carol"], kind: "owners" };
    default:
      return { kind: "open", body: "any-member" };
  }
}

async function seedCorpus(): Promise<string[]> {
  const ids: string[] = [];
  const batchSize = 50;
  for (let start = 0; start < SEED_DOCS; start += batchSize) {
    const end = Math.min(SEED_DOCS, start + batchSize);
    const docs = [];
    for (let i = start; i < end; i++) {
      const owner = principals[i % principals.length]!;
      const id = `seed-${suiteId}-${i}`;
      ids.push(id);
      docs.push({
        _id: id,
        ...aclPattern(i, owner),
        n: i,
        body: `seed-${i}`,
      });
    }
    // Use admin bulk for fast seed; ACL cache catches up via follower.
    const res = await fetch(`${PROXY}/${DB}/_bulk_docs`, {
      method: "POST",
      headers: { ...adminHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ docs }),
    });
    if (!res.ok) {
      throw new Error(`seed bulk: ${res.status} ${await res.text()}`);
    }
  }

  // Wait until a non-admin pull surface is ready for an open doc.
  const openId = ids.find((_, i) => i % 5 === 4) ?? ids[0]!;
  await waitUntil(
    `perf seed readable ${openId}`,
    async () => {
      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(openId)}`, {
        headers: authHeaders("jwt", principals[0]!.jwt),
      });
      return res.status === 200;
    },
    60_000,
  );
  return ids;
}

async function httpOp(
  baseUrl: string,
  principal: Principal,
  seedIds: string[],
  i: number,
  counter: OpCounter,
  latency: LatencyTracker,
): Promise<void> {
  const headers = {
    ...authHeaders("jwt", principal.jwt),
    "Content-Type": "application/json",
  };
  const write = i % 3 === 0;
  const { ms } = await timed(async () => {
    if (write) {
      const id = `http-${principal.name}-${suiteId}-${i}-${Math.random().toString(36).slice(2, 8)}`;
      const res = await fetch(`${baseUrl}/${DB}/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers,
        body: JSON.stringify({
          _id: id,
          creator: principal.name,
          kind: "http-write",
          body: `w-${i}`,
        }),
      });
      if (!res.ok) {
        counter.add({ ops: 1, errors: 1 });
        return;
      }
      counter.add({ ops: 1, docsWritten: 1 });
      return;
    }
    const id = seedIds[i % seedIds.length]!;
    const res = await fetch(`${baseUrl}/${DB}/${encodeURIComponent(id)}`, { headers });
    // 200 = allowed, 404 = ACL deny (still a completed ACL-challenging op)
    if (res.status === 200) counter.add({ ops: 1, docsRead: 1 });
    else if (res.status === 404) counter.add({ ops: 1 });
    else counter.add({ ops: 1, errors: 1 });
  });
  latency.record(ms);
}

async function runHttpPhase(
  baseUrl: string,
  seedIds: string[],
  label: string,
): Promise<RateReport> {
  const counter = new OpCounter();
  const latency = new LatencyTracker();
  const t0 = performance.now();
  await Promise.all(
    Array.from({ length: CLIENTS }, async (_, clientIdx) => {
      const p = principals[clientIdx % principals.length]!;
      for (let i = 0; i < HTTP_OPS; i++) {
        await httpOp(baseUrl, p, seedIds, clientIdx * HTTP_OPS + i, counter, latency);
      }
    }),
  );
  const report = rateReport(counter, latency, performance.now() - t0);
  console.log(`\n${formatRate(report, label)}\n`);
  return report;
}

async function runSyncPhase(): Promise<RateReport> {
  const counter = new OpCounter();
  const latency = new LatencyTracker();

  // Warm ACL path once so measured rounds are steady-state.
  {
    const warm = principals[0]!;
    const local = trackLocal("warmup");
    const remote = trackRemote(remoteWithJwt(PROXY, DB, warm.jwt));
    await local.replicate.from(remote);
  }

  const t0 = performance.now();
  // Reuse the demo principal set across CLIENTS workers (same ACL identities,
  // distinct Pouch local DBs) so concurrency scales with PERF_CLIENTS.
  await Promise.all(
    Array.from({ length: CLIENTS }, async (_, clientIdx) => {
      const principal = principals[clientIdx % principals.length]!;
      const local = trackLocal(`client-${clientIdx}`);
      const remote = trackRemote(remoteWithJwt(PROXY, DB, principal.jwt));

      for (let round = 0; round < ROUNDS; round++) {
        // Pull (ACL-filtered _changes / _bulk_get)
        {
          const { value, ms } = await timed(() => local.replicate.from(remote));
          latency.record(ms);
          if (!value.ok) counter.add({ ops: 1, errors: 1 });
          else {
            counter.add({
              ops: 1,
              docsRead: value.docs_read ?? value.docs_written ?? 0,
            });
          }
        }

        // Local creates + updates (push challenges write ACL / VDU)
        const createdIds: string[] = [];
        for (let d = 0; d < DOCS_PER_ROUND; d++) {
          const id = `c${clientIdx}-r${round}-d${d}-${suiteId}`;
          createdIds.push(id);
          await local.put({
            _id: id,
            creator: principal.name,
            acl: d % 2 === 0 ? ["r-readers"] : undefined,
            kind: "client-write",
            body: `round-${round}`,
            n: d,
          });
        }
        for (const id of createdIds.slice(0, 3)) {
          const doc = (await local.get(id)) as Doc;
          doc.body = `upd-${clientIdx}-${round}`;
          await local.put(doc);
        }

        // Push
        {
          const { value, ms } = await timed(() => local.replicate.to(remote));
          latency.record(ms);
          const failures = (value.doc_write_failures ?? 0) + (value.errors?.length ?? 0);
          if (!value.ok && failures > 0) counter.add({ ops: 1, errors: 1 });
          else {
            counter.add({
              ops: 1,
              docsWritten: value.docs_written ?? 0,
            });
          }
        }

        // Bidirectional sync round
        {
          const { value, ms } = await timed(() => local.sync(remote));
          latency.record(ms);
          const pullOk = value.pull?.ok !== false;
          const pushOk = value.push?.ok !== false;
          if (!pullOk || !pushOk) counter.add({ ops: 1, errors: 1 });
          else {
            counter.add({
              ops: 1,
              docsRead: value.pull?.docs_read ?? value.pull?.docs_written ?? 0,
              docsWritten: value.push?.docs_written ?? 0,
            });
          }
        }
      }
    }),
  );

  const report = rateReport(counter, latency, performance.now() - t0);
  console.log(`\n${formatRate(report, "proxy PouchDB sync load (ACL)")}\n`);
  return report;
}

async function runBulkGetPhase(seedIds: string[]): Promise<RateReport> {
  const counter = new OpCounter();
  const latency = new LatencyTracker();
  const chunk = 25;
  const t0 = performance.now();

  await Promise.all(
    Array.from({ length: CLIENTS }, async (_, clientIdx) => {
      const p = principals[clientIdx % principals.length]!;
      for (let offset = 0; offset < seedIds.length; offset += chunk) {
        const docs = seedIds.slice(offset, offset + chunk).map((id) => ({ id }));
        const { value, ms } = await timed(async () => {
          const res = await fetch(`${PROXY}/${DB}/_bulk_get`, {
            method: "POST",
            headers: {
              ...authHeaders("jwt", p.jwt),
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ docs }),
          });
          if (!res.ok) return { ok: false, readable: 0, total: docs.length };
          const body = (await res.json()) as {
            results: Array<{ docs: Array<{ ok?: unknown; error?: unknown }> }>;
          };
          const readable = body.results.filter((r) => r.docs[0]?.ok).length;
          return { ok: true, readable, total: docs.length };
        });
        latency.record(ms);
        if (!value.ok) counter.add({ ops: 1, errors: 1 });
        else counter.add({ ops: 1, docsRead: value.readable });
      }
    }),
  );

  const report = rateReport(counter, latency, performance.now() - t0);
  console.log(`\n${formatRate(report, "proxy _bulk_get ACL filter")}\n`);
  return report;
}

async function directCouchReachable(): Promise<boolean> {
  try {
    const res = await fetch(`${DIRECT}/_up`, { headers: adminHeaders() });
    return res.ok;
  } catch {
    return false;
  }
}

describe("ACL performance harness", () => {
  let seedIds: string[] = [];

  beforeAll(async () => {
    await waitForReady();
    const users = [
      { name: "alice", pass: "alice-pass", roles: ["readers"] },
      { name: "bob", pass: "bob-pass", roles: ["writers"] },
      { name: "carol", pass: "carol-pass", roles: ["readers"] },
      { name: "dave", pass: "dave-pass", roles: [] as string[] },
    ];
    for (const u of users) {
      await createUserIfMissing(u.name, u.pass, u.roles);
      principals.push({ ...u, jwt: await mintJwt(u.name, u.roles) });
    }
    await ensureDbOpenForDemoUsers(DB);
    // Ensure dave is a named member (helpers only open alice/bob/carol by default).
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
    seedIds = await seedCorpus();
    profilingEnabled = await profileEndpointAvailable();
    if (profilingEnabled) {
      console.log("\n(server PROFILE=true — will scrape phase timings per harness phase)\n");
    }
    // brief settle for ACL follower under large seed
    await sleep(500);
  }, 300_000);

  afterAll(async () => {
    await Promise.allSettled([...locals, ...remotes].map((db) => db.close()));
    const summary = {
      version: process.env.npm_package_version ?? "unknown",
      at: new Date().toISOString(),
      config: {
        clients: CLIENTS,
        seedDocs: SEED_DOCS,
        rounds: ROUNDS,
        docsPerRound: DOCS_PER_ROUND,
        httpOps: HTTP_OPS,
        proxy: PROXY,
        direct: DIRECT,
        db: DB,
        profiling: profilingEnabled,
      },
      reports,
      profiles: profilingEnabled ? profiles : undefined,
    };
    await mkdir(path.dirname(RESULTS_PATH), { recursive: true });
    await writeFile(RESULTS_PATH, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
    console.log(`\nWrote perf results → ${RESULTS_PATH}\n`);
    await fetch(`${PROXY}/${DB}`, { method: "DELETE", headers: adminHeaders() }).catch(
      () => undefined,
    );
  });

  it("measures concurrent PouchDB sync ops/sec under ACL", async () => {
    let sync!: RateReport;
    const snap = await measureServerProfile("server profile — PouchDB sync phase", async () => {
      sync = await runSyncPhase();
    });
    if (snap) profiles.sync = snap;
    reports.sync = sync;
    expect(sync.errorRate).toBeLessThan(0.05);
    expect(sync.opsPerSec).toBeGreaterThan(0);
    expect(sync.syncDocsPerSec).toBeGreaterThan(0);
  });

  it("measures HTTP r/w ops/sec through the proxy (ACL challenged)", async () => {
    let http!: RateReport;
    const snap = await measureServerProfile("server profile — HTTP r/w phase", async () => {
      http = await runHttpPhase(PROXY, seedIds, "proxy HTTP r/w (ACL)");
    });
    if (snap) profiles.httpProxy = snap;
    reports.httpProxy = http;
    expect(http.errorRate).toBeLessThan(0.05);
    expect(http.opsPerSec).toBeGreaterThan(MIN_OPS_PER_SEC);
  });

  it("measures _bulk_get ACL filtering throughput", async () => {
    let bulk!: RateReport;
    const snap = await measureServerProfile("server profile — _bulk_get phase", async () => {
      bulk = await runBulkGetPhase(seedIds);
    });
    if (snap) profiles.bulkGet = snap;
    reports.bulkGet = bulk;
    expect(bulk.errorRate).toBeLessThan(0.05);
    expect(bulk.opsPerSec).toBeGreaterThan(0);
  });

  it("compares proxy HTTP vs direct Couch when available", async () => {
    if (!(await directCouchReachable())) {
      reports.directCompare = {
        skipped: true,
        reason: `direct Couch not reachable at ${DIRECT}`,
      };
      console.log(`\n(skip direct compare: ${DIRECT} unreachable)\n`);
      return;
    }

    // Mirror DB on direct Couch is the same DB — clients talk past the proxy.
    const directHttp = await runHttpPhase(DIRECT, seedIds, "direct Couch HTTP r/w (no proxy ACL)");
    reports.httpDirect = directHttp;
    const proxyHttp = reports.httpProxy as RateReport;
    const ratio = proxyHttp.opsPerSec / Math.max(directHttp.opsPerSec, 1e-9);
    const compare = {
      proxyOpsPerSec: proxyHttp.opsPerSec,
      directOpsPerSec: directHttp.opsPerSec,
      proxyOverDirectRatio: ratio,
      overheadPct: (1 - ratio) * 100,
    };
    reports.directCompare = compare;
    console.log(
      [
        "=== proxy vs direct Couch (HTTP r/w) ===",
        `proxy_ops_per_sec:  ${compare.proxyOpsPerSec.toFixed(2)}`,
        `direct_ops_per_sec: ${compare.directOpsPerSec.toFixed(2)}`,
        `proxy/direct ratio: ${compare.proxyOverDirectRatio.toFixed(3)}`,
        `overhead_pct:       ${compare.overheadPct.toFixed(1)}%`,
        "",
      ].join("\n"),
    );

    // Soft signal only: ACL proxy should not collapse to a tiny fraction of Couch.
    // Hosts vary; require at least 15% of direct throughput as a fail-closed sanity check.
    expect(compare.proxyOverDirectRatio).toBeGreaterThan(0.15);
  });

  it("prints overall baseline summary", () => {
    const sync = reports.sync as RateReport;
    const http = reports.httpProxy as RateReport;
    const bulk = reports.bulkGet as RateReport;
    const overallOps = (sync?.ops ?? 0) + (http?.ops ?? 0) + (bulk?.ops ?? 0);
    const overallSec =
      (sync?.durationSec ?? 0) + (http?.durationSec ?? 0) + (bulk?.durationSec ?? 0);
    const overallOpsPerSec = overallOps / Math.max(overallSec, 1e-9);
    const syncDocs =
      (sync?.docsRead ?? 0) +
      (sync?.docsWritten ?? 0) +
      (http?.docsRead ?? 0) +
      (http?.docsWritten ?? 0) +
      (bulk?.docsRead ?? 0);
    const summary = {
      overallOps,
      overallSec,
      overallOpsPerSec,
      syncDocsPerSec: syncDocs / Math.max(overallSec, 1e-9),
      phases: {
        syncOpsPerSec: sync?.opsPerSec,
        syncDocsPerSec: sync?.syncDocsPerSec,
        httpOpsPerSec: http?.opsPerSec,
        bulkGetOpsPerSec: bulk?.opsPerSec,
      },
    };
    reports.overall = summary;
    console.log(
      [
        "=== BASELINE SUMMARY ===",
        `clients=${CLIENTS} seed_docs=${SEED_DOCS} rounds=${ROUNDS} docs_per_round=${DOCS_PER_ROUND} http_ops=${HTTP_OPS}`,
        `overall_ops_per_sec: ${summary.overallOpsPerSec.toFixed(2)}`,
        `sync_docs_per_sec:   ${summary.syncDocsPerSec.toFixed(2)}`,
        `sync_phase_ops/s:    ${(summary.phases.syncOpsPerSec ?? 0).toFixed(2)}`,
        `http_phase_ops/s:    ${(summary.phases.httpOpsPerSec ?? 0).toFixed(2)}`,
        `bulk_get_ops/s:      ${(summary.phases.bulkGetOpsPerSec ?? 0).toFixed(2)}`,
        "",
      ].join("\n"),
    );
    expect(summary.overallOpsPerSec).toBeGreaterThan(MIN_OPS_PER_SEC);
  });
});
