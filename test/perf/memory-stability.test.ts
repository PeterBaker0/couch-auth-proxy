/**
 * Long-running memory stability assessment (docker compose + PROFILE=true).
 *
 * Sustains ACL-challenging HTTP traffic against a fixed corpus while scraping
 * `/_couch-auth-proxy/profile` memory + resource counters. After a warmup
 * window, heap/rss trends are fit with linear regression and checked against
 * leak thresholds (ACL-row growth is budgeted as expected cache cost).
 *
 * Opt-in only — requires the profile overlay (or `PROFILE=true` on the proxy):
 *   pnpm test:perf:memory
 *
 * Tunables (env):
 *   PERF_MEMORY_DURATION_SEC   soak length (default 300)
 *   PERF_MEMORY_SAMPLE_MS      sample interval (default 2000)
 *   PERF_MEMORY_CLIENTS        concurrent workers (default 6)
 *   PERF_MEMORY_SEED_DOCS      fixed corpus size (default 300)
 *   PERF_MEMORY_WARMUP_FRAC    discarded leading fraction (default 0.25)
 *   PERF_MEMORY_FORCE_GC       POST /profile/gc each sample when available (default 1)
 *   PERF_MEMORY_RESULTS_PATH   JSON output (default test/perf/last-memory-results.json)
 *   PERF_MEMORY_REPORT_PATH    Markdown report (default test/perf/last-memory-report.md)
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
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
import { LatencyTracker, OpCounter, formatRate, rateReport, timed } from "./metrics.js";
import {
  DEFAULT_STABILITY_THRESHOLDS,
  analyzeMemoryTrend,
  formatTrendReport,
  memoryEndpointReady,
  requestServerGc,
  scrapeMemorySample,
  type MemorySample,
  type MemoryTrendReport,
  type StabilityThresholds,
} from "./memory.js";
import { resetServerProfile } from "./profile.js";

type Principal = {
  name: string;
  pass: string;
  roles: string[];
  jwt: string;
};

const suiteId = Date.now().toString(36);
const DB = `perfmem-${suiteId}`;

const DURATION_SEC = Math.max(30, Number(process.env.PERF_MEMORY_DURATION_SEC ?? 300));
const SAMPLE_MS = Math.max(250, Number(process.env.PERF_MEMORY_SAMPLE_MS ?? 2000));
const CLIENTS = Math.max(1, Number(process.env.PERF_MEMORY_CLIENTS ?? 6));
const SEED_DOCS = Math.max(40, Number(process.env.PERF_MEMORY_SEED_DOCS ?? 300));
const WARMUP_FRAC = Math.min(
  0.6,
  Math.max(0.05, Number(process.env.PERF_MEMORY_WARMUP_FRAC ?? 0.25)),
);
const FORCE_GC = !["0", "false", "no"].includes(
  String(process.env.PERF_MEMORY_FORCE_GC ?? "1").toLowerCase(),
);
const RESULTS_PATH =
  process.env.PERF_MEMORY_RESULTS_PATH ??
  path.join(path.dirname(fileURLToPath(import.meta.url)), "last-memory-results.json");
const REPORT_PATH =
  process.env.PERF_MEMORY_REPORT_PATH ??
  path.join(path.dirname(fileURLToPath(import.meta.url)), "last-memory-report.md");

const thresholds: StabilityThresholds = {
  ...DEFAULT_STABILITY_THRESHOLDS,
  warmupFraction: WARMUP_FRAC,
  maxHeapSlopeBytesPerSec: Number(
    process.env.PERF_MEMORY_MAX_HEAP_SLOPE_BPS ??
      DEFAULT_STABILITY_THRESHOLDS.maxHeapSlopeBytesPerSec,
  ),
  maxRssSlopeBytesPerSec: Number(
    process.env.PERF_MEMORY_MAX_RSS_SLOPE_BPS ??
      DEFAULT_STABILITY_THRESHOLDS.maxRssSlopeBytesPerSec,
  ),
  maxHeapThirdGrowthBytes: Number(
    process.env.PERF_MEMORY_MAX_HEAP_THIRD_GROWTH ??
      DEFAULT_STABILITY_THRESHOLDS.maxHeapThirdGrowthBytes,
  ),
};

const principals: Principal[] = [];
const samples: MemorySample[] = [];
let seedIds: string[] = [];
let trend: MemoryTrendReport | null = null;
let loadReport: ReturnType<typeof rateReport> | null = null;
let gcAvailable = false;

function aclPattern(i: number, owner: Principal): Record<string, unknown> {
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
      const id = `mem-seed-${suiteId}-${i}`;
      ids.push(id);
      docs.push({
        _id: id,
        ...aclPattern(i, owner),
        n: i,
        body: `seed-${i}`,
      });
    }
    const res = await fetch(`${PROXY}/${DB}/_bulk_docs`, {
      method: "POST",
      headers: { ...adminHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ docs }),
    });
    if (!res.ok) throw new Error(`seed bulk: ${res.status} ${await res.text()}`);
  }

  const openId = ids.find((_, i) => i % 5 === 4) ?? ids[0]!;
  await waitUntil(
    `mem seed readable ${openId}`,
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

/**
 * Steady-state op: mostly reads + in-place updates on the fixed corpus so ACL
 * row count plateaus. Occasional bounded creates keep write ACL warm without
 * unbounded cache growth (creates are capped by worker*loop modulo).
 */
async function steadyOp(
  principal: Principal,
  i: number,
  counter: OpCounter,
  latency: LatencyTracker,
): Promise<void> {
  const headers = {
    ...authHeaders("jwt", principal.jwt),
    "Content-Type": "application/json",
  };
  const mode = i % 5;
  const { ms } = await timed(async () => {
    if (mode === 0) {
      // Bounded create: overwrite a rotating slot id so ACL rows stay capped.
      const slot = i % Math.max(CLIENTS * 8, 16);
      const id = `mem-slot-${principal.name}-${suiteId}-${slot}`;
      const existing = await fetch(`${PROXY}/${DB}/${encodeURIComponent(id)}`, { headers });
      let rev: string | undefined;
      if (existing.status === 200) {
        rev = ((await existing.json()) as { _rev?: string })._rev;
      }
      const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers,
        body: JSON.stringify({
          _id: id,
          ...(rev ? { _rev: rev } : {}),
          creator: principal.name,
          kind: "slot-write",
          body: `slot-${i}`,
          n: i,
        }),
      });
      if (!res.ok) counter.add({ ops: 1, errors: 1 });
      else counter.add({ ops: 1, docsWritten: 1 });
      return;
    }

    if (mode === 1) {
      const chunk = 20;
      const offset = (i * chunk) % seedIds.length;
      const docs = seedIds.slice(offset, offset + chunk).map((id) => ({ id }));
      if (docs.length === 0) {
        counter.add({ ops: 1 });
        return;
      }
      const res = await fetch(`${PROXY}/${DB}/_bulk_get`, {
        method: "POST",
        headers,
        body: JSON.stringify({ docs }),
      });
      if (!res.ok) {
        counter.add({ ops: 1, errors: 1 });
        return;
      }
      const body = (await res.json()) as {
        results: Array<{ docs: Array<{ ok?: unknown }> }>;
      };
      const readable = body.results.filter((r) => r.docs[0]?.ok).length;
      counter.add({ ops: 1, docsRead: readable });
      return;
    }

    const id = seedIds[i % seedIds.length]!;
    const res = await fetch(`${PROXY}/${DB}/${encodeURIComponent(id)}`, { headers });
    if (res.status === 200) counter.add({ ops: 1, docsRead: 1 });
    else if (res.status === 404) counter.add({ ops: 1 });
    else counter.add({ ops: 1, errors: 1 });
  });
  latency.record(ms);
}

async function runSoak(): Promise<{
  load: ReturnType<typeof rateReport>;
  samples: MemorySample[];
  gcAvailable: boolean;
}> {
  const counter = new OpCounter();
  const latency = new LatencyTracker();
  const collected: MemorySample[] = [];
  let sawGc = false;
  const t0 = performance.now();
  const deadline = t0 + DURATION_SEC * 1000;
  let stop = false;

  await resetServerProfile();

  const sampler = (async () => {
    while (!stop) {
      if (FORCE_GC) {
        const ran = await requestServerGc();
        if (ran) sawGc = true;
      }
      const sample = await scrapeMemorySample(performance.now());
      if (sample) collected.push(sample);
      await sleep(SAMPLE_MS);
    }
  })();

  const workers = Array.from({ length: CLIENTS }, async (_, clientIdx) => {
    const principal = principals[clientIdx % principals.length]!;
    let i = 0;
    while (performance.now() < deadline) {
      await steadyOp(principal, clientIdx * 1_000_000 + i, counter, latency);
      i += 1;
    }
  });

  await Promise.all(workers);
  stop = true;
  await sampler;

  // Settle sample after load stops (helps distinguish leak vs in-flight buffers).
  await sleep(Math.min(SAMPLE_MS, 2000));
  if (FORCE_GC) {
    const ran = await requestServerGc();
    if (ran) sawGc = true;
  }
  const settle = await scrapeMemorySample(performance.now());
  if (settle) collected.push(settle);

  const load = rateReport(counter, latency, performance.now() - t0);
  console.log(`\n${formatRate(load, "memory soak load")}\n`);
  return { load, samples: collected, gcAvailable: sawGc };
}

function renderMarkdownReport(opts: {
  trend: MemoryTrendReport;
  load: ReturnType<typeof rateReport>;
  gcAvailable: boolean;
  sampleCount: number;
}): string {
  const { trend: t, load, gcAvailable: gc, sampleCount } = opts;
  const verdict = t.stable ? "STABLE — no evidence of a memory leak" : "UNSTABLE — investigate";
  const lines = [
    `# Memory stability report`,
    ``,
    `Generated: ${new Date().toISOString()}`,
    ``,
    `## Verdict`,
    ``,
    `**${verdict}**`,
    ``,
    t.reasons.length
      ? t.reasons.map((r) => `- ${r}`).join("\n")
      : `- Steady-state heap/rss slopes and median shifts stayed within budgets after warmup.`,
    ``,
    `## Configuration`,
    ``,
    `| Setting | Value |`,
    `| --- | --- |`,
    `| proxy | ${PROXY} |`,
    `| db | ${DB} |`,
    `| duration_sec | ${DURATION_SEC} |`,
    `| sample_ms | ${SAMPLE_MS} |`,
    `| clients | ${CLIENTS} |`,
    `| seed_docs | ${SEED_DOCS} |`,
    `| warmup_fraction | ${WARMUP_FRAC} |`,
    `| force_gc | ${FORCE_GC} (available=${gc}) |`,
    `| samples | ${sampleCount} |`,
    ``,
    `## Load summary`,
    ``,
    `| Metric | Value |`,
    `| --- | --- |`,
    `| duration_sec | ${load.durationSec.toFixed(2)} |`,
    `| ops | ${load.ops} |`,
    `| ops_per_sec | ${load.opsPerSec.toFixed(2)} |`,
    `| docs_read | ${load.docsRead} |`,
    `| docs_written | ${load.docsWritten} |`,
    `| error_rate | ${(load.errorRate * 100).toFixed(2)}% |`,
    `| latency p50/p95/p99 ms | ${load.latency.p50Ms.toFixed(1)} / ${load.latency.p95Ms.toFixed(1)} / ${load.latency.p99Ms.toFixed(1)} |`,
    ``,
    `## Memory trend (steady state)`,
    ``,
    `| Signal | Value |`,
    `| --- | --- |`,
    `| heap_used first → last | ${(t.heapUsed.first / (1024 * 1024)).toFixed(2)} → ${(t.heapUsed.last / (1024 * 1024)).toFixed(2)} MiB (Δ ${(t.heapUsed.netGrowth / (1024 * 1024)).toFixed(2)} MiB) |`,
    `| heap_used slope | ${(t.heapUsed.fit.slopePerSec / 1024).toFixed(2)} KiB/s (r=${t.heapUsed.fit.r.toFixed(3)}) |`,
    `| heap median 1st→3rd third | ${(t.heapUsed.medianFirstThird / (1024 * 1024)).toFixed(2)} → ${(t.heapUsed.medianLastThird / (1024 * 1024)).toFixed(2)} MiB |`,
    `| rss first → last | ${(t.rss.first / (1024 * 1024)).toFixed(2)} → ${(t.rss.last / (1024 * 1024)).toFixed(2)} MiB |`,
    `| rss slope | ${(t.rss.fit.slopePerSec / 1024).toFixed(2)} KiB/s (r=${t.rss.fit.r.toFixed(3)}) |`,
    `| acl_rows first → last | ${t.aclRows.first} → ${t.aclRows.last} (Δ ${t.aclRows.netGrowth}) |`,
    ``,
    `## Method`,
    ``,
    `1. Seed a fixed mixed-ACL corpus through the proxy.`,
    `2. Run concurrent HTTP readers/writers that reuse rotating document slots so the in-memory ACL map plateaus.`,
    `3. While load runs, scrape \`GET /_couch-auth-proxy/profile\` (opt-in \`PROFILE=true\`) for \`process.memoryUsage()\` plus ACL/session resource sizes.`,
    FORCE_GC
      ? `4. Optionally \`POST /_couch-auth-proxy/profile/gc\` each sample when the proxy was started with \`--expose-gc\` (profile compose overlay).`
      : `4. Forced GC disabled for this run.`,
    `5. Discard the leading warmup fraction, fit heap/rss vs time, and compare median heap in the first vs last third of the steady window. Expected ACL-row growth is budgeted; unexplained growth fails the assessment.`,
    ``,
    `## Thresholds`,
    ``,
    `| Threshold | Value |`,
    `| --- | --- |`,
    `| max heap slope | ${(thresholds.maxHeapSlopeBytesPerSec / 1024).toFixed(1)} KiB/s |`,
    `| max rss slope | ${(thresholds.maxRssSlopeBytesPerSec / 1024).toFixed(1)} KiB/s |`,
    `| max unexplained heap median shift | ${(thresholds.maxHeapThirdGrowthBytes / (1024 * 1024)).toFixed(1)} MiB |`,
    `| heap budget per new ACL row | ${thresholds.heapBytesPerAclRowBudget} B |`,
    `| min steady samples | ${thresholds.minSteadySamples} |`,
    ``,
  ];
  return `${lines.join("\n")}\n`;
}

describe("memory stability assessment", () => {
  beforeAll(async () => {
    await waitForReady();
    const ready = await memoryEndpointReady();
    if (!ready) {
      throw new Error(
        "PROFILE memory probe unavailable. Start with: pnpm docker:up:profile (or PROFILE=true), then pnpm test:perf:memory",
      );
    }
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
    console.log(
      `\n(memory soak: duration=${DURATION_SEC}s sample=${SAMPLE_MS}ms clients=${CLIENTS} seed=${SEED_DOCS})\n`,
    );
    await sleep(500);
  }, 300_000);

  afterAll(async () => {
    if (trend && loadReport) {
      const summary = {
        version: process.env.npm_package_version ?? "unknown",
        at: new Date().toISOString(),
        config: {
          durationSec: DURATION_SEC,
          sampleMs: SAMPLE_MS,
          clients: CLIENTS,
          seedDocs: SEED_DOCS,
          warmupFraction: WARMUP_FRAC,
          forceGc: FORCE_GC,
          gcAvailable,
          proxy: PROXY,
          db: DB,
          thresholds,
        },
        load: loadReport,
        trend,
        samples,
      };
      await mkdir(path.dirname(RESULTS_PATH), { recursive: true });
      await writeFile(RESULTS_PATH, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
      const md = renderMarkdownReport({
        trend,
        load: loadReport,
        gcAvailable,
        sampleCount: samples.length,
      });
      await writeFile(REPORT_PATH, md, "utf8");
      console.log(`\nWrote memory results → ${RESULTS_PATH}`);
      console.log(`Wrote memory report  → ${REPORT_PATH}\n`);
    }
    await fetch(`${PROXY}/${DB}`, { method: "DELETE", headers: adminHeaders() }).catch(
      () => undefined,
    );
  });

  it(
    "sustains ACL load without unbounded heap/rss growth",
    async () => {
      const result = await runSoak();
      samples.push(...result.samples);
      loadReport = result.load;
      gcAvailable = result.gcAvailable;

      trend = analyzeMemoryTrend(samples, thresholds);
      console.log(`\n${formatTrendReport(trend, "memory stability")}\n`);

      expect(loadReport.errorRate).toBeLessThan(0.05);
      expect(loadReport.ops).toBeGreaterThan(0);
      expect(samples.length).toBeGreaterThanOrEqual(thresholds.minSteadySamples);
      expect(trend.stable, trend.reasons.join("; ") || "unstable").toBe(true);
    },
    Math.max(600_000, (DURATION_SEC + 120) * 1000),
  );
});
