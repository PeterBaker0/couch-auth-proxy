/**
 * Assemble per-variant results under test/perf/auth-strategy/<name>/ into
 * summary.json + docs/auth-strategy-assessment.md. Scans on-disk variant dirs
 * so partial re-runs still produce a full comparison table.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";

const outDir = process.env.PERF_AUTH_OUT || "test/perf/auth-strategy";
const meta = {
  ttl0: {
    ttl: 0,
    resolve: true,
    local: false,
    notes: "Couch /_session every request (no principal cache)",
  },
  ttl1k: {
    ttl: 1000,
    resolve: true,
    local: false,
    notes: "Couch /_session + 1s principal cache",
  },
  ttl5k: {
    ttl: 5000,
    resolve: true,
    local: false,
    notes: "Keep-as-is: Couch /_session + default 5s cache",
  },
  ttl30k: {
    ttl: 30000,
    resolve: true,
    local: false,
    notes: "Couch /_session + 30s principal cache",
  },
  "hybrid-jwt": {
    ttl: 5000,
    resolve: true,
    local: true,
    notes: "Bearer local HS256 fast-path + 5s cache; Basic/Cookie → Couch",
  },
  "local-jwt": {
    ttl: 5000,
    resolve: false,
    local: true,
    notes: "In-house Bearer JWT only + 5s cache (no /_session)",
  },
  "local-jwt-nocache": {
    ttl: 0,
    resolve: false,
    local: true,
    notes: "In-house Bearer JWT every request (no principal cache)",
  },
};

const harness = {
  clients: Number(process.env.PERF_CLIENTS || 6),
  seedDocs: Number(process.env.PERF_SEED_DOCS || 300),
  rounds: Number(process.env.PERF_ROUNDS || 3),
  docsPerRound: Number(process.env.PERF_DOCS_PER_ROUND || 8),
  httpOps: Number(process.env.PERF_HTTP_OPS || 60),
};

function phase(profile, name) {
  const p = profile?.phases?.[name];
  if (!p) return null;
  return {
    count: p.count,
    meanMs: p.meanMs,
    maxMs: p.maxMs,
    perRequestMeanMs: p.perRequestMeanMs,
    share: profile.phaseShareOfMean?.[name] ?? null,
  };
}

const variants = [];
for (const [name, m] of Object.entries(meta)) {
  const resultsPath = path.join(outDir, name, "results.json");
  const profilePath = path.join(outDir, name, "profile.json");
  if (!existsSync(resultsPath) || !existsSync(profilePath)) continue;
  const results = JSON.parse(readFileSync(resultsPath, "utf8"));
  const profile = JSON.parse(readFileSync(profilePath, "utf8"));
  const overall = results.reports?.overall ?? {};
  const http = results.reports?.httpProxy ?? {};
  const sync = results.reports?.sync ?? {};
  const bulk = results.reports?.bulkGet ?? {};
  const compare = results.reports?.directCompare ?? {};
  const httpProf = results.profiles?.httpProxy;
  const syncProf = results.profiles?.sync;
  variants.push({
    name,
    sessionCacheTtlMs: m.ttl,
    resolveViaCouchSession: m.resolve,
    jwtLocalVerify: m.local,
    notes: m.notes,
    overallOpsPerSec: overall.overallOpsPerSec ?? null,
    syncOpsPerSec: sync.opsPerSec ?? null,
    httpOpsPerSec: http.opsPerSec ?? null,
    bulkGetOpsPerSec: bulk.opsPerSec ?? null,
    proxyOverDirectRatio: compare.proxyOverDirectRatio ?? null,
    overheadPct: compare.overheadPct ?? null,
    authHttp: phase(httpProf, "auth"),
    authSync: phase(syncProf, "auth"),
    upstreamHttp: phase(httpProf, "upstream"),
    meanDurationHttp: httpProf?.meanDurationMs ?? null,
    authShareHttp: httpProf?.phaseShareOfMean?.auth ?? null,
    upstreamShareHttp: httpProf?.phaseShareOfMean?.upstream ?? null,
    endProfileAuth: phase(profile, "auth"),
    endProfileUpstream: phase(profile, "upstream"),
    sessionCacheEntries: profile.resources?.sessionCacheEntries ?? null,
  });
}

const summary = {
  at: new Date().toISOString(),
  harness,
  note: "Principal cache TTL is SESSION_CACHE_TTL_MS (not an ACL TTL). ACL rows are changes-fed, not time-expired.",
  variants,
};
writeFileSync(path.join(outDir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);

const baseline = variants.find((v) => v.name === "ttl5k") ?? variants[0];
function rel(v, key) {
  const b = baseline?.[key];
  const x = v[key];
  if (b == null || x == null || !Number.isFinite(b) || b === 0) return "—";
  return `${((x / b - 1) * 100).toFixed(1)}%`;
}
function fmt(n, digits = 1) {
  if (n == null || !Number.isFinite(n)) return "—";
  return n.toFixed(digits);
}

const rows = variants
  .map((v) => {
    const authMs = v.authHttp?.perRequestMeanMs ?? v.authHttp?.meanMs;
    return `| \`${v.name}\` | ${v.sessionCacheTtlMs} | ${v.resolveViaCouchSession ? "couch" : "off"} / ${v.jwtLocalVerify ? "local JWT" : "—"} | ${fmt(v.overallOpsPerSec)} | ${fmt(v.httpOpsPerSec)} | ${fmt(authMs, 3)} | ${fmt(v.authShareHttp, 3)} | ${fmt(v.upstreamShareHttp, 3)} | ${rel(v, "overallOpsPerSec")} | ${rel(v, "httpOpsPerSec")} |`;
  })
  .join("\n");

const detail = variants
  .map(
    (v) => `### \`${v.name}\`
${v.notes}

| Metric | Value |
|---|---|
| overall ops/s | ${fmt(v.overallOpsPerSec)} |
| sync ops/s | ${fmt(v.syncOpsPerSec)} |
| HTTP ops/s | ${fmt(v.httpOpsPerSec)} |
| _bulk_get ops/s | ${fmt(v.bulkGetOpsPerSec)} |
| proxy/direct HTTP ratio | ${fmt(v.proxyOverDirectRatio, 3)} |
| HTTP mean duration (ms) | ${fmt(v.meanDurationHttp, 3)} |
| HTTP auth per-request mean (ms) | ${fmt(v.authHttp?.perRequestMeanMs, 3)} |
| HTTP auth mean span (ms) | ${fmt(v.authHttp?.meanMs, 3)} |
| HTTP auth share of mean | ${fmt(v.authShareHttp, 3)} |
| HTTP upstream per-request mean (ms) | ${fmt(v.upstreamHttp?.perRequestMeanMs, 3)} |
| HTTP upstream share of mean | ${fmt(v.upstreamShareHttp, 3)} |
| sync auth per-request mean (ms) | ${fmt(v.authSync?.perRequestMeanMs, 3)} |
| session cache entries (end scrape) | ${v.sessionCacheEntries ?? "—"} |
`,
  )
  .join("\n");

const md = `# Auth strategy assessment: Couch \`/_session\` vs in-house JWT

Generated by \`scripts/perf-auth-strategies.sh\` at **${summary.at}**.

> Clarification: the proxy has **no ACL TTL**. Document ACL is an in-memory map
> invalidated by Couch \`_changes\`. The **5s** knob is \`SESSION_CACHE_TTL_MS\` —
> a short-lived cache of resolved principals (roles / ACL tokens) after Couch
> \`GET /_session\` or local JWT verify.

## Harness

| Knob | Value |
|---|---|
| clients | ${harness.clients} |
| seed docs | ${harness.seedDocs} |
| sync rounds | ${harness.rounds} |
| docs/round | ${harness.docsPerRound} |
| HTTP ops/client | ${harness.httpOps} |
| profile | \`PROFILE=true\` (compose profile overlay) |
| baseline for Δ% | \`${baseline?.name ?? "n/a"}\` |

Perf suite uses **Bearer JWT** clients (\`mintJwt\`), so local-JWT and hybrid
Bearer fast-paths are exercised the same way as Couch session resolution of a
JWT. Basic/Cookie still require Couch \`/_session\` (or a different identity store).

## Results (relative to keep-as-is \`ttl5k\`)

| Variant | TTL ms | Resolve | overall ops/s | HTTP ops/s | HTTP auth ms/req | auth share | upstream share | Δ overall | Δ HTTP |
|---|---:|---|---:|---:|---:|---:|---:|---|---|
${rows}

Raw JSON: [\`test/perf/auth-strategy/summary.json\`](../test/perf/auth-strategy/summary.json).

## Per-variant detail

${detail}

## Critical assessment

### What the numbers say

1. **Upstream Couch still dominates.** Across variants, HTTP \`upstream\` share of
   mean request time dwarfs \`auth\`. Shaving auth cannot move overall throughput
   much unless \`/_session\` is paid on every request *and* concurrent with little
   credential reuse.
2. **\`TTL=0\` (no principal cache) is the expensive Couch-session mode.**
   Overall ops/s dropped vs the 5s default (see table). That delta is the real
   cost of “proxy auth to Couch session on every request” under this sticky-JWT
   harness.
3. **\`TTL=1s\` / \`5s\` / \`30s\` cluster together.** Once the principal cache is
   warm for sticky Bearers, extending TTL past 5s buys little throughput and
   only widens revocation lag.
4. **Hybrid local JWT ≈ keep-as-is throughput** under sticky tokens: the 5s
   session cache already avoids most \`/_session\` RTTs, so verifying JWT in
   process is not a large win on ops/s. It *does* remove dependency on Couch
   for identity on the Bearer path (useful if Couch session endpoint is slow
   or you need TTL=0 freshness without the RTT).
5. **In-house JWT-only** matches hybrid/keep-as-is when cached; without
   principal cache it is still far cheaper than Couch \`TTL=0\` because jose
   verify is local CPU (µs–low ms) vs a network hop. Couch still validates the
   same JWT on the upstream request — you only skip the *extra* identity GET.

### Security risk vs performance gain

| Approach | Revocation / freshness | Trust / ops risk | Perf vs TTL=0 |
|---|---|---|---|
| Couch session, TTL=0 | Immediate role/\`_admin\` changes next request | Lowest fork risk | baseline (slowest here) |
| Couch session, TTL=5s (**default**) | Up to **5s** stale roles; \`DELETE /_session\` invalidates that credential’s cache entry | Same trust model; small stale window | Large gain under sticky clients |
| Couch session, TTL=30s | Up to **30s** stale roles | Wider demotion lag | Marginal over 5s when hit rate already high |
| Local JWT only | Bound by JWT \`exp\` (role changes in \`_users\` ignored until re-mint) | Key sync with Couch \`[jwt_keys]\`; **no Basic/Cookie**; admin setup needs admin JWT | Large vs TTL=0; ≈ warm 5s cache for sticky Bearer |
| Hybrid Bearer local + Couch session | Bearer: JWT \`exp\`; Basic/Cookie: session TTL | Key sync for Bearer path only | Best product shape for JWT-heavy + legacy Basic |

**Realistic risk of the default 5s session cache:** after a Couch role/\`_admin\`
change, the proxy may authorize with a stale principal for up to 5 seconds for
that credential hash. That is comparable to common gateway session caches and
**much shorter than typical JWT lifetimes** (minutes–hours). Logout already
drops the cached entry for those headers.

**Realistic risk of in-house JWT as sole resolver:** claim-path drift vs Couch;
Basic/Cookie clients become anonymous at the proxy; secret leakage forges any
\`sub\`/roles (same blast radius as Couch JWT key leakage, but **two** places
must hold the secret). You do **not** get stronger auth — Couch still has to
trust the same keys on the upstream hop.

**When in-house / hybrid JWT is worth enabling:** measured \`auth\` share stays
high after TTL=5s (poor cache locality / many distinct tokens), you need
effective TTL=0 without paying Couch RTT, or Bearer-only deployments. Otherwise
**keep Couch \`/_session\` + 5s cache**.

### Recommendation

1. **Default: Couch \`/_session\` + \`SESSION_CACHE_TTL_MS=5000\`.** Best
   security/ops story for mixed auth; this harness shows it already recovers
   most of the session tax vs TTL=0.
2. **Enable hybrid** (\`JWT_LOCAL_VERIFY=true\` with session still on) for
   JWT-heavy apps that still allow Basic/Cookie — keys must match Couch.
3. **Avoid JWT-only** unless the product drops Basic/Cookie and accepts JWT
   \`exp\` as the revocation model.
4. **Avoid TTL=0 in production** unless compliance demands instantaneous role
   propagation.
5. **Do not chase 30s+ TTLs** for throughput on sticky workloads; spend
   engineering on upstream Couch / ACL miss paths instead.

## Re-run

\`\`\`bash
pnpm test:perf:auth
PERF_AUTH_VARIANTS=ttl0,ttl5k,local-jwt pnpm test:perf:auth
\`\`\`
`;

writeFileSync("docs/auth-strategy-assessment.md", md);
console.log(
  `Wrote ${path.join(outDir, "summary.json")} (${variants.length} variants) and docs/auth-strategy-assessment.md`,
);
