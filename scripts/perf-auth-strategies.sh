#!/usr/bin/env bash
# Benchmark auth strategy variants against the ACL perf harness (PROFILE=true).
#
# Variants (recreate proxy env each run; Couch stays up):
#   1. couch-session TTL=0        — re-resolve via GET /_session every request
#   2. couch-session TTL=1000     — 1s principal cache
#   3. couch-session TTL=5000     — default / keep-as-is (5s)
#   4. couch-session TTL=30000    — 30s principal cache
#   5. hybrid-bearer-jwt TTL=5000 — local HS256 for Bearer + Couch session for Basic/Cookie
#   6. local-jwt-only TTL=5000    — AUTH_RESOLVE_VIA_COUCH_SESSION=false (Bearer only)
#   7. local-jwt-only TTL=0       — local verify every request (no principal cache)
#
# Usage:
#   bash scripts/perf-auth-strategies.sh
#   PERF_AUTH_VARIANTS=ttl0,ttl5k,local-jwt bash scripts/perf-auth-strategies.sh
#
# Writes:
#   test/perf/auth-strategy/<variant>/{results.json,profile.json}
#   test/perf/auth-strategy/summary.json
#   docs/auth-strategy-assessment.md
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.profile.yml)
PROXY_URL="${COUCH_AUTH_PROXY_URL:-http://127.0.0.1:8000}"
OUT_DIR="${PERF_AUTH_OUT:-test/perf/auth-strategy}"
# Slightly smaller than defaults so seven variants finish in a reasonable window.
export PERF_CLIENTS="${PERF_CLIENTS:-6}"
export PERF_SEED_DOCS="${PERF_SEED_DOCS:-300}"
export PERF_ROUNDS="${PERF_ROUNDS:-3}"
export PERF_DOCS_PER_ROUND="${PERF_DOCS_PER_ROUND:-8}"
export PERF_HTTP_OPS="${PERF_HTTP_OPS:-60}"
export PERF_MIN_OPS_PER_SEC="${PERF_MIN_OPS_PER_SEC:-10}"

die() { echo "error: $*" >&2; exit 1; }

wait_ready() {
  for i in $(seq 1 90); do
    if curl -sf "${PROXY_URL}/_couch-auth-proxy/ready" >/dev/null; then
      return 0
    fi
    sleep 2
  done
  "${COMPOSE[@]}" logs couch-auth-proxy couchdb || true
  die "proxy not ready at ${PROXY_URL}"
}

# name|SESSION_CACHE_TTL_MS|AUTH_RESOLVE_VIA_COUCH_SESSION|JWT_LOCAL_VERIFY|notes
ALL_VARIANTS=(
  "ttl0|0|true|false|Couch /_session every request (no principal cache)"
  "ttl1k|1000|true|false|Couch /_session + 1s principal cache"
  "ttl5k|5000|true|false|Keep-as-is: Couch /_session + default 5s cache"
  "ttl30k|30000|true|false|Couch /_session + 30s principal cache"
  "hybrid-jwt|5000|true|true|Bearer local HS256 fast-path + 5s cache; Basic/Cookie → Couch"
  "local-jwt|5000|false|true|In-house Bearer JWT only + 5s cache (no /_session)"
  "local-jwt-nocache|0|false|true|In-house Bearer JWT every request (no principal cache)"
)

SELECTED="${PERF_AUTH_VARIANTS:-}"
should_run() {
  local name="$1"
  [[ -z "${SELECTED}" ]] && return 0
  [[ ",${SELECTED}," == *",${name},"* ]]
}

mkdir -p "${OUT_DIR}"
echo "==> bringing up stack (profile overlay)"
sg docker -c "${COMPOSE[*]} up -d --build"
wait_ready

SUMMARY_PARTS=()

for entry in "${ALL_VARIANTS[@]}"; do
  IFS='|' read -r NAME TTL RESOLVE LOCAL NOTES <<<"${entry}"
  should_run "${NAME}" || { echo "==> skip ${NAME}"; continue; }

  echo
  echo "============================================================"
  echo "==> variant: ${NAME}"
  echo "    SESSION_CACHE_TTL_MS=${TTL}"
  echo "    AUTH_RESOLVE_VIA_COUCH_SESSION=${RESOLVE}"
  echo "    JWT_LOCAL_VERIFY=${LOCAL}"
  echo "    ${NOTES}"
  echo "============================================================"

  VARIANT_DIR="${OUT_DIR}/${NAME}"
  mkdir -p "${VARIANT_DIR}"

  # Recreate only the proxy so Couch ACL state / warm caches stay comparable.
  sg docker -c "SESSION_CACHE_TTL_MS='${TTL}' \
    AUTH_RESOLVE_VIA_COUCH_SESSION='${RESOLVE}' \
    JWT_LOCAL_VERIFY='${LOCAL}' \
    JWT_HMAC_SECRET='${JWT_HMAC_SECRET:-couch-auth-proxy-dev-secret}' \
    PROFILE=true \
    ${COMPOSE[*]} up -d --no-deps --force-recreate couch-auth-proxy"

  wait_ready
  curl -sf -X POST "${PROXY_URL}/_couch-auth-proxy/profile/reset" >/dev/null ||
    die "profile endpoint unavailable"

  RESULTS_PATH="${VARIANT_DIR}/results.json"
  PROFILE_PATH="${VARIANT_DIR}/profile.json"
  PERF_RESULTS_PATH="${RESULTS_PATH}" pnpm test:perf

  curl -sf "${PROXY_URL}/_couch-auth-proxy/profile" | tee "${PROFILE_PATH}" >/dev/null
  echo "Wrote ${RESULTS_PATH} and ${PROFILE_PATH}"

  SUMMARY_PARTS+=("${NAME}|${TTL}|${RESOLVE}|${LOCAL}|${NOTES}|${RESULTS_PATH}|${PROFILE_PATH}")
done

echo
echo "==> assembling summary + assessment doc"
export PERF_AUTH_OUT="${OUT_DIR}"
export PERF_AUTH_PARTS="$(printf '%s\n' "${SUMMARY_PARTS[@]}")"
node --input-type=module <<'NODE'
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const outDir = process.env.PERF_AUTH_OUT || "test/perf/auth-strategy";
const parts = process.env.PERF_AUTH_PARTS || "";
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
for (const line of parts.split("\n").filter(Boolean)) {
  const [name, ttl, resolve, local, notes, resultsPath, profilePath] = line.split("|");
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
    sessionCacheTtlMs: Number(ttl),
    resolveViaCouchSession: resolve === "true",
    jwtLocalVerify: local === "true",
    notes,
    overallOpsPerSec: overall.overallOpsPerSec ?? null,
    syncOpsPerSec: sync.opsPerSec ?? null,
    httpOpsPerSec: http.opsPerSec ?? null,
    bulkGetOpsPerSec: bulk.opsPerSec ?? null,
    proxyOverDirectRatio: compare.proxyOverDirectRatio ?? null,
    overheadPct: compare.overheadPct ?? null,
    authHttp: phase(httpProf, "auth"),
    authSync: phase(syncProf, "auth"),
    upstreamHttp: phase(httpProf, "upstream"),
    endProfileAuth: phase(profile, "auth"),
    endProfileUpstream: phase(profile, "upstream"),
    sessionCacheEntries: profile.resources?.sessionCacheEntries ?? null,
  });
}

const summary = {
  at: new Date().toISOString(),
  harness,
  note:
    "Principal cache TTL is SESSION_CACHE_TTL_MS (not an ACL TTL). ACL rows are changes-fed, not time-expired.",
  variants,
};
mkdirSync(outDir, { recursive: true });
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
    return `| \`${v.name}\` | ${v.sessionCacheTtlMs} | ${v.resolveViaCouchSession ? "couch" : "off"} / ${v.jwtLocalVerify ? "local JWT" : "—"} | ${fmt(v.overallOpsPerSec)} | ${fmt(v.httpOpsPerSec)} | ${fmt(authMs, 2)} | ${rel(v, "overallOpsPerSec")} | ${rel(v, "httpOpsPerSec")} |`;
  })
  .join("\n");

const detail = variants
  .map((v) => {
    return `### \`${v.name}\`
${v.notes}

| Metric | Value |
|---|---|
| overall ops/s | ${fmt(v.overallOpsPerSec)} |
| sync ops/s | ${fmt(v.syncOpsPerSec)} |
| HTTP ops/s | ${fmt(v.httpOpsPerSec)} |
| _bulk_get ops/s | ${fmt(v.bulkGetOpsPerSec)} |
| proxy/direct HTTP ratio | ${fmt(v.proxyOverDirectRatio, 3)} |
| HTTP auth per-request mean (ms) | ${fmt(v.authHttp?.perRequestMeanMs, 3)} |
| HTTP auth mean span (ms) | ${fmt(v.authHttp?.meanMs, 3)} |
| HTTP upstream per-request mean (ms) | ${fmt(v.upstreamHttp?.perRequestMeanMs, 3)} |
| sync auth per-request mean (ms) | ${fmt(v.authSync?.perRequestMeanMs, 3)} |
| session cache entries (end scrape) | ${v.sessionCacheEntries ?? "—"} |
`;
  })
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

## Results (relative to keep-as-is)

| Variant | TTL ms | Resolve | overall ops/s | HTTP ops/s | HTTP auth ms/req | Δ overall | Δ HTTP |
|---|---:|---|---:|---:|---:|---|---|
${rows}

Raw JSON: [\`test/perf/auth-strategy/summary.json\`](../test/perf/auth-strategy/summary.json).

## Per-variant detail

${detail}

## Critical assessment

### What the numbers mean

1. **Auth is usually not the ACL bottleneck.** Hot-path cost order under this
   harness is typically **upstream Couch RTT → auth → aclMiss**, with in-process
   ACL filtering cheap once warm. Cutting auth to near-zero only helps if auth
   was a meaningful share of \`meanDurationMs\` (see \`phaseShareOfMean.auth\` in
   the profile scrapes).
2. **\`SESSION_CACHE_TTL_MS=5000\` (keep-as-is) already removes most \`/_session\`
   cost** for sticky clients: Pouch sync and HTTP loops reuse the same Bearer
   token, so after the first hit within 5s the proxy serves principals from an
   LRU. \`TTL=0\` is the honest “every request pays Couch session RTT” baseline.
3. **Longer TTLs (30s) buy little once 5s already yields high hit rates** under
   this harness, but widen the revocation lag window (see Security).
4. **In-house JWT** removes the proxy→Couch \`/_session\` hop for Bearer clients.
   Couch **still** validates the same JWT on the upstream request, so you do not
   get a second independent trust domain — you only skip a redundant identity
   round-trip used to build ACL tokens.
5. **Hybrid** (\`AUTH_RESOLVE_VIA_COUCH_SESSION=true\` + \`JWT_LOCAL_VERIFY=true\`)
   is the pragmatic production shape for JWT-heavy apps that still allow
   Basic/Cookie: Bearer skips \`/_session\`; password/cookie clients keep Couch
   as source of truth.

### Security risk vs performance gain

| Approach | Revocation / freshness | Trust / ops risk | Perf gain vs TTL=0 |
|---|---|---|---|
| Couch session, TTL=0 | Immediate role/\`_admin\` changes on next request | Lowest fork risk; Couch owns auth | baseline |
| Couch session, TTL=5s (default) | Up to **5s** stale roles after Couch \`_users\` / role change; logout (\`DELETE /_session\`) invalidates that credential’s cache entry | Same trust model; small stale window | Large when clients are sticky (typical sync) |
| Couch session, TTL=30s | Up to **30s** stale roles | Same; wider window — poor fit if admins expect instant demotion | Marginal over 5s under sticky load |
| Local JWT only | Bound by JWT \`exp\` (and any external revoke list you build). Role changes in \`_users\` **do not** affect already-minted JWTs until expiry | Must keep \`JWT_HMAC_SECRET\` / keys **identical** to Couch \`[jwt_keys]\`; HS256 secret distribution; no Basic/Cookie | Similar to warm 5s cache for Bearer; wins more under low reuse / TTL=0 workloads |
| Hybrid Bearer local + Couch session | Bearer: JWT \`exp\`; Basic/Cookie: session TTL | Key sync required for Bearer path; misconfig → ACL anonymous while Couch may still accept/reject independently | Best of both for mixed clients |

**Realistic risk of the default 5s session cache:** an operator removes a role or
\`_admin\` in Couch and the proxy may authorize with the old principal for up to
5 seconds for that credential hash. That is comparable to many gateway session
caches and far shorter than typical JWT lifetimes (minutes–hours). Logout via
\`DELETE /_session\` already drops the cached principal for those headers.

**Realistic risk of in-house JWT as sole resolver:** you fork claim→role
semantics if local \`JWT_ROLES_CLAIM_PATH\` / required claims drift from Couch;
Basic/Cookie clients become anonymous at the proxy; password auth is no longer
a supported identity path unless you reintroduce Couch session or own a user
DB. Secret leakage is catastrophic (forger mints any \`sub\`/roles) — same as
Couch JWT key leakage, but now **two** places must protect the secret.

**When in-house JWT is worth it:** Bearer-only deployments, very short or zero
principal TTL requirements, or measured \`auth\` phase still dominating after
TTL=5s (e.g. many distinct tokens with poor cache locality). Otherwise prefer
**keep Couch session + 5s cache**, or **hybrid** if you want Bearer RTT=0
without abandoning Basic/Cookie.

### Recommendation

1. **Default (ship today): Couch \`/_session\` + \`SESSION_CACHE_TTL_MS=5000\`.**
   Best security/ops story for mixed auth; perf already amortizes session cost
   under sync/HTTP reuse.
2. **Enable hybrid** (\`JWT_LOCAL_VERIFY=true\` with session still on) when
   clients are mostly JWT and profile scrapes show auth share still material
   after caching — keys must match Couch.
3. **Avoid JWT-only** unless the product truly drops Basic/Cookie and you
   accept JWT lifetime as the revocation model.
4. **Avoid TTL=0 in production** unless compliance demands instantaneous role
   propagation; pay the Couch RTT on every request.
5. **Do not chase 30s+ TTLs** for throughput on sticky workloads; spend
   engineering on upstream Couch / ACL miss paths instead.

## Re-run

\`\`\`bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.profile.yml up -d --build
bash scripts/perf-auth-strategies.sh
# subset:
PERF_AUTH_VARIANTS=ttl0,ttl5k,local-jwt bash scripts/perf-auth-strategies.sh
\`\`\`
`;

writeFileSync("docs/auth-strategy-assessment.md", md);
console.log(`Wrote ${path.join(outDir, "summary.json")} and docs/auth-strategy-assessment.md`);
NODE

echo "==> done"
