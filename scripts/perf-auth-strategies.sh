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

  # Bearer-only proxy cannot authenticate admin Basic; mint _admin JWT for setup.
  RUN_ENV=(PERF_RESULTS_PATH="${RESULTS_PATH}")
  if [[ "${RESOLVE}" == "false" ]]; then
    ADMIN_JWT="$(
      JWT_HMAC_SECRET="${JWT_HMAC_SECRET:-couch-auth-proxy-dev-secret}" \
        node --input-type=module <<'MINT'
import { SignJWT } from "jose";
const secret = process.env.JWT_HMAC_SECRET || "couch-auth-proxy-dev-secret";
const jwt = await new SignJWT({ "_couchdb.roles": ["_admin"] })
  .setProtectedHeader({ alg: "HS256" })
  .setSubject(process.env.COUCH_ADMIN_USER || "admin")
  .setExpirationTime("2h")
  .sign(new TextEncoder().encode(secret));
process.stdout.write(jwt);
MINT
    )"
    RUN_ENV+=(PERF_ADMIN_JWT="${ADMIN_JWT}")
  fi

  env "${RUN_ENV[@]}" pnpm test:perf

  curl -sf "${PROXY_URL}/_couch-auth-proxy/profile" | tee "${PROFILE_PATH}" >/dev/null
  echo "Wrote ${RESULTS_PATH} and ${PROFILE_PATH}"
done

echo
echo "==> assembling summary + assessment doc"
PERF_AUTH_OUT="${OUT_DIR}" node scripts/assemble-auth-strategy-report.mjs
echo "==> done"
