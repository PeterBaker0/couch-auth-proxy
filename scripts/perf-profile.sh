#!/usr/bin/env bash
# Bring up the compose stack with PROFILE=true, run the ACL perf harness, and
# print the scrapeable server phase snapshot. Host CPU profiles are optional
# via PERF_CPU_PROF=1 (uses a host-local proxy instead of the docker one).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.profile.yml)
PROXY_URL="${COUCH_AUTH_PROXY_URL:-http://127.0.0.1:8000}"
RESULTS_PATH="${PERF_RESULTS_PATH:-test/perf/last-results.json}"

die() {
  echo "error: $*" >&2
  exit 1
}

if [[ "${PERF_CPU_PROF:-0}" == "1" ]]; then
  die "PERF_CPU_PROF host mode: start Couch with docker compose.dev, then:
  PROFILE=true pnpm start:profile
  COUCH_AUTH_PROXY_URL=http://127.0.0.1:8000 pnpm test:perf
  Inspect CPU profiles under ./profiles/"
fi

echo "==> starting stack with PROFILE=true"
"${COMPOSE[@]}" up -d --build

echo "==> waiting for ready"
for i in $(seq 1 90); do
  if curl -sf "${PROXY_URL}/_couch-auth-proxy/ready" >/dev/null; then
    break
  fi
  if [[ "$i" -eq 90 ]]; then
    "${COMPOSE[@]}" logs couch-auth-proxy couchdb || true
    die "proxy not ready at ${PROXY_URL}"
  fi
  sleep 2
done

echo "==> resetting profile counters"
curl -sf -X POST "${PROXY_URL}/_couch-auth-proxy/profile/reset" >/dev/null ||
  die "profile endpoint unavailable — is PROFILE=true on the proxy?"

echo "==> running pnpm test:perf"
PERF_RESULTS_PATH="${RESULTS_PATH}" pnpm test:perf

echo "==> server profile snapshot"
curl -sf "${PROXY_URL}/_couch-auth-proxy/profile" | tee test/perf/last-profile.json
echo
echo "Wrote ${RESULTS_PATH} and test/perf/last-profile.json"
