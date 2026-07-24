#!/usr/bin/env bash
# Bring up the compose stack with PROFILE=true (+ optional --expose-gc), run the
# long-running memory stability soak, and write JSON + Markdown reports.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.profile.yml)
PROXY_URL="${COUCH_AUTH_PROXY_URL:-http://127.0.0.1:8000}"
RESULTS_PATH="${PERF_MEMORY_RESULTS_PATH:-test/perf/last-memory-results.json}"
REPORT_PATH="${PERF_MEMORY_REPORT_PATH:-test/perf/last-memory-report.md}"
# Default 5-minute soak; override with PERF_MEMORY_DURATION_SEC.
export PERF_MEMORY_DURATION_SEC="${PERF_MEMORY_DURATION_SEC:-300}"

die() {
  echo "error: $*" >&2
  exit 1
}

echo "==> starting stack with PROFILE=true (memory probe + optional expose-gc)"
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

echo "==> checking PROFILE memory probe"
curl -sf "${PROXY_URL}/_couch-auth-proxy/profile" >/dev/null ||
  die "profile endpoint unavailable — is PROFILE=true on the proxy?"

echo "==> running memory soak (${PERF_MEMORY_DURATION_SEC}s)"
PERF_MEMORY_RESULTS_PATH="${RESULTS_PATH}" \
  PERF_MEMORY_REPORT_PATH="${REPORT_PATH}" \
  PERF_MEMORY_REQUIRED=1 \
  pnpm exec vitest run --config vitest.perf.memory.config.ts

echo "==> final profile snapshot"
curl -sf "${PROXY_URL}/_couch-auth-proxy/profile" | tee test/perf/last-memory-profile.json >/dev/null
echo
echo "Wrote ${RESULTS_PATH}"
echo "Wrote ${REPORT_PATH}"
echo "Wrote test/perf/last-memory-profile.json"
if [[ -f "${REPORT_PATH}" ]]; then
  echo
  sed -n '1,80p' "${REPORT_PATH}"
fi
