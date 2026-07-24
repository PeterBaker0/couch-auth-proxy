/**
 * Vitest config for docker-backed ACL performance harness under test/perf.
 * Requires `docker compose up` (same stack as integration tests).
 * Not run in CI by default — timings are host-dependent; use for baselines.
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Throughput harness only — memory soak is opt-in via vitest.perf.memory.config.ts
    include: ["test/perf/acl-sync-load.test.ts"],
    environment: "node",
    testTimeout: 600_000,
    hookTimeout: 300_000,
    fileParallelism: false,
    sequence: { concurrent: false },
  },
});
