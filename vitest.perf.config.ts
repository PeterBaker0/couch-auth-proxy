/**
 * Vitest config for docker-backed ACL performance harness under test/perf.
 * Requires `docker compose up` (same stack as integration tests).
 * Not run in CI by default — timings are host-dependent; use for baselines.
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/perf/**/*.test.ts"],
    environment: "node",
    testTimeout: 600_000,
    hookTimeout: 300_000,
    fileParallelism: false,
    sequence: { concurrent: false },
  },
});
