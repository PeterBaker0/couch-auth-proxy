/**
 * Vitest config for the long-running memory stability assessment.
 * Requires PROFILE=true on the proxy (see `pnpm test:perf:memory`).
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/perf/memory-stability.test.ts"],
    environment: "node",
    // Soak length is env-tunable; allow long runs (default 5m + headroom).
    testTimeout: 1_800_000,
    hookTimeout: 300_000,
    fileParallelism: false,
    sequence: { concurrent: false },
  },
});
