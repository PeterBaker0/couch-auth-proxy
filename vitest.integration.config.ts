/**
 * Vitest config for docker-backed integration tests under test/integration.
 * Requires `docker compose up` (couch-auth-proxy + CouchDB). Runs files serially
 * with long timeouts for readiness and ACL follower lag.
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/integration/**/*.test.ts"],
    environment: "node",
    testTimeout: 90_000,
    hookTimeout: 180_000,
    fileParallelism: false,
    // Shared Docker DB mutations (restrict/dbacl) must not interleave.
    sequence: { concurrent: false },
  },
});
