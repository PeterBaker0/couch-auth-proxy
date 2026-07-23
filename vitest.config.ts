/**
 * Vitest config for fast unit tests under test/unit.
 * No Docker / live Couch required.
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/unit/**/*.test.ts"],
    environment: "node",
  },
});
