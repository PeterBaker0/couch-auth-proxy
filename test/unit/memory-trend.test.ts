/**
 * Unit tests for memory-stability trend analysis (no docker).
 */
import { describe, expect, it } from "vitest";
import { formatBytes } from "../../src/util/memory.js";
import { analyzeMemoryTrend, linearFit, type MemorySample } from "../perf/memory.js";

function sample(tMs: number, heapUsed: number, rss: number, aclRows: number): MemorySample {
  return {
    tMs,
    at: new Date(tMs).toISOString(),
    memory: {
      rss,
      heapTotal: heapUsed + 10,
      heapUsed,
      external: 1,
      arrayBuffers: 0,
    },
    resources: {
      aclDbs: 1,
      aclRows,
      aclTombstones: 0,
      aclInflightEnsures: 0,
      aclInflightRefreshes: 0,
      sessionCacheEntries: 2,
      sessionInflight: 0,
    },
    requests: 0,
  };
}

describe("memory util", () => {
  it("formats bytes", () => {
    expect(formatBytes(512)).toBe("512B");
    expect(formatBytes(2048)).toBe("2.0KiB");
    expect(formatBytes(2 * 1024 * 1024)).toBe("2.00MiB");
  });
});

describe("linearFit", () => {
  it("recovers a known slope", () => {
    const xs = [0, 1000, 2000, 3000];
    const ys = [100, 200, 300, 400]; // 0.1 per ms → 100/s
    const fit = linearFit(xs, ys);
    expect(fit.slopePerMs).toBeCloseTo(0.1, 6);
    expect(fit.slopePerSec).toBeCloseTo(100, 3);
    expect(fit.r).toBeCloseTo(1, 6);
  });
});

describe("analyzeMemoryTrend", () => {
  it("marks a flat series stable", () => {
    const samples = Array.from({ length: 20 }, (_, i) =>
      sample(i * 1000, 50 * 1024 * 1024, 80 * 1024 * 1024, 300),
    );
    const report = analyzeMemoryTrend(samples, {
      warmupFraction: 0.25,
      maxHeapSlopeBytesPerSec: 64 * 1024,
      maxRssSlopeBytesPerSec: 128 * 1024,
      maxHeapThirdGrowthBytes: 48 * 1024 * 1024,
      heapBytesPerAclRowBudget: 2048,
      minSteadySamples: 8,
    });
    expect(report.stable).toBe(true);
    expect(report.heapUsed.fit.slopePerSec).toBeCloseTo(0, 3);
  });

  it("flags a steep heap climb as unstable", () => {
    const samples = Array.from({ length: 20 }, (_, i) =>
      sample(
        i * 1000,
        20 * 1024 * 1024 + i * 2 * 1024 * 1024, // +2MiB/s
        40 * 1024 * 1024 + i * 2 * 1024 * 1024,
        300,
      ),
    );
    const report = analyzeMemoryTrend(samples);
    expect(report.stable).toBe(false);
    expect(report.reasons.some((r) => r.includes("heapUsed slope"))).toBe(true);
  });

  it("budgets heap growth explained by ACL row growth", () => {
    // Steady window grows ~1KiB heap per new ACL row — within 2KiB budget.
    const samples = Array.from({ length: 20 }, (_, i) =>
      sample(i * 1000, 30 * 1024 * 1024 + i * 1000, 60 * 1024 * 1024, 100 + i),
    );
    const report = analyzeMemoryTrend(samples);
    expect(report.aclRows.netGrowth).toBeGreaterThan(0);
    expect(report.stable).toBe(true);
  });
});
