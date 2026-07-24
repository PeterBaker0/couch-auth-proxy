/**
 * Memory sampling + trend analysis for the long-running stability harness.
 */
import {
  formatBytes,
  formatMemorySnapshot,
  type ProcessMemorySnapshot,
  type ResourceStats,
} from "../../src/util/memory.js";
import type { ProfileSnapshot } from "../../src/util/profile.js";
import { PROXY } from "../integration/helpers.js";
import { fetchServerProfile, profileEndpointAvailable } from "./profile.js";

export type MemorySample = {
  tMs: number;
  at: string;
  memory: ProcessMemorySnapshot;
  resources: ResourceStats;
  requests: number;
};

export type LinearFit = {
  /** Slope in units per millisecond. */
  slopePerMs: number;
  /** Slope in units per second. */
  slopePerSec: number;
  intercept: number;
  /** Pearson r (−1..1); 0 when undefined. */
  r: number;
  n: number;
};

export type MemoryTrendReport = {
  samples: number;
  steadySamples: number;
  durationSec: number;
  warmupSec: number;
  heapUsed: {
    first: number;
    last: number;
    min: number;
    max: number;
    mean: number;
    medianFirstThird: number;
    medianLastThird: number;
    netGrowth: number;
    thirdGrowth: number;
    fit: LinearFit;
  };
  rss: {
    first: number;
    last: number;
    min: number;
    max: number;
    netGrowth: number;
    fit: LinearFit;
  };
  aclRows: {
    first: number;
    last: number;
    netGrowth: number;
    fit: LinearFit;
  };
  /** Bytes of heap growth attributed per new ACL row (Infinity if rows flat). */
  heapBytesPerAclRow: number;
  /** True when steady-state heap/rss trends look leak-free under configured thresholds. */
  stable: boolean;
  reasons: string[];
};

export type StabilityThresholds = {
  /** Discard this leading fraction of the run as warmup (cache fill, JIT). */
  warmupFraction: number;
  /** Max allowed heapUsed linear slope after warmup (bytes/sec). */
  maxHeapSlopeBytesPerSec: number;
  /** Max allowed rss linear slope after warmup (bytes/sec). */
  maxRssSlopeBytesPerSec: number;
  /** Max median(last third) − median(first third) heap growth (bytes). */
  maxHeapThirdGrowthBytes: number;
  /**
   * When ACL rows grow, allow this many extra heap bytes per new row before
   * counting toward the absolute third-growth budget.
   */
  heapBytesPerAclRowBudget: number;
  /** Require at least this many steady-state samples. */
  minSteadySamples: number;
};

export const DEFAULT_STABILITY_THRESHOLDS: StabilityThresholds = {
  warmupFraction: 0.25,
  maxHeapSlopeBytesPerSec: 64 * 1024, // 64 KiB/s sustained
  maxRssSlopeBytesPerSec: 128 * 1024, // 128 KiB/s sustained
  maxHeapThirdGrowthBytes: 48 * 1024 * 1024, // 48 MiB median shift
  heapBytesPerAclRowBudget: 2048,
  minSteadySamples: 8,
};

export function linearFit(xs: number[], ys: number[]): LinearFit {
  const n = Math.min(xs.length, ys.length);
  if (n < 2) {
    return { slopePerMs: 0, slopePerSec: 0, intercept: ys[0] ?? 0, r: 0, n };
  }
  let sumX = 0;
  let sumY = 0;
  let sumXX = 0;
  let sumYY = 0;
  let sumXY = 0;
  for (let i = 0; i < n; i++) {
    const x = xs[i]!;
    const y = ys[i]!;
    sumX += x;
    sumY += y;
    sumXX += x * x;
    sumYY += y * y;
    sumXY += x * y;
  }
  const denom = n * sumXX - sumX * sumX;
  const slopePerMs = denom === 0 ? 0 : (n * sumXY - sumX * sumY) / denom;
  const intercept = (sumY - slopePerMs * sumX) / n;
  const varX = n * sumXX - sumX * sumX;
  const varY = n * sumYY - sumY * sumY;
  const cov = n * sumXY - sumX * sumY;
  const r = varX <= 0 || varY <= 0 ? 0 : cov / Math.sqrt(varX * varY);
  return {
    slopePerMs,
    slopePerSec: slopePerMs * 1000,
    intercept,
    r,
    n,
  };
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) return (sorted[mid - 1]! + sorted[mid]!) / 2;
  return sorted[mid]!;
}

function seriesStats(values: number[]): {
  first: number;
  last: number;
  min: number;
  max: number;
  mean: number;
} {
  if (values.length === 0) {
    return { first: 0, last: 0, min: 0, max: 0, mean: 0 };
  }
  let min = values[0]!;
  let max = values[0]!;
  let sum = 0;
  for (const v of values) {
    if (v < min) min = v;
    if (v > max) max = v;
    sum += v;
  }
  return {
    first: values[0]!,
    last: values[values.length - 1]!,
    min,
    max,
    mean: sum / values.length,
  };
}

/** Analyze sampled memory for steady-state leak signals. */
export function analyzeMemoryTrend(
  samples: MemorySample[],
  thresholds: StabilityThresholds = DEFAULT_STABILITY_THRESHOLDS,
): MemoryTrendReport {
  const reasons: string[] = [];
  if (samples.length === 0) {
    return {
      samples: 0,
      steadySamples: 0,
      durationSec: 0,
      warmupSec: 0,
      heapUsed: {
        first: 0,
        last: 0,
        min: 0,
        max: 0,
        mean: 0,
        medianFirstThird: 0,
        medianLastThird: 0,
        netGrowth: 0,
        thirdGrowth: 0,
        fit: { slopePerMs: 0, slopePerSec: 0, intercept: 0, r: 0, n: 0 },
      },
      rss: {
        first: 0,
        last: 0,
        min: 0,
        max: 0,
        netGrowth: 0,
        fit: { slopePerMs: 0, slopePerSec: 0, intercept: 0, r: 0, n: 0 },
      },
      aclRows: {
        first: 0,
        last: 0,
        netGrowth: 0,
        fit: { slopePerMs: 0, slopePerSec: 0, intercept: 0, r: 0, n: 0 },
      },
      heapBytesPerAclRow: 0,
      stable: false,
      reasons: ["no samples collected"],
    };
  }

  const t0 = samples[0]!.tMs;
  const durationSec = (samples[samples.length - 1]!.tMs - t0) / 1000;
  const warmupCount = Math.min(
    samples.length - 1,
    Math.max(0, Math.floor(samples.length * thresholds.warmupFraction)),
  );
  const steady = samples.slice(warmupCount);
  const warmupSec = steady.length ? (steady[0]!.tMs - t0) / 1000 : durationSec;

  const xs = steady.map((s) => s.tMs - t0);
  const heapYs = steady.map((s) => s.memory.heapUsed);
  const rssYs = steady.map((s) => s.memory.rss);
  const aclYs = steady.map((s) => s.resources.aclRows);

  const heapFit = linearFit(xs, heapYs);
  const rssFit = linearFit(xs, rssYs);
  const aclFit = linearFit(xs, aclYs);
  const heapBasic = seriesStats(heapYs);
  const rssBasic = seriesStats(rssYs);
  const aclBasic = seriesStats(aclYs);

  const third = Math.max(1, Math.floor(steady.length / 3));
  const medianFirstThird = median(heapYs.slice(0, third));
  const medianLastThird = median(heapYs.slice(Math.max(0, steady.length - third)));
  const thirdGrowth = medianLastThird - medianFirstThird;
  const aclGrowth = Math.max(0, aclBasic.last - aclBasic.first);
  const heapBudgetFromAcl = aclGrowth * thresholds.heapBytesPerAclRowBudget;
  const unexplainedThirdGrowth = thirdGrowth - heapBudgetFromAcl;
  const heapNetGrowth = heapBasic.last - heapBasic.first;
  const heapBytesPerAclRow =
    aclGrowth === 0
      ? heapNetGrowth > 0
        ? Number.POSITIVE_INFINITY
        : 0
      : heapNetGrowth / aclGrowth;

  if (steady.length < thresholds.minSteadySamples) {
    reasons.push(`insufficient steady samples (${steady.length} < ${thresholds.minSteadySamples})`);
  }
  if (heapFit.slopePerSec > thresholds.maxHeapSlopeBytesPerSec) {
    reasons.push(
      `heapUsed slope ${formatBytes(heapFit.slopePerSec)}/s exceeds ${formatBytes(thresholds.maxHeapSlopeBytesPerSec)}/s`,
    );
  }
  if (rssFit.slopePerSec > thresholds.maxRssSlopeBytesPerSec) {
    reasons.push(
      `rss slope ${formatBytes(rssFit.slopePerSec)}/s exceeds ${formatBytes(thresholds.maxRssSlopeBytesPerSec)}/s`,
    );
  }
  if (unexplainedThirdGrowth > thresholds.maxHeapThirdGrowthBytes) {
    reasons.push(
      `unexplained heap median shift ${formatBytes(unexplainedThirdGrowth)} exceeds ${formatBytes(thresholds.maxHeapThirdGrowthBytes)} (aclRows +${aclGrowth}, budget ${formatBytes(heapBudgetFromAcl)})`,
    );
  }

  return {
    samples: samples.length,
    steadySamples: steady.length,
    durationSec,
    warmupSec,
    heapUsed: {
      ...heapBasic,
      medianFirstThird,
      medianLastThird,
      netGrowth: heapBasic.last - heapBasic.first,
      thirdGrowth,
      fit: heapFit,
    },
    rss: {
      ...rssBasic,
      netGrowth: rssBasic.last - rssBasic.first,
      fit: rssFit,
    },
    aclRows: {
      first: aclBasic.first,
      last: aclBasic.last,
      netGrowth: aclBasic.last - aclBasic.first,
      fit: aclFit,
    },
    heapBytesPerAclRow,
    stable: reasons.length === 0,
    reasons,
  };
}

export function formatTrendReport(report: MemoryTrendReport, label = "memory trend"): string {
  const lines = [
    `=== ${label} ===`,
    `samples:              ${report.samples} (steady ${report.steadySamples})`,
    `duration_sec:         ${report.durationSec.toFixed(1)} (warmup ${report.warmupSec.toFixed(1)})`,
    `heap_used first/last: ${formatBytes(report.heapUsed.first)} → ${formatBytes(report.heapUsed.last)} (Δ ${formatBytes(report.heapUsed.netGrowth)})`,
    `heap_used min/max:    ${formatBytes(report.heapUsed.min)} / ${formatBytes(report.heapUsed.max)}`,
    `heap_used slope:      ${formatBytes(report.heapUsed.fit.slopePerSec)}/s (r=${report.heapUsed.fit.r.toFixed(3)})`,
    `heap_used 1st→3rd med:${formatBytes(report.heapUsed.medianFirstThird)} → ${formatBytes(report.heapUsed.medianLastThird)} (Δ ${formatBytes(report.heapUsed.thirdGrowth)})`,
    `rss first/last:       ${formatBytes(report.rss.first)} → ${formatBytes(report.rss.last)} (Δ ${formatBytes(report.rss.netGrowth)})`,
    `rss slope:            ${formatBytes(report.rss.fit.slopePerSec)}/s (r=${report.rss.fit.r.toFixed(3)})`,
    `acl_rows first/last:  ${report.aclRows.first} → ${report.aclRows.last} (Δ ${report.aclRows.netGrowth})`,
    `heap_per_acl_row:     ${Number.isFinite(report.heapBytesPerAclRow) ? formatBytes(report.heapBytesPerAclRow) : "n/a"}`,
    `stable:               ${report.stable ? "yes" : "NO"}`,
  ];
  if (report.reasons.length) {
    lines.push(`reasons:`);
    for (const r of report.reasons) lines.push(`  - ${r}`);
  }
  return lines.join("\n");
}

export function sampleFromProfile(snap: ProfileSnapshot, tMs: number): MemorySample | null {
  if (!snap.memory || !snap.resources) return null;
  return {
    tMs,
    at: new Date().toISOString(),
    memory: snap.memory,
    resources: snap.resources,
    requests: snap.requests,
  };
}

/** Scrape one memory sample from the PROFILE probe (null when disabled). */
export async function scrapeMemorySample(
  tMs = performance.now(),
  baseUrl = PROXY,
): Promise<MemorySample | null> {
  const snap = await fetchServerProfile(baseUrl);
  if (!snap) return null;
  return sampleFromProfile(snap, tMs);
}

/** Request optional V8 GC via the PROFILE probe. */
export async function requestServerGc(baseUrl = PROXY): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl}/_couch-auth-proxy/profile/gc`, { method: "POST" });
    if (!res.ok) return false;
    const body = (await res.json()) as { gc?: boolean };
    return body.gc === true;
  } catch {
    return false;
  }
}

export async function memoryEndpointReady(baseUrl = PROXY): Promise<boolean> {
  if (!(await profileEndpointAvailable(baseUrl))) return false;
  const sample = await scrapeMemorySample(performance.now(), baseUrl);
  return sample !== null;
}

export { formatBytes, formatMemorySnapshot };
