/**
 * Lightweight ops/latency collectors for the ACL performance harness.
 */

export type LatencyStats = {
  count: number;
  minMs: number;
  maxMs: number;
  meanMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
};

export class LatencyTracker {
  private readonly samples: number[] = [];

  record(ms: number): void {
    this.samples.push(ms);
  }

  get count(): number {
    return this.samples.length;
  }

  stats(): LatencyStats {
    if (this.samples.length === 0) {
      return {
        count: 0,
        minMs: 0,
        maxMs: 0,
        meanMs: 0,
        p50Ms: 0,
        p95Ms: 0,
        p99Ms: 0,
      };
    }
    const sorted = [...this.samples].sort((a, b) => a - b);
    const sum = sorted.reduce((a, b) => a + b, 0);
    const pct = (p: number): number => {
      const idx = Math.min(
        sorted.length - 1,
        Math.max(0, Math.ceil((p / 100) * sorted.length) - 1),
      );
      return sorted[idx]!;
    };
    return {
      count: sorted.length,
      minMs: sorted[0]!,
      maxMs: sorted[sorted.length - 1]!,
      meanMs: sum / sorted.length,
      p50Ms: pct(50),
      p95Ms: pct(95),
      p99Ms: pct(99),
    };
  }
}

export type CounterSnapshot = {
  ops: number;
  errors: number;
  docsRead: number;
  docsWritten: number;
  bytesIn: number;
  bytesOut: number;
};

export class OpCounter {
  ops = 0;
  errors = 0;
  docsRead = 0;
  docsWritten = 0;
  bytesIn = 0;
  bytesOut = 0;

  add(partial: Partial<CounterSnapshot>): void {
    this.ops += partial.ops ?? 0;
    this.errors += partial.errors ?? 0;
    this.docsRead += partial.docsRead ?? 0;
    this.docsWritten += partial.docsWritten ?? 0;
    this.bytesIn += partial.bytesIn ?? 0;
    this.bytesOut += partial.bytesOut ?? 0;
  }

  merge(other: OpCounter): void {
    this.add(other.snapshot());
  }

  snapshot(): CounterSnapshot {
    return {
      ops: this.ops,
      errors: this.errors,
      docsRead: this.docsRead,
      docsWritten: this.docsWritten,
      bytesIn: this.bytesIn,
      bytesOut: this.bytesOut,
    };
  }
}

export type RateReport = CounterSnapshot & {
  durationSec: number;
  opsPerSec: number;
  docsReadPerSec: number;
  docsWrittenPerSec: number;
  syncDocsPerSec: number;
  errorRate: number;
  latency: LatencyStats;
};

export function rateReport(
  counter: OpCounter,
  latency: LatencyTracker,
  durationMs: number,
): RateReport {
  const snap = counter.snapshot();
  const durationSec = Math.max(durationMs / 1000, 1e-9);
  return {
    ...snap,
    durationSec,
    opsPerSec: snap.ops / durationSec,
    docsReadPerSec: snap.docsRead / durationSec,
    docsWrittenPerSec: snap.docsWritten / durationSec,
    syncDocsPerSec: (snap.docsRead + snap.docsWritten) / durationSec,
    errorRate: snap.ops === 0 ? 0 : snap.errors / snap.ops,
    latency: latency.stats(),
  };
}

export function formatRate(report: RateReport, label: string): string {
  const lines = [
    `=== ${label} ===`,
    `duration_sec:        ${report.durationSec.toFixed(3)}`,
    `ops:                 ${report.ops}`,
    `ops_per_sec:         ${report.opsPerSec.toFixed(2)}`,
    `docs_read:           ${report.docsRead}`,
    `docs_written:        ${report.docsWritten}`,
    `docs_read_per_sec:   ${report.docsReadPerSec.toFixed(2)}`,
    `docs_written_per_sec:${report.docsWrittenPerSec.toFixed(2)}`,
    `sync_docs_per_sec:   ${report.syncDocsPerSec.toFixed(2)}`,
    `errors:              ${report.errors}`,
    `error_rate:          ${(report.errorRate * 100).toFixed(2)}%`,
    `latency_ms p50/p95/p99: ${report.latency.p50Ms.toFixed(1)} / ${report.latency.p95Ms.toFixed(1)} / ${report.latency.p99Ms.toFixed(1)}`,
    `latency_ms mean/min/max: ${report.latency.meanMs.toFixed(1)} / ${report.latency.minMs.toFixed(1)} / ${report.latency.maxMs.toFixed(1)}`,
  ];
  return lines.join("\n");
}

/** Wall-clock timer helper. */
export async function timed<T>(fn: () => Promise<T>): Promise<{ value: T; ms: number }> {
  const t0 = performance.now();
  const value = await fn();
  return { value, ms: performance.now() - t0 };
}
