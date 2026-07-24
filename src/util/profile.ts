/**
 * Opt-in request phase profiling (`PROFILE=true`).
 *
 * When enabled, middleware installs an AsyncLocalStorage request profile and
 * hot-path helpers accumulate wall time for auth / ACL / upstream / filter.
 * Aggregated stats are exposed via `/_couch-auth-proxy/profile` for the perf
 * harness; per-request phase ms are also attached to structured access logs.
 *
 * Disabled by default — zero ALS / timer cost on the hot path when off.
 */
import { AsyncLocalStorage } from "node:async_hooks";

/** Timed phases on the ACL proxy hot path. */
export const PROFILE_PHASES = ["auth", "acl", "aclMiss", "upstream", "filter"] as const;
export type ProfilePhase = (typeof PROFILE_PHASES)[number];

export type RequestProfile = {
  phases: Record<ProfilePhase, number>;
  counts: Record<ProfilePhase, number>;
};

export type PhaseStats = {
  count: number;
  totalMs: number;
  meanMs: number;
  maxMs: number;
  /** Mean ms attributed per profiled request (totalMs / requests). */
  perRequestMeanMs: number;
};

export type ProfileSnapshot = {
  enabled: true;
  requests: number;
  startedAt: string;
  updatedAt: string;
  /** Mean end-to-end request duration among profiled requests. */
  meanDurationMs: number;
  phases: Record<ProfilePhase, PhaseStats>;
  /**
   * Share of meanDurationMs explained by each phase (may sum >1 when phases
   * overlap or when other work is unattributed — use as a relative signal).
   */
  phaseShareOfMean: Record<ProfilePhase, number>;
};

type PhaseAccum = {
  count: number;
  totalMs: number;
  maxMs: number;
};

const als = new AsyncLocalStorage<RequestProfile>();

function emptyPhases(): Record<ProfilePhase, number> {
  return { auth: 0, acl: 0, aclMiss: 0, upstream: 0, filter: 0 };
}

function emptyCounts(): Record<ProfilePhase, number> {
  return { auth: 0, acl: 0, aclMiss: 0, upstream: 0, filter: 0 };
}

/** Create an empty per-request profile bag. */
export function createRequestProfile(): RequestProfile {
  return { phases: emptyPhases(), counts: emptyCounts() };
}

/** Current request profile, if profiling is active for this async chain. */
export function currentProfile(): RequestProfile | undefined {
  return als.getStore();
}

/** Run `fn` with a fresh request profile bound to the async context. */
export function runWithProfile<T>(profile: RequestProfile, fn: () => T): T {
  return als.run(profile, fn);
}

/** Add wall-ms to a phase on the current request profile (no-op if inactive). */
export function addProfileMs(phase: ProfilePhase, ms: number): void {
  const profile = als.getStore();
  if (!profile || !(ms > 0)) return;
  profile.phases[phase] += ms;
  profile.counts[phase] += 1;
}

/** Time an async function against a profile phase (no-op overhead when inactive). */
export async function profileAsync<T>(phase: ProfilePhase, fn: () => Promise<T>): Promise<T> {
  const profile = als.getStore();
  if (!profile) return fn();
  const t0 = performance.now();
  try {
    return await fn();
  } finally {
    const ms = performance.now() - t0;
    profile.phases[phase] += ms;
    profile.counts[phase] += 1;
  }
}

/** Time a sync function against a profile phase. */
export function profileSync<T>(phase: ProfilePhase, fn: () => T): T {
  const profile = als.getStore();
  if (!profile) return fn();
  const t0 = performance.now();
  try {
    return fn();
  } finally {
    const ms = performance.now() - t0;
    profile.phases[phase] += ms;
    profile.counts[phase] += 1;
  }
}

/**
 * Process-wide aggregator for scrapeable `/_couch-auth-proxy/profile` snapshots.
 * Not a high-cardinality metrics system — meant for load-harness debugging.
 */
export class ProfileAggregator {
  private requests = 0;
  private durationTotalMs = 0;
  private readonly phases: Record<ProfilePhase, PhaseAccum> = {
    auth: { count: 0, totalMs: 0, maxMs: 0 },
    acl: { count: 0, totalMs: 0, maxMs: 0 },
    aclMiss: { count: 0, totalMs: 0, maxMs: 0 },
    upstream: { count: 0, totalMs: 0, maxMs: 0 },
    filter: { count: 0, totalMs: 0, maxMs: 0 },
  };
  private readonly startedAt = new Date().toISOString();
  private updatedAt = this.startedAt;

  record(profile: RequestProfile, durationMs: number): void {
    this.requests += 1;
    this.durationTotalMs += durationMs;
    this.updatedAt = new Date().toISOString();
    for (const phase of PROFILE_PHASES) {
      const ms = profile.phases[phase];
      if (!(ms > 0) && profile.counts[phase] === 0) continue;
      const acc = this.phases[phase]!;
      acc.count += profile.counts[phase];
      acc.totalMs += ms;
      if (ms > acc.maxMs) acc.maxMs = ms;
    }
  }

  reset(): void {
    this.requests = 0;
    this.durationTotalMs = 0;
    this.updatedAt = new Date().toISOString();
    for (const phase of PROFILE_PHASES) {
      this.phases[phase] = { count: 0, totalMs: 0, maxMs: 0 };
    }
  }

  snapshot(): ProfileSnapshot {
    const meanDurationMs = this.requests === 0 ? 0 : this.durationTotalMs / this.requests;
    const phases = {} as Record<ProfilePhase, PhaseStats>;
    const phaseShareOfMean = {} as Record<ProfilePhase, number>;
    for (const phase of PROFILE_PHASES) {
      const acc = this.phases[phase]!;
      const meanMs = acc.count === 0 ? 0 : acc.totalMs / acc.count;
      const perRequestMeanMs = this.requests === 0 ? 0 : acc.totalMs / this.requests;
      phases[phase] = {
        count: acc.count,
        totalMs: acc.totalMs,
        meanMs,
        maxMs: acc.maxMs,
        perRequestMeanMs,
      };
      phaseShareOfMean[phase] = meanDurationMs === 0 ? 0 : perRequestMeanMs / meanDurationMs;
    }
    return {
      enabled: true,
      requests: this.requests,
      startedAt: this.startedAt,
      updatedAt: this.updatedAt,
      meanDurationMs,
      phases,
      phaseShareOfMean,
    };
  }
}

/** Format a snapshot for console / harness output. */
export function formatProfileSnapshot(snap: ProfileSnapshot, label = "server profile"): string {
  const lines = [
    `=== ${label} ===`,
    `requests:          ${snap.requests}`,
    `mean_duration_ms:  ${snap.meanDurationMs.toFixed(2)}`,
  ];
  for (const phase of PROFILE_PHASES) {
    const s = snap.phases[phase];
    const share = snap.phaseShareOfMean[phase] * 100;
    lines.push(
      `${phase.padEnd(10)} per_req=${s.perRequestMeanMs.toFixed(2)}ms` +
        ` mean=${s.meanMs.toFixed(2)}ms max=${s.maxMs.toFixed(2)}ms` +
        ` count=${s.count} share=${share.toFixed(1)}%`,
    );
  }
  return lines.join("\n");
}
