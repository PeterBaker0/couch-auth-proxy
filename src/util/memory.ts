/**
 * Opt-in process memory snapshots for `/_couch-auth-proxy/profile`.
 *
 * Only consulted when `PROFILE=true`. Cheap (`process.memoryUsage()`); no
 * allocators or heap dumps — meant for long-running load harness scrapes.
 */

/** Bytes from `process.memoryUsage()`. */
export type ProcessMemorySnapshot = {
  rss: number;
  heapTotal: number;
  heapUsed: number;
  external: number;
  arrayBuffers: number;
};

/** Bounded in-process structure sizes correlated with expected heap growth. */
export type ResourceStats = {
  aclDbs: number;
  aclRows: number;
  aclTombstones: number;
  aclInflightEnsures: number;
  aclInflightRefreshes: number;
  sessionCacheEntries: number;
  sessionInflight: number;
};

/** Capture current process memory counters. */
export function captureProcessMemory(): ProcessMemorySnapshot {
  const m = process.memoryUsage();
  return {
    rss: m.rss,
    heapTotal: m.heapTotal,
    heapUsed: m.heapUsed,
    external: m.external,
    arrayBuffers: m.arrayBuffers,
  };
}

/** Format bytes for harness / console output. */
export function formatBytes(bytes: number): string {
  const sign = bytes < 0 ? "-" : "";
  const abs = Math.abs(bytes);
  if (abs < 1024) {
    const whole = Number.isInteger(abs) ? String(abs) : abs.toFixed(1);
    return `${sign}${whole}B`;
  }
  if (abs < 1024 * 1024) return `${sign}${(abs / 1024).toFixed(1)}KiB`;
  if (abs < 1024 * 1024 * 1024) return `${sign}${(abs / (1024 * 1024)).toFixed(2)}MiB`;
  return `${sign}${(abs / (1024 * 1024 * 1024)).toFixed(2)}GiB`;
}

/** Human-readable memory + resource lines for harness logs. */
export function formatMemorySnapshot(
  memory: ProcessMemorySnapshot,
  resources?: ResourceStats,
  label = "process memory",
): string {
  const lines = [
    `=== ${label} ===`,
    `rss:           ${formatBytes(memory.rss)}`,
    `heap_used:     ${formatBytes(memory.heapUsed)}`,
    `heap_total:    ${formatBytes(memory.heapTotal)}`,
    `external:      ${formatBytes(memory.external)}`,
    `array_buffers: ${formatBytes(memory.arrayBuffers)}`,
  ];
  if (resources) {
    lines.push(
      `acl_dbs:       ${resources.aclDbs}`,
      `acl_rows:      ${resources.aclRows}`,
      `acl_tombstones:${resources.aclTombstones}`,
      `session_cache: ${resources.sessionCacheEntries}`,
      `session_inflight:${resources.sessionInflight}`,
    );
  }
  return lines.join("\n");
}

/**
 * Request a V8 GC when the process was started with `--expose-gc`.
 * Returns false when GC is unavailable (typical production / default PROFILE).
 */
export function tryForceGc(): boolean {
  const gc = (globalThis as { gc?: () => void }).gc;
  if (typeof gc !== "function") return false;
  gc();
  return true;
}
