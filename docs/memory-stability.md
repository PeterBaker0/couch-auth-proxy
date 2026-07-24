# Memory stability report

Generated: 2026-07-24T22:24:16.881Z  
Branch / harness: `feat/memory-stability-perf-38c4` via `pnpm test:perf:memory`  
Proxy: compose profile overlay (`PROFILE=true`, `NODE_OPTIONS=--expose-gc`)

## Verdict

**STABLE — no evidence of a memory leak**

- V8 `heapUsed` was flat-to-down over a 5-minute steady-state ACL load (net **−1.55 MiB**).
- In-process ACL map size plateaued (`acl_rows` **504 → 504**), so cache growth does not explain any residual process size change.
- Linear heap slope after warmup was **~0.45 KiB/s** with weak correlation (**r = 0.094**) — consistent with GC sawtooth, not a leak.
- Median heap in the last third of the steady window was only **~200 KiB** above the first third.
- RSS rose modestly (**+9.6 MiB**, ~48 KiB/s, r = 0.988) while heap declined. That pattern matches native allocator retention / freelist growth under sustained HTTP, not retained JavaScript objects. Slope remained under the soak threshold (128 KiB/s).

## Load (steady-state)

| Metric                  | Value                                      |
| ----------------------- | ------------------------------------------ |
| duration                | 302.8 s                                    |
| clients                 | 6                                          |
| seed docs               | 300                                        |
| samples                 | 150 (2 s interval; 25% warmup discarded)   |
| ops                     | 185,926 (613.9 ops/s)                      |
| docs read / written     | 600,998 / 37,188                           |
| error rate              | 0.00%                                      |
| latency p50 / p95 / p99 | 7.0 / 24.8 / 31.2 ms                       |
| forced GC samples       | yes (`POST /_couch-auth-proxy/profile/gc`) |

Workload reuses rotating document slots and a fixed mixed-ACL corpus so the ACL row count plateaus while still exercising auth, ACL lookup, `_bulk_get` filtering, and writes.

## Memory trend (steady state)

| Signal                      | Value                             |
| --------------------------- | --------------------------------- |
| heap_used first → last      | 16.48 → 14.93 MiB (Δ −1.55 MiB)   |
| heap_used slope             | 0.45 KiB/s (r = 0.094)            |
| heap median 1st → 3rd third | 16.27 → 16.47 MiB                 |
| rss first → last            | 217.10 → 226.73 MiB (Δ +9.63 MiB) |
| rss slope                   | 47.88 KiB/s (r = 0.988)           |
| acl_rows first → last       | 504 → 504 (Δ 0)                   |

## Method

1. Seed a fixed mixed-ACL corpus through the proxy.
2. Run concurrent HTTP readers/writers that reuse rotating document slots so the in-memory ACL map plateaus.
3. While load runs, scrape `GET /_couch-auth-proxy/profile` (opt-in `PROFILE=true`) for `process.memoryUsage()` plus ACL/session resource sizes.
4. Optionally `POST /_couch-auth-proxy/profile/gc` each sample when the proxy was started with `--expose-gc` (profile compose overlay).
5. Discard the leading warmup fraction, fit heap/rss vs time, and compare median heap in the first vs last third of the steady window. Expected ACL-row growth is budgeted; unexplained growth fails the assessment.

## Thresholds used

| Threshold                         | Value       |
| --------------------------------- | ----------- |
| max heap slope                    | 64.0 KiB/s  |
| max rss slope                     | 128.0 KiB/s |
| max unexplained heap median shift | 48.0 MiB    |
| heap budget per new ACL row       | 2048 B      |
| min steady samples                | 8           |

## How to reproduce

```bash
pnpm test:perf:memory
# longer soak:
PERF_MEMORY_DURATION_SEC=600 pnpm test:perf:memory
```

Artifacts (gitignored): `test/perf/last-memory-results.json`, `test/perf/last-memory-report.md`, `test/perf/last-memory-profile.json`.
