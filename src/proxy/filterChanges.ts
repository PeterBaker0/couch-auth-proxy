/**
 * Stream-filter Couch `_changes` responses by read ACL.
 *
 * Supports continuous (NDJSON), eventsource, and normal/longpoll JSON feeds.
 * Opaque `seq` / `last_seq` values pass through unchanged. Heartbeats and
 * non-change control lines are forwarded so clients keep the feed alive.
 *
 * Cold ACL-cache misses are warmed via `ensureDocRows` before authorize — a
 * missing in-memory row must not drop a live change that the principal can
 * read once the view/`_all_docs` reconcile catches up. Continuous feeds never
 * redeliver a seq, so deny-on-cold would permanently hide the document.
 */
import type { Principal } from "../auth/types.js";
import type { AclCache, DbAclState } from "../acl/cache.js";
import { canRead, ensureDocRows } from "../acl/lookup.js";
import { BodyTooLargeError, limitBytes } from "../util/limitStream.js";
import { createLogger, isLevelEnabled } from "../util/log.js";
import { addProfileMs } from "../util/profile.js";

const log = createLogger("filter-changes");
const textEncoder = new TextEncoder();

type ChangeLine = {
  id?: string;
  seq?: string | number;
  changes?: unknown[];
  deleted?: boolean;
  doc?: { _id?: string };
  last_seq?: string | number;
  pending?: number;
};

export type FilterChangesOptions = {
  /** Cap for buffered normal/longpoll JSON bodies (default: 50 MiB). */
  maxBufferBytes?: number;
};

/**
 * Stream-filter a Couch `_changes` response for the given feed style.
 *
 * `cache` is required so missing ACL rows can be warmed before sync `canRead`.
 */
export function filterChangesStream(
  upstream: ReadableStream<Uint8Array>,
  cache: AclCache,
  state: DbAclState,
  principal: Principal,
  feed: string,
  options?: FilterChangesOptions,
): ReadableStream<Uint8Array> {
  const mode = normalizeFeed(feed);
  if (isLevelEnabled("verbose")) {
    log.verbose("filterChangesStream", {
      db: state.name,
      user: principal.name,
      feed: mode,
    });
  }
  const maxBytes = options?.maxBufferBytes ?? 50 * 1024 * 1024;
  if (mode === "continuous" || mode === "eventsource") {
    return filterLineFeed(upstream, cache, state, principal, mode === "eventsource", maxBytes);
  }
  return filterJsonChanges(upstream, cache, state, principal, maxBytes);
}

function normalizeFeed(feed: string): string {
  const normalized = (feed || "normal").toLowerCase();
  if (
    normalized === "continuous" ||
    normalized === "live" ||
    normalized === "eventsource" ||
    normalized === "longpoll" ||
    normalized === "normal"
  ) {
    return normalized === "live" ? "continuous" : normalized;
  }
  return "normal";
}

/** True when sync `canRead` would hit the missing-row create path. */
function needsAclWarm(state: DbAclState, principal: Principal, docId: string): boolean {
  if (principal.admin || state.noacl) return false;
  if (!docId || typeof docId !== "string") return false;
  return !state.acl.has(docId);
}

/** Collect document ids from continuous / SSE lines that still need a warm. */
function collectMissingIdsFromLines(
  lines: string[],
  eventsource: boolean,
  state: DbAclState,
  principal: Principal,
): string[] {
  const missing: string[] = [];
  for (const rawLine of lines) {
    const id = changeIdFromLine(rawLine, eventsource);
    if (id && needsAclWarm(state, principal, id)) missing.push(id);
  }
  return missing;
}

function changeIdFromLine(rawLine: string, eventsource: boolean): string | null {
  const line = rawLine.replace(/\r$/, "");
  if (!line.trim()) return null;
  let payload = line;
  if (eventsource) {
    if (!line.startsWith("data:")) return null;
    payload = line.slice(5).trim();
    if (!payload) return null;
  }
  try {
    const obj = JSON.parse(payload) as ChangeLine;
    if (typeof obj.id === "string" && obj.id) return obj.id;
  } catch {
    // ignore malformed — processLine drops them
  }
  return null;
}

/**
 * Filter continuous NDJSON or Server-Sent Events line-by-line with backpressure.
 * Missing ACL rows in each read chunk are batched through `ensureDocRows` before
 * sync filtering so a cold cache cannot permanently drop a continuous seq.
 */
function filterLineFeed(
  upstream: ReadableStream<Uint8Array>,
  cache: AclCache,
  state: DbAclState,
  principal: Principal,
  eventsource: boolean,
  maxBufferBytes: number,
): ReadableStream<Uint8Array> {
  const reader = upstream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  /** Complete lines warmed but not yet filtered (survives backpressure yields). */
  let pendingLines: string[] = [];
  let upstreamDone = false;
  /** For eventsource: only forward `id:` lines after an allowed `data:` line. */
  let lastEsDataAllowed = false;

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      while (true) {
        // Output backpressure: wait until the consumer has drained.
        while (controller.desiredSize !== null && controller.desiredSize <= 0) {
          await sleep(1);
        }

        if (pendingLines.length === 0 && !upstreamDone) {
          const { done, value } = await reader.read();
          if (done) {
            upstreamDone = true;
            if (buffer.length > 0) {
              pendingLines = [buffer];
              buffer = "";
            }
          } else {
            buffer += decoder.decode(value, { stream: true });

            // Bound incomplete-line buffer (malformed/huge lines).
            if (buffer.length > maxBufferBytes && !buffer.includes("\n")) {
              controller.error(new BodyTooLargeError(maxBufferBytes));
              void reader.cancel();
              return;
            }

            const completeLines: string[] = [];
            let newlineIndex: number;
            while ((newlineIndex = buffer.indexOf("\n")) >= 0) {
              completeLines.push(buffer.slice(0, newlineIndex));
              buffer = buffer.slice(newlineIndex + 1);
            }
            pendingLines = completeLines;
          }

          if (pendingLines.length > 0) {
            const tWarm = performance.now();
            try {
              await warmMissingForLines(pendingLines, eventsource);
            } catch (err) {
              addProfileMs("filter", performance.now() - tWarm);
              controller.error(err);
              void reader.cancel();
              return;
            }
            addProfileMs("filter", performance.now() - tWarm);
          }
        }

        if (pendingLines.length === 0) {
          if (upstreamDone) {
            controller.close();
            return;
          }
          continue;
        }

        const t0 = performance.now();
        let enqueued = false;
        while (pendingLines.length > 0) {
          const rawLine = pendingLines.shift()!;
          const out = processLine(rawLine, eventsource);
          if (out != null) {
            controller.enqueue(textEncoder.encode(out + "\n"));
            enqueued = true;
            // Yield after an allowed line so desiredSize can apply backpressure.
            // Remaining pendingLines stay queued for the next pull.
            if (controller.desiredSize !== null && controller.desiredSize <= 0) {
              addProfileMs("filter", performance.now() - t0);
              return;
            }
          }
        }
        addProfileMs("filter", performance.now() - t0);
        if (enqueued) return;
        if (upstreamDone) {
          controller.close();
          return;
        }
      }

      async function warmMissingForLines(lines: string[], es: boolean): Promise<void> {
        const missing = collectMissingIdsFromLines(lines, es, state, principal);
        if (missing.length === 0) return;
        if (isLevelEnabled("verbose")) {
          log.verbose("changes-cache-miss-warm", {
            db: state.name,
            user: principal.name,
            count: missing.length,
            feed: es ? "eventsource" : "continuous",
          });
        }
        await ensureDocRows(cache, state, missing);
      }

      function processLine(rawLine: string, es: boolean): string | null {
        const line = rawLine.replace(/\r$/, "");
        if (!line.trim()) return line; // heartbeat

        if (es) {
          if (line.startsWith(":") || line.startsWith("event:") || line.startsWith("retry:")) {
            return line;
          }
          if (line.startsWith("id:")) {
            if (!lastEsDataAllowed) return null;
            lastEsDataAllowed = false;
            return line;
          }
          if (line.startsWith("data:")) {
            const payload = line.slice(5).trim();
            if (!payload) return line;
            const allowed = allowChangeJson(payload, state, principal);
            lastEsDataAllowed = allowed;
            return allowed ? line : null;
          }
          // Unknown SSE fields: drop (fail closed) rather than forward.
          return null;
        }

        // continuous NDJSON
        try {
          const obj = JSON.parse(line) as ChangeLine;
          // A pure last_seq row is control metadata. If Couch (or a compatible
          // upstream) includes an id too, it is still a document change and
          // must pass the ACL check.
          if (obj.id == null) return obj.last_seq != null ? line : null;
          if (typeof obj.id !== "string") return null;
          if (!canRead(state, principal, obj.id)) {
            if (
              isLevelEnabled("verbose") &&
              !state.acl.has(obj.id) &&
              !principal.admin &&
              !state.noacl
            ) {
              log.verbose("missing-row-deny-after-ensure", {
                db: state.name,
                user: principal.name,
                docId: obj.id,
                stillMissing: true,
              });
            }
            return null;
          }
          return line;
        } catch {
          // Malformed change lines: drop (fail closed).
          return null;
        }
      }
    },
    cancel() {
      void reader.cancel();
    },
  });
}

/** Buffer a normal/longpoll JSON `_changes` body, filter `results`, re-encode. */
function filterJsonChanges(
  upstream: ReadableStream<Uint8Array>,
  cache: AclCache,
  state: DbAclState,
  principal: Principal,
  maxBytes: number,
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        const text = await new Response(limitBytes(upstream, maxBytes)).text();
        const t0 = performance.now();
        let body: {
          results?: ChangeLine[];
          last_seq?: unknown;
          pending?: unknown;
          [k: string]: unknown;
        };
        try {
          body = JSON.parse(text) as typeof body;
        } catch {
          // Non-JSON body: do not forward opaque payloads.
          controller.error(new Error("invalid _changes JSON"));
          return;
        }
        const upstreamResults = body.results ?? [];
        const ids = upstreamResults
          .map((row) => row.id)
          .filter((id): id is string => typeof id === "string" && id.length > 0);
        const missing = ids.filter((id) => needsAclWarm(state, principal, id));
        if (missing.length > 0) {
          if (isLevelEnabled("verbose")) {
            log.verbose("changes-cache-miss-warm", {
              db: state.name,
              user: principal.name,
              count: missing.length,
              feed: "normal",
            });
          }
          await ensureDocRows(cache, state, missing);
        }
        const results = upstreamResults.filter((row) => {
          // Fail closed: only forward changes with a readable document id.
          if (!row.id || typeof row.id !== "string") return false;
          const allowed = canRead(state, principal, row.id);
          if (
            !allowed &&
            isLevelEnabled("verbose") &&
            !state.acl.has(row.id) &&
            !principal.admin &&
            !state.noacl
          ) {
            log.verbose("missing-row-deny-after-ensure", {
              db: state.name,
              user: principal.name,
              docId: row.id,
              stillMissing: true,
            });
          }
          return allowed;
        });
        if (isLevelEnabled("verbose")) {
          log.verbose("filterJsonChanges", {
            db: state.name,
            user: principal.name,
            upstream: upstreamResults.length,
            kept: results.length,
            dropped: upstreamResults.length - results.length,
            warmed: missing.length,
          });
        }
        const out = JSON.stringify({ ...body, results });
        controller.enqueue(textEncoder.encode(out));
        addProfileMs("filter", performance.now() - t0);
        controller.close();
      } catch (err) {
        controller.error(err);
      }
    },
  });
}

/** Parse a change JSON payload and decide whether the principal may see it. */
function allowChangeJson(payload: string, state: DbAclState, principal: Principal): boolean {
  try {
    const obj = JSON.parse(payload) as ChangeLine;
    if (obj.id == null) return obj.last_seq != null;
    if (typeof obj.id !== "string" || !obj.id) return false;
    return canRead(state, principal, obj.id);
  } catch {
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
