/**
 * Stream-filter Couch `_changes` responses by read ACL.
 *
 * Supports continuous (NDJSON), eventsource, and normal/longpoll JSON feeds.
 * Opaque `seq` / `last_seq` values pass through unchanged. Heartbeats and
 * non-change control lines are forwarded so clients keep the feed alive.
 */
import type { Principal } from "../auth/types.js";
import type { DbAclState } from "../acl/cache.js";
import { canRead } from "../acl/lookup.js";
import { BodyTooLargeError, limitBytes } from "../util/limitStream.js";

/** Pause upstream reads when the incomplete line buffer exceeds this size. */
const HIGH_WATER_BYTES = 256 * 1024;

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
 */
export function filterChangesStream(
  upstream: ReadableStream<Uint8Array>,
  state: DbAclState,
  principal: Principal,
  feed: string,
  options?: FilterChangesOptions,
): ReadableStream<Uint8Array> {
  const mode = normalizeFeed(feed);
  if (mode === "continuous" || mode === "eventsource") {
    return filterLineFeed(upstream, state, principal, mode === "eventsource");
  }
  const maxBytes = options?.maxBufferBytes ?? 50 * 1024 * 1024;
  return filterJsonChanges(upstream, state, principal, maxBytes);
}

function normalizeFeed(feed: string): string {
  const normalized = (feed || "normal").toLowerCase();
  if (
    normalized === "continuous" ||
    normalized === "eventsource" ||
    normalized === "longpoll" ||
    normalized === "normal"
  ) {
    return normalized;
  }
  return "normal";
}

/**
 * Filter continuous NDJSON or Server-Sent Events line-by-line with backpressure.
 */
function filterLineFeed(
  upstream: ReadableStream<Uint8Array>,
  state: DbAclState,
  principal: Principal,
  eventsource: boolean,
): ReadableStream<Uint8Array> {
  const reader = upstream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  /** For eventsource: only forward `id:` lines after an allowed `data:` line. */
  let lastEsDataAllowed = false;

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      while (true) {
        // Output backpressure: wait until the consumer has drained.
        while (controller.desiredSize !== null && controller.desiredSize <= 0) {
          await sleep(10);
        }

        const { done, value } = await reader.read();
        if (done) {
          flushLine(buffer);
          controller.close();
          return;
        }
        buffer += decoder.decode(value, { stream: true });

        // Bound incomplete-line buffer (malformed/huge lines).
        if (buffer.length > HIGH_WATER_BYTES && !buffer.includes("\n")) {
          controller.error(new BodyTooLargeError(HIGH_WATER_BYTES));
          void reader.cancel();
          return;
        }

        let newlineIndex: number;
        let enqueued = false;
        while ((newlineIndex = buffer.indexOf("\n")) >= 0) {
          const rawLine = buffer.slice(0, newlineIndex);
          buffer = buffer.slice(newlineIndex + 1);
          const out = processLine(rawLine, eventsource);
          if (out != null) {
            controller.enqueue(new TextEncoder().encode(out + "\n"));
            enqueued = true;
            // Yield after an allowed line so desiredSize can apply backpressure.
            if (controller.desiredSize !== null && controller.desiredSize <= 0) {
              return;
            }
          }
        }
        if (enqueued) return;
      }

      function flushLine(line: string) {
        const out = processLine(line, eventsource);
        if (out != null) controller.enqueue(new TextEncoder().encode(out + "\n"));
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
          if (obj.last_seq != null) return line;
          // Fail closed: id-less lines (other than last_seq) are not forwarded.
          if (obj.id == null || typeof obj.id !== "string") return null;
          if (!canRead(state, principal, obj.id)) return null;
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
  state: DbAclState,
  principal: Principal,
  maxBytes: number,
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        const text = await new Response(limitBytes(upstream, maxBytes)).text();
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
        const results = (body.results ?? []).filter((row) => {
          // Fail closed: only forward changes with a readable document id.
          if (!row.id || typeof row.id !== "string") return false;
          return canRead(state, principal, row.id);
        });
        const out = JSON.stringify({ ...body, results });
        controller.enqueue(new TextEncoder().encode(out));
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
    if (obj.last_seq != null) return true;
    if (!obj.id || typeof obj.id !== "string") return false;
    return canRead(state, principal, obj.id);
  } catch {
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
