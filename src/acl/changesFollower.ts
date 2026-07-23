/**
 * Continuous CouchDB `_changes` follower for ACL cache invalidation.
 *
 * Sequences are treated as opaque strings (CouchDB 3.x). The follower never
 * compares seq to `_local_seq` / map stamp `s` — it only notifies by document
 * id so the cache can refetch or drop that row.
 *
 * On feed errors, `onError` is invoked so the cache can fail closed until
 * `onUp` fires after a successful reconnect.
 */
import type { AdminClient } from "../couch/adminClient.js";
import type { AclRow } from "./types.js";
import { createLogger } from "../util/log.js";

const log = createLogger("changes");

/** One change notification from the continuous feed. */
export type ChangeEvent = {
  id: string;
  /** Opaque update sequence (stringified if Couch sent a number). */
  seq: string;
  deleted?: boolean;
  /** Winning rev from the change line (used to recover ACL after delete). */
  rev?: string;
};

/** Callbacks wired by `AclCache` when starting a per-DB follower. */
export type ChangesFollowerHandlers = {
  onChange: (change: ChangeEvent) => Promise<void>;
  /** Feed connection lost / request failed — ACL must fail closed until onUp. */
  onError?: (err: unknown) => void;
  /** Continuous feed successfully opened (including after reconnect). */
  onUp?: () => void;
};

/**
 * Continuous `_changes` follower using opaque string sequences.
 * Never parses seq as a number; invalidates by document id only.
 */
export class ChangesFollower {
  private abort: AbortController | null = null;
  private since: string;
  private running = false;
  private readonly maxBackoffMs = 30_000;

  constructor(
    private readonly admin: AdminClient,
    private readonly db: string,
    private readonly handlers: ChangesFollowerHandlers,
    /** Opaque seq captured before ACL bulk load (replay mid-load changes). */
    initialSince: string = "0",
  ) {
    this.since = initialSince;
  }

  /** Whether the reconnect loop is active (may be mid-backoff). */
  get isRunning(): boolean {
    return this.running;
  }

  /** Last observed opaque sequence (for diagnostics). */
  get lastSeq(): string {
    return this.since;
  }

  /** Start the continuous feed loop (no-op if already running). */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.abort = new AbortController();
    void this.loop();
  }

  /** Abort the in-flight feed and stop reconnecting. */
  stop(): void {
    this.running = false;
    this.abort?.abort();
    this.abort = null;
  }

  /** Reconnect loop with exponential backoff up to `maxBackoffMs`. */
  private async loop(): Promise<void> {
    let backoffMs = 500;
    while (this.running) {
      try {
        await this.consumeOnce();
        backoffMs = 500;
      } catch (err) {
        if (!this.running) return;
        if ((err as Error)?.name === "AbortError") return;
        log.warn("follower error", { db: this.db, err: String(err) });
        this.handlers.onError?.(err);
        await sleep(backoffMs);
        backoffMs = Math.min(backoffMs * 2, this.maxBackoffMs);
      }
    }
  }

  /** Open one continuous feed and process NDJSON lines until it ends. */
  private async consumeOnce(): Promise<void> {
    const signal = this.abort?.signal;
    const res = await this.admin.fetch(`/${encodeURIComponent(this.db)}/_changes`, {
      query: {
        feed: "continuous",
        heartbeat: "1000",
        since: this.since,
        style: "main_only",
      },
      signal,
    });

    if (!res.ok || !res.body) {
      throw new Error(`_changes ${this.db}: ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let caughtUp = false;

    while (this.running) {
      const { done, value } = await reader.read();
      if (done) {
        throw new Error(`_changes ${this.db}: feed ended`);
      }
      buffer += decoder.decode(value, { stream: true });
      let newlineIndex: number;
      while ((newlineIndex = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newlineIndex).trim();
        buffer = buffer.slice(newlineIndex + 1);
        if (!line) {
          // Couch writes queued changes before the first heartbeat. Treat that
          // heartbeat as the catch-up barrier for the snapshot loaded earlier.
          if (!caughtUp) {
            caughtUp = true;
            this.handlers.onUp?.();
          }
          continue;
        }
        let obj: {
          id?: string;
          seq?: string | number;
          deleted?: boolean;
          last_seq?: string | number;
          changes?: Array<{ rev?: string }>;
        };
        try {
          obj = JSON.parse(line) as typeof obj;
        } catch {
          continue;
        }
        if (obj.last_seq != null) {
          this.since = String(obj.last_seq);
          continue;
        }
        if (obj.id == null || obj.seq == null) continue;
        const nextSeq = String(obj.seq);
        const rev = typeof obj.changes?.[0]?.rev === "string" ? obj.changes[0].rev : undefined;
        await this.handlers.onChange({
          id: obj.id,
          seq: nextSeq,
          deleted: !!obj.deleted,
          rev,
        });
        // Never skip a failed ACL refresh on reconnect.
        this.since = nextSeq;
      }
    }
  }
}

/** Result of fetching one ACL view row — distinguishes errors from confirmed absence. */
export type FetchAclRowResult =
  | { ok: true; row: AclRow | undefined }
  | { ok: false; status: number };

/**
 * Reload a single ACL row from the view (by doc id).
 * On HTTP/view failure returns `{ ok: false }` — callers must not treat that as
 * "no ACL" (deleting the cache entry would open writes for unknown ids).
 */
export async function fetchAclRow(
  admin: AdminClient,
  db: string,
  docId: string,
): Promise<FetchAclRowResult> {
  const res = await admin.json<{
    rows: Array<{ key: string; value?: AclRow; error?: string }>;
  }>(`/${encodeURIComponent(db)}/_design/acl/_view/acl`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ keys: [docId] }),
    query: { reduce: "false" },
  });
  if (!res.ok) return { ok: false, status: res.status };
  const row = res.body.rows?.[0];
  if (!row || row.error || row.value == null) {
    return { ok: true, row: undefined };
  }
  return { ok: true, row: row.value };
}

/** Opaque `update_seq` from DB info (starting point for follower catch-up). */
export async function fetchUpdateSeq(admin: AdminClient, db: string): Promise<string> {
  const res = await admin.json<{ update_seq?: string | number }>(`/${encodeURIComponent(db)}`);
  if (!res.ok || res.body.update_seq == null) return "0";
  return String(res.body.update_seq);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
