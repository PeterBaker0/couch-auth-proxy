/**
 * In-memory per-database ACL cache with continuous `_changes` invalidation.
 *
 * Lifecycle for each DB:
 * 1. Ensure / migrate `_design/acl` (or mark `noacl` / missing)
 * 2. Capture opaque `update_seq`, bulk-load the ACL view
 * 3. Start a `ChangesFollower` from that seq (replays mid-load writes)
 * 4. On each change: refresh the row (keep last ACL on delete for tombstones);
 *    reload on `_design/acl` edits
 *
 * Fail-closed rules:
 * - View/admin failures never open the DB via `noacl`
 * - `requireReady` throws while the follower is down (stale risk)
 * - System DBs never get auto-installed ACL ddocs
 */
import type { AppConfig } from "../config.js";
import type { AclRow, DbAclOverlay, RestrictMap } from "./types.js";
import { buildAclDesignDoc } from "./ddoc.js";
import { aclRowFromDoc } from "./resolve.js";
import { AdminClient } from "../couch/adminClient.js";
import { ChangesFollower, fetchAclRow, fetchUpdateSeq } from "./changesFollower.js";
import { isSystemDatabase } from "./names.js";
import { compileRestrict, type CompiledRestrict } from "./restrict.js";
import { createLogger } from "../util/log.js";

type EnsureDdocResult =
  /** Database does not exist upstream */
  | { kind: "missing" }
  /** `_design/acl` is present (or was just installed) */
  | { kind: "present" }
  /** DB exists but has no ACL ddoc and we will not install one */
  | { kind: "absent" };

const log = createLogger("acl-cache");

/** Mutable per-DB ACL state held in the process. */
export type DbAclState = {
  name: string;
  /** docId → ACL row */
  acl: Map<string, AclRow>;
  dbacl?: DbAclOverlay;
  restrict?: RestrictMap;
  compiledRestrict?: CompiledRestrict;
  /** true when bucket has no usable ACL ddoc — pass-through Couch behavior */
  noacl: boolean;
  ready: boolean;
  /** Last ensure/load failure message — callers must fail closed */
  error?: string;
  /** DB does not exist upstream */
  missing?: boolean;
  follower?: ChangesFollower;
  /** false while reconnecting — `requireReady` fails closed */
  followerUp: boolean;
};

/**
 * In-memory per-DB ACL cache with continuous `_changes` invalidation-by-id.
 *
 * CouchDB 3.5 notes:
 * - `since` / seq are opaque strings
 * - Never compare seq to `_local_seq`
 * - On each change, refetch that doc's ACL row (retain last grants on delete)
 */
export class AclCache {
  private readonly dbs = new Map<string, DbAclState>();
  private readonly admin: AdminClient;
  /** Coalesce concurrent `ensureDb` calls for the same name. */
  private readonly inflight = new Map<string, Promise<DbAclState>>();
  private stopped = false;

  constructor(private readonly config: AppConfig) {
    this.admin = new AdminClient(config);
  }

  /** Admin client used by readiness probes and tests. */
  get adminClient(): AdminClient {
    return this.admin;
  }

  /** Return cached state if present (may be incomplete / not ready). */
  get(db: string): DbAclState | undefined {
    return this.dbs.get(db);
  }

  /** All DB states (for readiness reporting). */
  all(): IterableIterator<DbAclState> {
    return this.dbs.values();
  }

  /**
   * Ensure ACL state for `db` is loaded (or return existing ready state).
   * Concurrent callers share one in-flight load promise.
   */
  async ensureDb(db: string): Promise<DbAclState> {
    if (this.stopped) {
      return {
        name: db,
        acl: new Map(),
        noacl: false,
        ready: false,
        followerUp: false,
        error: "acl cache stopped",
      };
    }

    const existing = this.dbs.get(db);
    if (existing?.ready && !existing.error) return existing;

    const pending = this.inflight.get(db);
    if (pending) return pending;

    const work = this.loadDb(db);
    this.inflight.set(db, work);
    try {
      return await work;
    } finally {
      this.inflight.delete(db);
    }
  }

  /** Warm caches for configured DBs at boot (errors logged, not thrown). */
  async preload(dbs: string[]): Promise<void> {
    await Promise.all(
      dbs.map(async (db) => {
        try {
          await this.ensureDb(db);
        } catch (err) {
          log.error("preload failed", { db, err: String(err) });
        }
      }),
    );
  }

  /** Stop all followers (process shutdown). Further ensures fail closed. */
  stop(): void {
    this.stopped = true;
    for (const state of this.dbs.values()) {
      state.follower?.stop();
      state.followerUp = false;
    }
  }

  /** On-demand ACL row refresh (opaque-seq safe; keyed by doc id). */
  async refreshDoc(db: string, docId: string): Promise<void> {
    const state = this.dbs.get(db);
    if (!state || state.noacl) return;
    const result = await fetchAclRow(this.admin, db, docId);
    if (!result.ok) {
      log.warn("refreshDoc view fetch failed; leaving cache unchanged", {
        db,
        docId,
        status: result.status,
      });
      return;
    }
    if (result.row) state.acl.set(docId, result.row);
    // Confirmed absence: leave missing (create path); do not invent a row.
  }

  /**
   * Return a ready ACL state or throw.
   * Throws `DbMissingError` / `AclUnavailableError` — actors map these to HTTP.
   */
  async requireReady(db: string): Promise<DbAclState> {
    const state = await this.ensureDb(db);
    if (state.missing) {
      throw new DbMissingError(db);
    }
    if (!state.ready || state.error) {
      throw new AclUnavailableError(state.error ?? "ACL cache not ready");
    }
    // Fail closed while the changes follower is down — cache may be stale.
    if (!state.noacl && !state.followerUp) {
      throw new AclUnavailableError("ACL changes follower unavailable");
    }
    return state;
  }

  /** Load or reload one DB: ddoc ensure → bulk view → follower. */
  private async loadDb(db: string): Promise<DbAclState> {
    const state: DbAclState = this.dbs.get(db) ?? {
      name: db,
      acl: new Map(),
      noacl: false,
      ready: false,
      followerUp: false,
    };
    this.dbs.set(db, state);

    try {
      const ddoc = await this.ensureAclDdoc(db);
      if (ddoc.kind === "missing") {
        state.ready = false;
        state.missing = true;
        state.error = `db missing: ${db}`;
        state.noacl = false;
        state.followerUp = false;
        return state;
      }
      if (ddoc.kind === "absent") {
        // No couch-auth-proxy ACL ddoc — pass through to Couch `_security` only.
        state.noacl = true;
        state.acl.clear();
        state.dbacl = undefined;
        state.restrict = undefined;
        state.compiledRestrict = undefined;
        state.ready = true;
        state.missing = false;
        state.error = undefined;
        state.followerUp = true;
        state.follower?.stop();
        state.follower = undefined;
        return state;
      }

      // Capture seq before bulk load so the follower replays mid-load changes.
      const since = await fetchUpdateSeq(this.admin, db);
      await this.loadAll(db, state);
      state.ready = true;
      state.missing = false;
      state.error = undefined;
      this.startFollower(db, state, since);
      return state;
    } catch (err) {
      state.ready = false;
      state.error = String(err);
      state.noacl = false;
      state.followerUp = false;
      log.error("ensureDb failed", { db, err: String(err) });
      return state;
    }
  }

  /**
   * Ensure `_design/acl` exists, migrate legacy stamps, or decide pass-through.
   * Never auto-installs into system DBs; respects `aclAutoInstall`.
   */
  private async ensureAclDdoc(db: string): Promise<EnsureDdocResult> {
    const get = await this.admin.fetch(`/${encodeURIComponent(db)}/_design/acl`);
    if (get.status === 200) {
      await this.maybeMigrateStamp(db, get);
      return { kind: "present" };
    }
    if (get.status === 404) {
      const dbHead = await this.admin.fetch(`/${encodeURIComponent(db)}`);
      if (dbHead.status === 404) return { kind: "missing" };

      // Never mutate system DBs. Optional: skip install when ACL_AUTO_INSTALL=false.
      if (isSystemDatabase(db) || !this.config.couch.aclAutoInstall) {
        log.info("ACL ddoc absent; pass-through (no auto-install)", {
          db,
          system: isSystemDatabase(db),
          aclAutoInstall: this.config.couch.aclAutoInstall,
        });
        return { kind: "absent" };
      }

      const put = await this.admin.fetch(`/${encodeURIComponent(db)}/_design/acl`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildAclDesignDoc()),
      });
      if (!put.ok) {
        const text = await put.text();
        throw new Error(`Failed to install _design/acl in ${db}: ${put.status} ${text}`);
      }
      return { kind: "present" };
    }
    if (get.status === 401 || get.status === 403) {
      throw new Error(`Admin auth failed reading _design/acl in ${db}`);
    }
    throw new Error(`Failed to read _design/acl in ${db}: ${get.status}`);
  }

  /** Migrate legacy map that stamped `s` from `_local_seq` → `_rev`. */
  private async maybeMigrateStamp(db: string, getRes: Response): Promise<void> {
    const ddoc = (await getRes.json()) as {
      _rev?: string;
      version?: string;
      views?: { acl?: { map?: string } };
    };
    const mapSrc = ddoc.views?.acl?.map ?? "";
    const usesLocalSeq = /_local_seq/.test(mapSrc) && !/doc\._rev/.test(mapSrc);
    const alreadyV2 = typeof ddoc.version === "string" && ddoc.version.startsWith("2.");
    if (!usesLocalSeq || alreadyV2) return;

    const next = buildAclDesignDoc("2.0.0");
    const put = await this.admin.fetch(`/${encodeURIComponent(db)}/_design/acl`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...next, _rev: ddoc._rev }),
    });
    if (!put.ok) {
      log.warn("ddoc migrate skipped", { db, status: put.status });
    } else {
      log.info("migrated _design/acl stamp to _rev", { db });
    }
  }

  /** Load dbacl/restrict + all ACL view rows into `state`. */
  private async loadAll(db: string, state: DbAclState): Promise<void> {
    const ddocRes = await this.admin.json<{
      dbacl?: DbAclOverlay;
      restrict?: RestrictMap;
      views?: { acl?: { map?: string } };
    }>(`/${encodeURIComponent(db)}/_design/acl`);

    if (!ddocRes.ok) {
      throw new Error(`Failed to read _design/acl body in ${db}: ${ddocRes.status}`);
    }

    const ddoc = ddocRes.body;
    state.dbacl = ddoc.dbacl;
    state.restrict = ddoc.restrict;
    state.compiledRestrict = compileRestrict(ddoc.restrict);

    // Intentional pass-through only when the ddoc has no ACL map function.
    if (!ddoc.views?.acl?.map) {
      state.noacl = true;
      state.acl.clear();
      return;
    }

    const res = await this.admin.json<{
      rows: Array<{ id: string; key: string; value: AclRow }>;
    }>(`/${encodeURIComponent(db)}/_design/acl/_view/acl`, {
      query: { reduce: "false", include_docs: "false" },
    });

    if (!res.ok) {
      throw new Error(`ACL view unavailable in ${db}: ${res.status} ${res.text}`);
    }

    state.acl.clear();
    for (const row of res.body.rows ?? []) {
      state.acl.set(String(row.key ?? row.id), row.value);
    }
    state.noacl = false;
  }

  /** Attach (or replace) the continuous changes follower for an ACL-backed DB. */
  private startFollower(db: string, state: DbAclState, since: string): void {
    if (state.noacl) {
      state.followerUp = true;
      return;
    }
    state.follower?.stop();
    const follower = new ChangesFollower(
      this.admin,
      db,
      {
        onChange: async (change) => {
          await this.applyChange(db, state, change.id, change.deleted, change.rev);
        },
        onError: () => {
          state.followerUp = false;
        },
        onUp: () => {
          state.followerUp = true;
        },
      },
      since,
    );
    state.follower = follower;
    // Fail closed until the feed actually opens (onUp).
    state.followerUp = false;
    follower.start();
  }

  /**
   * Apply one change event: refresh a single doc, reload ddoc, or handle delete.
   *
   * On document delete we **keep** the last known ACL row. Dropping it would make
   * `_changes` tombstones invisible to principals who previously had read access
   * (Pouch/Couch replicas would never learn the doc was removed). The row is
   * replaced on recreate via the normal refresh path. If the cache was cold
   * (e.g. after restart), recover grants from the pre-delete revision.
   */
  private async applyChange(
    db: string,
    state: DbAclState,
    id: string,
    deleted?: boolean,
    rev?: string,
  ): Promise<void> {
    if (deleted) {
      if (id === "_design/acl") {
        state.acl.delete(id);
        try {
          await this.loadAll(db, state);
        } catch (err) {
          state.ready = false;
          state.error = String(err);
          state.noacl = false;
          log.warn("reload after acl ddoc delete failed", { db, err: String(err) });
        }
        return;
      }
      if (!state.acl.has(id)) {
        const recovered = await this.recoverAclFromDeletedDoc(db, id, rev);
        if (recovered) state.acl.set(id, recovered);
      }
      // Retain last ACL grants for tombstone visibility on user _changes feeds.
      return;
    }

    if (id === "_design/acl") {
      try {
        await this.loadAll(db, state);
        state.error = undefined;
        state.ready = true;
      } catch (err) {
        state.ready = false;
        state.error = String(err);
        state.noacl = false;
        log.warn("reload acl ddoc failed", { db, err: String(err) });
      }
      return;
    }

    const result = await fetchAclRow(this.admin, db, id);
    if (!result.ok) {
      // Leave previous ACL in place — deleting would open write for unknown ids.
      log.warn("applyChange view fetch failed; leaving cache unchanged", {
        db,
        id,
        status: result.status,
      });
      return;
    }
    if (result.row) state.acl.set(id, result.row);
    else state.acl.delete(id);
  }

  /**
   * After a delete, the ACL view no longer emits the doc. Recover grants from
   * the pre-delete revision body (via `_revisions`) so tombstones stay
   * visible to prior readers even when the in-memory row was never loaded.
   */
  private async recoverAclFromDeletedDoc(
    db: string,
    id: string,
    deletedRev?: string,
  ): Promise<AclRow | undefined> {
    if (!deletedRev) return undefined;
    try {
      const metaRes = await this.admin.json<{
        _deleted?: boolean;
        _revisions?: { start?: number; ids?: string[] };
      }>(`/${encodeURIComponent(db)}/${encodeURIComponent(id)}`, {
        query: { rev: deletedRev, revs: "true" },
      });
      if (!metaRes.ok) return undefined;
      const start = metaRes.body._revisions?.start;
      const ids = metaRes.body._revisions?.ids;
      if (typeof start !== "number" || !ids || ids.length < 2) return undefined;
      const prevRev = `${start - 1}-${ids[1]}`;
      const prevRes = await this.admin.json<{
        _id?: string;
        creator?: string;
        owners?: string[];
        acl?: string[];
        parent?: string;
      }>(`/${encodeURIComponent(db)}/${encodeURIComponent(id)}`, {
        query: { rev: prevRev },
      });
      if (!prevRes.ok || !prevRes.body._id) return undefined;
      return aclRowFromDoc({
        _id: prevRes.body._id,
        creator: prevRes.body.creator,
        owners: prevRes.body.owners,
        acl: prevRes.body.acl,
        parent: prevRes.body.parent,
      });
    } catch (err) {
      log.warn("recover ACL from deleted doc failed", {
        db,
        id,
        err: String(err),
      });
      return undefined;
    }
  }
}

/** Thrown when ACL cache is not ready or the changes follower is down. */
export class AclUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AclUnavailableError";
  }
}

/** Thrown when the target database does not exist upstream. */
export class DbMissingError extends Error {
  constructor(public readonly db: string) {
    super(`missing db: ${db}`);
    this.name = "DbMissingError";
  }
}
