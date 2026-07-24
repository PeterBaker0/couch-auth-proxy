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
import { ACL_MAP_SOURCE, buildAclDesignDoc } from "./ddoc.js";
import { aclRowFromDoc } from "./resolve.js";
import { AdminClient } from "../couch/adminClient.js";
import { ChangesFollower, fetchAclRow, fetchUpdateSeq } from "./changesFollower.js";
import { isSystemDatabase } from "./names.js";
import { compileRestrict, type CompiledRestrict } from "./restrict.js";
import { createLogger, isLevelEnabled } from "../util/log.js";

type EnsureDdocResult =
  /** Database does not exist upstream */
  | { kind: "missing" }
  /** `_design/acl` is present (or was just installed) */
  | { kind: "present" }
  /** DB exists but has no ACL ddoc and we will not install one */
  | { kind: "absent" };

const log = createLogger("acl-cache");
const ACL_VIEW_PAGE_SIZE = 2_000;
const ACL_RECOVERY_CONCURRENCY = 16;

/** Mutable per-DB ACL state held in the process. */
export type DbAclState = {
  name: string;
  /** docId → ACL row */
  acl: Map<string, AclRow>;
  /** Deleted ids whose retained rows authorize replication tombstones. */
  tombstones?: Set<string>;
  /** Whether current deleted winners were reconstructed after process start. */
  tombstonesLoaded?: boolean;
  /** Exact map source used to build `acl`; detects policy-map changes. */
  aclMapSource?: string;
  /** Whether historical rows can be reconstructed with `aclRowFromDoc`. */
  generatedAclMap?: boolean;
  dbacl?: DbAclOverlay;
  restrict?: RestrictMap;
  compiledRestrict?: CompiledRestrict;
  /** true when bucket has no usable ACL ddoc — pass-through Couch behavior */
  noacl: boolean;
  ready: boolean;
  /** True while a design-document policy snapshot is rebuilding. */
  reloading?: boolean;
  /** Last ensure/load failure message — callers must fail closed */
  error?: string;
  /** DB does not exist upstream */
  missing?: boolean;
  follower?: ChangesFollower;
  /** false while reconnecting — `requireReady` fails closed */
  followerUp: boolean;
};

/** Read-only policy needed to decide whether a DB is visible in `/_all_dbs`. */
export type DbAccessPolicy = {
  noacl: boolean;
  compiledRestrict?: CompiledRestrict;
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
   * Read only the bucket policy needed by `/_all_dbs`.
   *
   * Unlike `ensureDb`, this never installs `_design/acl`, starts a follower, or
   * stores a no-ACL state. A metadata listing must not mutate every database it
   * happens to enumerate.
   */
  async inspectAccessPolicy(db: string): Promise<DbAccessPolicy> {
    const existing = this.dbs.get(db);
    if (existing?.ready && !existing.error) {
      if (isLevelEnabled("verbose")) {
        log.verbose("inspectAccessPolicy cache-hit", {
          db,
          noacl: existing.noacl,
          hasRestrictStar: !!existing.compiledRestrict?.star,
        });
      }
      return {
        noacl: existing.noacl,
        compiledRestrict: existing.compiledRestrict,
      };
    }

    const ddoc = await this.admin.json<{
      restrict?: RestrictMap;
      views?: { acl?: { map?: string } };
    }>(`/${encodeURIComponent(db)}/_design/acl`);
    if (!ddoc.ok) {
      if (ddoc.status === 404) {
        if (isLevelEnabled("verbose")) {
          log.verbose("inspectAccessPolicy", { db, noacl: true, reason: "ddoc-404" });
        }
        return { noacl: true };
      }
      throw new Error(`Failed to inspect _design/acl in ${db}: ${ddoc.status}`);
    }
    const noacl = !ddoc.body.views?.acl?.map;
    if (isLevelEnabled("verbose")) {
      log.verbose("inspectAccessPolicy", {
        db,
        noacl,
        reason: noacl ? "no-acl-map" : "acl-map-present",
      });
    }
    return {
      noacl,
      compiledRestrict: compileRestrict(ddoc.body.restrict),
    };
  }

  /**
   * Ensure ACL state for `db` is loaded (or return existing ready state).
   * Concurrent callers share one in-flight load promise.
   */
  async ensureDb(db: string): Promise<DbAclState> {
    if (this.stopped) {
      log.warn("ensureDb while stopped", { db });
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
    if (existing?.ready && !existing.error) {
      if (isLevelEnabled("verbose")) {
        log.verbose("ensureDb ready", {
          db,
          noacl: existing.noacl,
          rows: existing.acl.size,
          followerUp: existing.followerUp,
        });
      }
      return existing;
    }

    const pending = this.inflight.get(db);
    if (pending) {
      if (isLevelEnabled("verbose")) log.verbose("ensureDb join-inflight", { db });
      return pending;
    }

    log.debug("ensureDb load", { db });
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
    log.info("stopping ACL cache", { dbs: this.dbs.size });
    for (const state of this.dbs.values()) {
      state.follower?.stop();
      state.followerUp = false;
    }
  }

  /** On-demand ACL row refresh (opaque-seq safe; keyed by doc id). */
  async refreshDoc(db: string, docId: string): Promise<void> {
    const state = this.dbs.get(db);
    if (!state || state.noacl) return;
    let result;
    try {
      result = await fetchAclRow(this.admin, db, docId);
    } catch (err) {
      const message = `ACL row unavailable in ${db}: ${String(err)}`;
      this.markUnavailable(state, message);
      throw new AclUnavailableError(message);
    }
    if (!result.ok) {
      const message = `ACL row unavailable in ${db}: ${result.status}`;
      this.markUnavailable(state, message);
      log.warn("refreshDoc view fetch failed; failing closed", {
        db,
        docId,
        status: result.status,
      });
      throw new AclUnavailableError(message);
    }
    if (result.row) {
      state.acl.set(docId, result.row);
      state.tombstones?.delete(docId);
      if (isLevelEnabled("verbose")) {
        log.verbose("refreshDoc", { db, docId, reason: "view-row", parent: result.row.p || "" });
      }
      return;
    }
    if (isLevelEnabled("verbose")) {
      log.verbose("refreshDoc", { db, docId, reason: "reconcile-missing" });
    }
    await this.reconcileMissingAclRow(db, state, docId);
  }

  /**
   * Return a ready ACL state or throw.
   * Throws `DbMissingError` / `AclUnavailableError` — actors map these to HTTP.
   */
  async requireReady(db: string): Promise<DbAclState> {
    const existing = this.dbs.get(db);
    if (existing?.reloading) {
      log.warn("requireReady during reload", { db });
      throw new AclUnavailableError("ACL policy reload in progress");
    }
    const state = await this.ensureDb(db);
    if (state.missing) {
      if (isLevelEnabled("verbose")) log.verbose("requireReady missing", { db });
      throw new DbMissingError(db);
    }
    if (!state.ready || state.error) {
      log.warn("requireReady not ready", { db, error: state.error, ready: state.ready });
      throw new AclUnavailableError(state.error ?? "ACL cache not ready");
    }
    // Fail closed while the changes follower is down — cache may be stale.
    if (!state.noacl && !state.followerUp) {
      log.warn("requireReady follower down", { db });
      throw new AclUnavailableError("ACL changes follower unavailable");
    }
    return state;
  }

  /** Load or reload one DB: ddoc ensure → bulk view → follower. */
  private async loadDb(db: string): Promise<DbAclState> {
    const state: DbAclState = this.dbs.get(db) ?? {
      name: db,
      acl: new Map(),
      tombstones: new Set(),
      tombstonesLoaded: false,
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
        log.info("loadDb missing", { db });
        return state;
      }
      if (ddoc.kind === "absent") {
        // No couch-auth-proxy ACL ddoc — pass through to Couch `_security` only.
        state.noacl = true;
        state.acl.clear();
        state.tombstones?.clear();
        state.tombstonesLoaded = false;
        state.aclMapSource = undefined;
        state.generatedAclMap = false;
        state.dbacl = undefined;
        state.restrict = undefined;
        state.compiledRestrict = undefined;
        state.ready = true;
        state.missing = false;
        state.error = undefined;
        state.followerUp = true;
        state.follower?.stop();
        state.follower = undefined;
        log.info("loadDb noacl passthrough", { db });
        return state;
      }

      // Capture seq before bulk load so the follower replays mid-load changes.
      const since = await fetchUpdateSeq(this.admin, db);
      await this.loadAll(db, state);
      state.ready = true;
      state.missing = false;
      state.error = undefined;
      log.info("loadDb ready", {
        db,
        rows: state.acl.size,
        tombstones: state.tombstones?.size ?? 0,
        noacl: state.noacl,
        hasDbacl: !!state.dbacl,
        hasRestrict: !!state.restrict,
        since,
      });
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
      log.info("installed _design/acl", { db });
      return { kind: "present" };
    }
    if (get.status === 401 || get.status === 403) {
      throw new Error(`Admin auth failed reading _design/acl in ${db}`);
    }
    throw new Error(`Failed to read _design/acl in ${db}: ${get.status}`);
  }

  /**
   * Upgrade generated ACL ddocs while preserving bucket policy/custom views.
   * v2.0 used `_rev` stamps but its VDU incorrectly overrode proxy delete
   * grants from parent/dbacl; older versions also used `_local_seq`. v2.1 did
   * not recognize role owners and allowed non-creators to retarget `parent`.
   * v2.2 allowed a writer to claim `creator` on an existing creator-less doc.
   */
  private async maybeMigrateStamp(db: string, getRes: Response): Promise<void> {
    const ddoc = (await getRes.json()) as {
      _id?: string;
      _rev?: string;
      version?: string;
      type?: string;
      acl?: unknown;
      options?: Record<string, unknown>;
      views?: Record<string, unknown> & { acl?: { map?: string } };
      validate_doc_update?: string;
      [key: string]: unknown;
    };
    const mapSrc = ddoc.views?.acl?.map ?? "";
    const version = typeof ddoc.version === "string" ? ddoc.version : "";
    const generatedShape = ddoc.type === "ddoc" && Array.isArray(ddoc.acl) && version.length > 0;
    const legacyGeneratedVersion = generatedShape && /^(?:1\.|2\.0\.)/.test(version);
    const needsGlobalViewOption =
      generatedShape && version.startsWith("2.1.") && ddoc.options?.partitioned !== false;
    const usesLocalSeq = /_local_seq/.test(mapSrc) && !/doc\._rev/.test(mapSrc);
    const validateSrc = ddoc.validate_doc_update ?? "";
    const hasLegacyDeleteRule = /You can't delete doc\./.test(validateSrc);
    const needsLegacyRewrite = legacyGeneratedVersion && (usesLocalSeq || hasLegacyDeleteRule);
    const needsOwnerPolicyRewrite =
      generatedShape &&
      version.startsWith("2.1.") &&
      /Readers list can not be changed\./.test(validateSrc) &&
      (!/Parent can not be changed\./.test(validateSrc) || !/roleToken/.test(validateSrc));
    const looksLikeGeneratedAclMap = /var cr = doc\.creator, acl = doc\.acl, ow = doc\.owners/.test(
      mapSrc,
    );
    const needsV21FullPolicyRewrite = needsOwnerPolicyRewrite && looksLikeGeneratedAclMap;
    const needsV22FullPolicyRewrite =
      generatedShape &&
      version.startsWith("2.2.") &&
      looksLikeGeneratedAclMap &&
      /if \(odc && odc != ndc\)/.test(validateSrc);
    const needsCreatorPolicyRewrite =
      generatedShape &&
      version.startsWith("2.2.") &&
      !looksLikeGeneratedAclMap &&
      /if \(odc && odc != ndc\)/.test(validateSrc);
    if (
      !needsLegacyRewrite &&
      !needsOwnerPolicyRewrite &&
      !needsCreatorPolicyRewrite &&
      !needsV22FullPolicyRewrite &&
      !needsGlobalViewOption
    ) {
      return;
    }

    const generated = buildAclDesignDoc();
    const next =
      needsLegacyRewrite || needsV21FullPolicyRewrite || needsV22FullPolicyRewrite
        ? {
            ...ddoc,
            _id: ddoc._id ?? generated._id,
            _rev: ddoc._rev,
            language: generated.language,
            options: { ...ddoc.options, ...generated.options },
            type: generated.type,
            version: generated.version,
            stamp: generated.stamp,
            views: { ...ddoc.views, acl: generated.views.acl },
            validate_doc_update: generated.validate_doc_update,
          }
        : needsOwnerPolicyRewrite || needsCreatorPolicyRewrite
          ? {
              ...ddoc,
              _id: ddoc._id ?? generated._id,
              _rev: ddoc._rev,
              options: { ...ddoc.options, ...generated.options },
              type: generated.type,
              version: generated.version,
              stamp: generated.stamp,
              validate_doc_update: generated.validate_doc_update,
            }
          : {
              ...ddoc,
              options: { ...ddoc.options, partitioned: false },
              stamp: generated.stamp,
            };
    const put = await this.admin.fetch(`/${encodeURIComponent(db)}/_design/acl`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(next),
    });
    if (!put.ok) {
      throw new Error(`Failed to upgrade _design/acl in ${db}: ${put.status}`);
    } else {
      log.info("upgraded _design/acl", { db, version: String(next.version ?? version) });
    }
  }

  /** Load dbacl/restrict + all ACL view rows, then atomically swap `state`. */
  private async loadAll(
    db: string,
    state: DbAclState,
    scanCurrentTombstones = true,
  ): Promise<void> {
    const ddocRes = await this.admin.json<{
      dbacl?: DbAclOverlay;
      restrict?: RestrictMap;
      views?: { acl?: { map?: string } };
    }>(`/${encodeURIComponent(db)}/_design/acl`);

    if (!ddocRes.ok) {
      throw new Error(`Failed to read _design/acl body in ${db}: ${ddocRes.status}`);
    }

    const ddoc = ddocRes.body;
    const nextDbacl = ddoc.dbacl;
    const nextRestrict = ddoc.restrict;
    const nextCompiledRestrict = compileRestrict(ddoc.restrict);
    const mapSource = ddoc.views?.acl?.map;

    // Intentional pass-through only when the ddoc has no ACL map function.
    if (!mapSource) {
      state.acl = new Map();
      state.tombstones = new Set();
      state.tombstonesLoaded = false;
      state.aclMapSource = undefined;
      state.generatedAclMap = false;
      state.dbacl = nextDbacl;
      state.restrict = nextRestrict;
      state.compiledRestrict = nextCompiledRestrict;
      state.noacl = true;
      return;
    }

    // Page the view so one large database cannot create an unbounded response
    // body. Build separately and swap only after every page succeeds.
    const loaded = new Map<string, AclRow>();
    let startKey: string | undefined;
    while (true) {
      const query: Record<string, string> = {
        reduce: "false",
        include_docs: "false",
        limit: String(ACL_VIEW_PAGE_SIZE),
      };
      if (startKey !== undefined) {
        query.startkey = JSON.stringify(startKey);
        query.skip = "1";
      }
      const res = await this.admin.json<{
        rows: Array<{ id: string; key: string; value: AclRow }>;
      }>(`/${encodeURIComponent(db)}/_design/acl/_view/acl`, { query });

      if (!res.ok) {
        throw new Error(`ACL view unavailable in ${db}: ${res.status} ${res.text}`);
      }

      const rows = res.body.rows ?? [];
      for (const row of rows) {
        loaded.set(String(row.key ?? row.id), row.value);
      }
      if (rows.length < ACL_VIEW_PAGE_SIZE) break;
      const last = rows.at(-1);
      if (!last) break;
      startKey = String(last.key ?? last.id);
    }

    const mapChanged = state.aclMapSource != null && state.aclMapSource !== mapSource;
    const shouldScanTombstones = scanCurrentTombstones || mapChanged || !state.tombstonesLoaded;
    let tombstones: Set<string>;

    if (shouldScanTombstones) {
      tombstones = new Set();
      await this.loadCurrentTombstones(db, loaded, tombstones, {
        recoverWithGeneratedMap: mapSource === ACL_MAP_SOURCE,
        knownAcl: mapChanged ? undefined : state.acl,
        knownTombstones: mapChanged ? undefined : state.tombstones,
      });
    } else {
      tombstones = new Set(state.tombstones ?? []);
      for (const id of loaded.keys()) tombstones.delete(id);
      // `_design/acl` edits trigger a live-view reload. Deleted documents are
      // absent from that view, so retain only rows explicitly known to be
      // tombstones instead of silently dropping replication visibility.
      for (const id of tombstones) {
        const retained = state.acl.get(id);
        if (retained && !loaded.has(id)) loaded.set(id, { ...retained, deleted: true });
      }
    }

    state.acl = loaded;
    state.tombstones = tombstones;
    state.tombstonesLoaded = true;
    state.aclMapSource = mapSource;
    state.generatedAclMap = mapSource === ACL_MAP_SOURCE;
    state.dbacl = nextDbacl;
    state.restrict = nextRestrict;
    state.compiledRestrict = nextCompiledRestrict;
    state.noacl = false;
    log.debug("loadAll complete", {
      db,
      rows: loaded.size,
      tombstones: tombstones.size,
      mapChanged,
      scannedTombstones: shouldScanTombstones,
      generatedAclMap: state.generatedAclMap,
      hasDbacl: !!nextDbacl,
      hasRestrictStar: !!nextCompiledRestrict.star,
    });
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
          log.warn("follower marked down", { db });
          // A per-row refresh failure marks the whole state unavailable. Repair
          // it with a fresh snapshot instead of waiting for unrelated traffic.
          if (!state.ready || state.error) {
            void this.ensureDb(db);
          }
        },
        onUp: () => {
          state.followerUp = true;
          log.debug("follower up", { db, since: follower.lastSeq });
        },
      },
      since,
    );
    state.follower = follower;
    // Fail closed until the feed actually opens (onUp).
    state.followerUp = false;
    log.debug("starting follower", { db, since });
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
    if (id === "_design/acl") {
      // Do not authorize against a mixed snapshot while a potentially large
      // policy/view reload is in progress.
      log.info("reloading ACL policy from ddoc change", { db, deleted: !!deleted });
      state.reloading = true;
      state.ready = false;
      try {
        await this.loadAll(db, state, false);
        state.error = undefined;
        state.ready = true;
        state.reloading = false;
        log.info("ACL policy reload complete", {
          db,
          rows: state.acl.size,
          noacl: state.noacl,
        });
      } catch (err) {
        state.noacl = false;
        state.reloading = false;
        this.markUnavailable(state, String(err));
        log.warn("reload acl ddoc failed", { db, deleted: !!deleted, err: String(err) });
        throw new AclUnavailableError(String(err));
      }
      return;
    }

    if (deleted) {
      // A delayed delete notification can arrive after a recreate, and the ACL
      // view may still omit the live winner briefly. Reconcile through
      // `_all_docs` so we never stamp `deleted: true` onto a live document.
      const retained = state.acl.get(id);
      if (isLevelEnabled("verbose")) {
        log.verbose("applyChange delete", { db, id, reason: "reconcile-delete", rev });
      }
      await this.reconcileMissingAclRow(db, state, id);
      if (state.acl.get(id) && !state.acl.get(id)?.deleted && !state.tombstones?.has(id)) {
        // Live winner confirmed (recreate won before this notification).
        return;
      }
      if (!state.acl.has(id) && retained) {
        state.acl.set(id, { ...retained, deleted: true });
        (state.tombstones ??= new Set()).add(id);
      }
      return;
    }

    let result;
    try {
      result = await fetchAclRow(this.admin, db, id);
    } catch (err) {
      const message = `ACL row refresh failed in ${db}: ${String(err)}`;
      this.markUnavailable(state, message);
      throw new AclUnavailableError(message);
    }
    if (!result.ok) {
      // Retain the row for a later full reload, but stop authorizing from stale
      // state. Throwing also makes the follower reconnect and report itself down.
      const message = `ACL row refresh failed in ${db}: ${result.status}`;
      this.markUnavailable(state, message);
      log.warn("applyChange view fetch failed; failing closed", {
        db,
        id,
        status: result.status,
      });
      throw new AclUnavailableError(message);
    }
    if (result.row) {
      state.acl.set(id, result.row);
      state.tombstones?.delete(id);
      if (isLevelEnabled("verbose")) {
        log.verbose("applyChange upsert", { db, id, parent: result.row.p || "", rev });
      }
    } else {
      if (isLevelEnabled("verbose")) {
        log.verbose("applyChange upsert", { db, id, reason: "reconcile-missing", rev });
      }
      await this.reconcileMissingAclRow(db, state, id);
    }
  }

  /**
   * Distinguish a genuinely new id from a live document omitted by a broken
   * ACL view and from a deleted winner. This prevents cold-cache create and
   * replication probes from treating private tombstones as writable.
   */
  private async reconcileMissingAclRow(db: string, state: DbAclState, id: string): Promise<void> {
    let meta;
    try {
      meta = await this.admin.json<{
        rows?: Array<{
          error?: string;
          value?: { rev?: string; deleted?: boolean };
        }>;
      }>(`/${encodeURIComponent(db)}/_all_docs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ keys: [id] }),
      });
    } catch (err) {
      const message = `Document state unavailable in ${db}: ${String(err)}`;
      this.markUnavailable(state, message);
      throw new AclUnavailableError(message);
    }

    if (!meta.ok) {
      const message = `Document state unavailable in ${db}: ${meta.status}`;
      this.markUnavailable(state, message);
      throw new AclUnavailableError(message);
    }

    const row = meta.body.rows?.[0];
    if (!row || row.error === "not_found") {
      state.acl.delete(id);
      state.tombstones?.delete(id);
      return;
    }

    if (row.value?.deleted) {
      const rev = row.value.rev;
      let recovered: AclRow | undefined;
      try {
        recovered = state.generatedAclMap
          ? await this.recoverAclFromDeletedDoc(db, id, rev)
          : undefined;
      } catch (err) {
        const message = `Deleted ACL unavailable in ${db}: ${String(err)}`;
        this.markUnavailable(state, message);
        throw new AclUnavailableError(message);
      }
      state.acl.set(id, { ...(recovered ?? this.deniedTombstoneRow(rev)), deleted: true });
      (state.tombstones ??= new Set()).add(id);
      return;
    }

    if (state.generatedAclMap) {
      try {
        const live = await this.aclRowFromLiveDoc(db, id, row.value?.rev);
        if (live) {
          state.acl.set(id, live);
          state.tombstones?.delete(id);
          return;
        }
      } catch (err) {
        const message = `Live document ACL unavailable in ${db}: ${String(err)}`;
        this.markUnavailable(state, message);
        throw new AclUnavailableError(message);
      }
    }

    // Custom maps cannot be reproduced safely from document ACL fields. A
    // live document omitted by one of those maps makes policy indeterminate.
    const message = `ACL view omitted live document ${id} in ${db}`;
    this.markUnavailable(state, message);
    throw new AclUnavailableError(message);
  }

  /**
   * Reconstruct current deleted winners after a full snapshot. `_changes` is
   * paged; historical-revision lookups use bounded concurrency.
   */
  private async loadCurrentTombstones(
    db: string,
    loaded: Map<string, AclRow>,
    tombstones: Set<string>,
    options: {
      recoverWithGeneratedMap: boolean;
      knownAcl?: Map<string, AclRow>;
      knownTombstones?: Set<string>;
    },
  ): Promise<void> {
    let since = "0";
    while (true) {
      const res = await this.admin.json<{
        results?: Array<{
          id?: string;
          deleted?: boolean;
          changes?: Array<{ rev?: string }>;
        }>;
        last_seq?: string | number;
        pending?: number;
      }>(`/${encodeURIComponent(db)}/_changes`, {
        query: {
          since,
          limit: String(ACL_VIEW_PAGE_SIZE),
          style: "main_only",
        },
      });
      if (!res.ok) {
        throw new Error(`Deleted ACL scan unavailable in ${db}: ${res.status}`);
      }

      const results = res.body.results ?? [];
      const deleted = results.filter(
        (change) => change.deleted && change.id && change.id !== "_design/acl",
      );
      for (let i = 0; i < deleted.length; i += ACL_RECOVERY_CONCURRENCY) {
        await Promise.all(
          deleted.slice(i, i + ACL_RECOVERY_CONCURRENCY).map(async (change) => {
            const id = change.id!;
            const known =
              options.knownTombstones?.has(id) === true ? options.knownAcl?.get(id) : undefined;
            if (known) {
              loaded.set(id, { ...known, deleted: true });
            } else {
              const rev = change.changes?.[0]?.rev;
              const recovered = options.recoverWithGeneratedMap
                ? await this.recoverAclFromDeletedDoc(db, id, rev)
                : undefined;
              loaded.set(id, { ...(recovered ?? this.deniedTombstoneRow(rev)), deleted: true });
            }
            tombstones.add(id);
          }),
        );
      }

      const nextSince = String(res.body.last_seq ?? since);
      if (
        results.length === 0 ||
        res.body.pending === 0 ||
        results.length < ACL_VIEW_PAGE_SIZE ||
        nextSince === since
      ) {
        break;
      }
      since = nextSince;
    }
  }

  /** A compact fail-closed row when Couch has compacted the prior revision. */
  private deniedTombstoneRow(rev?: string): AclRow {
    return {
      s: rev ?? "",
      p: "",
      deleted: true,
      _r: {},
      _w: {},
      _d: {},
    };
  }

  /** Reproduce the shipped map for a live revision during a view-index race. */
  private async aclRowFromLiveDoc(
    db: string,
    id: string,
    rev?: string,
  ): Promise<AclRow | undefined> {
    const res = await this.admin.json<{
      _id?: string;
      _rev?: string;
      _deleted?: boolean;
      creator?: string;
      owners?: string[];
      acl?: string[];
      parent?: string;
    }>(
      `/${encodeURIComponent(db)}/${encodeURIComponent(id)}`,
      rev ? { query: { rev } } : undefined,
    );
    if (!res.ok) {
      if (res.status === 404) return undefined;
      throw new Error(`Live revision unavailable: ${res.status}`);
    }
    if (!res.body._id || res.body._deleted) return undefined;
    const doc = res.body;
    return aclRowFromDoc({
      _id: doc._id!,
      _rev: doc._rev ?? rev,
      ...(Object.hasOwn(doc, "creator") ? { creator: doc.creator } : {}),
      ...(Object.hasOwn(doc, "owners") ? { owners: doc.owners } : {}),
      ...(Object.hasOwn(doc, "acl") ? { acl: doc.acl } : {}),
      ...(Object.hasOwn(doc, "parent") ? { parent: doc.parent } : {}),
    });
  }

  /** Mark a DB unusable until `ensureDb` completes a fresh full reload. */
  private markUnavailable(state: DbAclState, message: string): void {
    state.ready = false;
    state.error = message;
    state.followerUp = false;
    log.warn("ACL state marked unavailable", { db: state.name, error: message });
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
    const metaRes = await this.admin.json<{
      _deleted?: boolean;
      _revisions?: { start?: number; ids?: string[] };
    }>(`/${encodeURIComponent(db)}/${encodeURIComponent(id)}`, {
      query: { rev: deletedRev, revs: "true" },
    });
    if (!metaRes.ok) {
      if (metaRes.status === 404) return undefined;
      throw new Error(`Deleted revision metadata unavailable: ${metaRes.status}`);
    }
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
    if (!prevRes.ok) {
      if (prevRes.status === 404) return undefined;
      throw new Error(`Pre-delete revision unavailable: ${prevRes.status}`);
    }
    if (!prevRes.body._id) return undefined;
    const doc = prevRes.body;
    return aclRowFromDoc({
      _id: doc._id!,
      _rev: prevRev,
      ...(Object.hasOwn(doc, "creator") ? { creator: doc.creator } : {}),
      ...(Object.hasOwn(doc, "owners") ? { owners: doc.owners } : {}),
      ...(Object.hasOwn(doc, "acl") ? { acl: doc.acl } : {}),
      ...(Object.hasOwn(doc, "parent") ? { parent: doc.parent } : {}),
    });
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
