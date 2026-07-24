/**
 * Restmap actors — per-route middleware steps for ACL enforcement.
 *
 * Each actor is a named step from `restmap.ts`. Actors may:
 * - return a `Response` to short-circuit the chain, or
 * - call `next()` / fall through so later actors (or final pipe) run.
 *
 * Typical DB-scoped chain: `db` → (`doc` | `rows` | `bulk` | …) → `pipe`.
 * The `db` actor loads ACL state and enforces `restrict`; document/list actors
 * filter or authorize; terminal actors proxy or rewrite Couch responses.
 */
import type { Context, Next } from "hono";
import type { AppEnv } from "../middleware/context.js";
import {
  AclUnavailableError,
  DbMissingError,
  type AclCache,
  type DbAclState,
} from "../acl/cache.js";
import { isDatabaseName, isDocumentId } from "../acl/names.js";
import { dbAccessLevel, methodAllowed } from "../acl/restrict.js";
import { canDelete, canRead, ensureDocRow, flagsForDoc } from "../acl/lookup.js";
import {
  couchError,
  fetchFromCouch,
  forwardToCouch,
  jsonResponse,
  toClientResponse,
} from "../proxy/forward.js";
import { filterBulkGet, filterRows, type RowsResponse } from "../proxy/filterRows.js";
import {
  filterBulkDocs,
  filterRevsObject,
  mergeBulkResults,
  type BulkDocsBody,
} from "../proxy/filterBulk.js";
import { filterChangesStream } from "../proxy/filterChanges.js";
import { filterFindDocs, type FindResponse } from "../proxy/filterFind.js";
import {
  BodyTooLargeError,
  readJsonLimited,
  readResponseTextLimited,
  readTextLimited,
} from "../util/limitStream.js";
import { createLogger, isLevelEnabled } from "../util/log.js";

type AppContext = Context<AppEnv>;
const ACL_LOOKUP_CONCURRENCY = 16;
const DESIGN_API_ATTACHMENT =
  /^_(?:view|list|show|update|search|search_info|nouveau|nouveau_info|rewrite|info)(?:\/|$)/;
const log = createLogger("actors");

/** Verbose/debug helper for actor allow/deny decisions. */
function logDecision(
  actor: string,
  fields: Record<string, unknown>,
  level: "verbose" | "debug" | "info" | "warn" = "verbose",
): void {
  if (!isLevelEnabled(level)) return;
  log[level](actor, fields);
}

/** One restmap middleware step. */
export type Actor = (c: AppContext, next: Next) => Promise<Response | void>;

/**
 * Resolve document id from route params.
 * Prefer `:docId` when present (e.g. `_show` / `_update` target); otherwise
 * `_design/:ddoc` for design-doc and design-attachment routes.
 */
function docIdFromParams(c: AppContext): string {
  const docId = c.req.param("docId");
  if (docId) return docId;
  const ddoc = c.req.param("ddoc");
  if (ddoc != null && c.req.path.includes("/_design/")) {
    return `_design/${ddoc}`;
  }
  return "";
}

/** Apply Couch endpoint classification plus the configured document-id ceiling. */
function validDocumentId(c: AppContext, id: string): boolean {
  // Hono decodes route params but matches against the encoded path. Without
  // this guard, `/_design%2Fapp/_view/name` matches the generic
  // `/:docId/:attachment` route, authorizes only the readable design doc, and
  // pipes an otherwise ACL-filtered view directly to Couch. Reserved document
  // prefixes must use their canonical, explicitly classified route shapes.
  if (id.startsWith("_design/") && c.req.param("ddoc") == null) return false;
  if (id.startsWith("_local/")) return false;
  const attachment = c.req.param("attachment");
  if (c.req.param("ddoc") != null && attachment != null && DESIGN_API_ATTACHMENT.test(attachment)) {
    return false;
  }
  return isDocumentId(id, c.get("config").couch.maxIdLength);
}

/** Refresh unique ACL ids with bounded Couch admin-request fan-out. */
async function ensureDocRows(
  cache: AclCache,
  state: DbAclState,
  ids: Iterable<string>,
): Promise<void> {
  const pending = [...new Set(ids)];
  let index = 0;
  const workers = Array.from(
    { length: Math.min(ACL_LOOKUP_CONCURRENCY, pending.length) },
    async () => {
      while (index < pending.length) {
        const id = pending[index++]!;
        await ensureDocRow(cache, state, id);
      }
    },
  );
  await Promise.all(workers);
}

/**
 * Parse Couch's `Destination: doc-id[?rev=…]` COPY header.
 *
 * The destination is one URL-encoded id in the current DB. Reject absolute,
 * root-relative, and unencoded multi-segment paths so authorization cannot be
 * performed against a different id than Couch ultimately writes.
 */
function copyDestinationId(rawHeader: string): string | undefined {
  const raw = rawHeader.trim();
  if (!raw || raw.startsWith("/") || raw.includes("://") || raw.includes("#")) {
    return undefined;
  }
  const queryIndex = raw.indexOf("?");
  const encodedId = queryIndex >= 0 ? raw.slice(0, queryIndex) : raw;
  if (!encodedId || encodedId.includes("/") || encodedId.includes("\\")) {
    return undefined;
  }
  try {
    return decodeURIComponent(encodedId);
  } catch {
    return undefined;
  }
}

/** Path + query after `/{db}`, used for `restrict` method matching. */
function urlAfterDb(c: AppContext, db: string): string {
  const query = c.req.url.includes("?") ? `?${c.req.url.split("?")[1]}` : "";
  const full = c.req.path + query;
  const prefix = `/${db}`;
  return full.startsWith(prefix) ? full.slice(prefix.length) || "/" : full;
}

/**
 * Named actor implementations keyed by `ActorName` from restmap.
 */
export const actors: Record<string, Actor> = {
  /** Transparent proxy — no ACL beyond what earlier actors already enforced. */
  async pipe(c) {
    logDecision("pipe", {
      method: c.req.method,
      path: c.req.path,
      user: c.get("principal")?.name ?? null,
    });
    return forwardToCouch(c, c.get("config"));
  },

  /** Session endpoints — pipe to Couch; drop cached principal on logout. */
  async session(c) {
    if (c.req.method === "DELETE") {
      c.get("sessions").invalidate(c.req.raw.headers);
      logDecision("session", { action: "invalidate-cache", method: "DELETE" }, "debug");
    }
    return forwardToCouch(c, c.get("config"));
  },

  /** Server-admin only; everyone else gets 403. */
  async admin(c) {
    const principal = c.get("principal");
    if (!principal.admin) {
      logDecision(
        "admin",
        {
          decision: "deny",
          reason: "not-admin",
          user: principal.name,
          method: c.req.method,
          path: c.req.path,
        },
        "debug",
      );
      return couchError("forbidden", "Access denied.", 403);
    }
    logDecision("admin", {
      decision: "allow",
      user: principal.name,
      method: c.req.method,
      path: c.req.path,
    });
    return forwardToCouch(c, c.get("config"));
  },

  /** `_list` is unsupported in couch-auth-proxy — return 501 with migration hint. */
  async list501() {
    return couchError(
      "not_implemented",
      "couch-auth-proxy does not emulate _list. Use filtered views or Mango; admin may call Couch directly.",
      501,
    );
  },

  /**
   * Fail-closed stub for surfaces that cannot be ACL-filtered safely
   * (e.g. `_show` / `_update` without a target document id).
   */
  async unsupported() {
    return couchError(
      "not_implemented",
      "Unsupported endpoint for ACL proxy. Use a document id, filtered views/Mango, or call as admin against Couch.",
      501,
    );
  },

  /**
   * Database gate: ensure ACL cache, enforce `restrict.*` / method rules,
   * attach `dbAclState`. `noacl` DBs pipe immediately (Couch `_security` only).
   */
  async db(c, next) {
    const db = c.req.param("db");
    if (!db) {
      await next();
      return;
    }
    if (!isDatabaseName(db)) {
      logDecision(
        "db",
        { decision: "deny", reason: "invalid-db-name", db, user: c.get("principal").name },
        "debug",
      );
      return couchError("forbidden", "Access denied.", 403);
    }

    let state;
    try {
      state = await c.get("aclCache").requireReady(db);
    } catch (err) {
      if (err instanceof DbMissingError) {
        // Let Couch return its native missing-db error.
        logDecision("db", { decision: "pipe", reason: "db-missing", db }, "debug");
        return forwardToCouch(c, c.get("config"));
      }
      if (err instanceof AclUnavailableError) {
        log.warn("db ACL unavailable", { db, err: String(err) });
        return couchError("service_unavailable", "ACL cache unavailable", 503);
      }
      // Fail closed on unexpected errors — never open the DB.
      log.error("db ACL unexpected error", { db, err: String(err) });
      return couchError("service_unavailable", "ACL cache unavailable", 503);
    }

    const principal = c.get("principal");
    const level = dbAccessLevel(principal, state.compiledRestrict, state.noacl);
    if (level === 0) {
      // Hide restricted DBs as not_found (same as missing).
      logDecision(
        "db",
        {
          decision: "deny",
          reason: "restrict-star",
          db,
          user: principal.name,
          accessLevel: level,
          noacl: state.noacl,
        },
        "debug",
      );
      return couchError("not_found", "Database does not exist.", 404);
    }

    const after = urlAfterDb(c, db);
    if (!methodAllowed(principal, state.compiledRestrict, c.req.method, after)) {
      logDecision(
        "db",
        {
          decision: "deny",
          reason: "method-restricted",
          db,
          user: principal.name,
          method: c.req.method,
          urlAfterDb: after,
          accessLevel: level,
        },
        "debug",
      );
      return couchError("forbidden", "Method restricted.", 403);
    }

    if (state.noacl) {
      logDecision("db", {
        decision: "pipe",
        reason: "noacl",
        db,
        user: principal.name,
        accessLevel: level,
      });
      return forwardToCouch(c, c.get("config"));
    }

    logDecision("db", {
      decision: "allow",
      db,
      user: principal.name,
      accessLevel: level,
      method: c.req.method,
      urlAfterDb: after,
      aclRows: state.acl.size,
      ready: state.ready,
      followerUp: state.followerUp,
    });
    c.set("dbAclState", state);
    await next();
  },

  /** Single-doc read: 404 if principal cannot read (indistinguishable from missing). */
  async doc(c, next) {
    const state = c.get("dbAclState");
    const id = docIdFromParams(c);
    if (!state || !id) {
      await next();
      return;
    }
    if (!validDocumentId(c, id)) {
      logDecision("doc", { decision: "deny", reason: "invalid-doc-id", docId: id, db: state.name });
      return couchError("not_found", "Unsupported endpoint.", 404);
    }
    await ensureDocRow(c.get("aclCache"), state, id);
    const principal = c.get("principal");
    const allowed = canRead(state, principal, id);
    logDecision(
      "doc",
      {
        decision: allowed ? "allow" : "deny",
        action: "read",
        db: state.name,
        docId: id,
        user: principal.name,
      },
      allowed ? "verbose" : "debug",
    );
    if (!allowed) {
      return couchError("not_found", "missing", 404);
    }
    await next();
  },

  /**
   * Single-doc write/create: 403 if principal lacks write.
   * POST /{db} may carry `_id` in the JSON body — check that id too (legacy parity).
   */
  async docWrite(c, next) {
    const state = c.get("dbAclState");
    if (!state) {
      await next();
      return;
    }

    let id = docIdFromParams(c);
    let bufferedBody: string | undefined;
    let deleting = false;
    let bodyParseFailed = false;
    const principal = c.get("principal");

    // Direct JSON document writes can carry a tombstone. Attachments are
    // arbitrary bytes and use the route method for delete authorization.
    const inspectBody =
      !principal.admin &&
      (c.req.method === "POST" || (c.req.method === "PUT" && c.req.param("attachment") == null));
    if (inspectBody) {
      try {
        bufferedBody = await readTextLimited(c.req.raw, c.get("config").server.maxBodyBytes);
      } catch (err) {
        if (err instanceof BodyTooLargeError) {
          return couchError("bad_request", "Request body too large", 413);
        }
        throw err;
      }
      try {
        const parsed = JSON.parse(bufferedBody || "null") as {
          _id?: unknown;
          _deleted?: unknown;
        } | null;
        if (parsed && typeof parsed === "object") {
          if (!id && typeof parsed._id === "string" && parsed._id) {
            id = parsed._id;
          }
          deleting = parsed._deleted === true;
        }
      } catch {
        bodyParseFailed = true;
      }
    }

    if (id) {
      if (!validDocumentId(c, id)) {
        logDecision("docWrite", {
          decision: "deny",
          reason: "invalid-doc-id",
          docId: id,
          db: state.name,
        });
        return couchError("not_found", "Unsupported endpoint.", 404);
      }
      await ensureDocRow(c.get("aclCache"), state, id);
      const flags = flagsForDoc(state, principal, id);
      const allowed = deleting ? flags._d : flags._w;
      logDecision(
        "docWrite",
        {
          decision: allowed ? "allow" : "deny",
          action: deleting ? "delete-via-put" : "write",
          db: state.name,
          docId: id,
          user: principal.name,
          flags,
        },
        allowed ? "verbose" : "debug",
      );
      if (!allowed) {
        return couchError("forbidden", "ACL", 403);
      }
    }

    if (bodyParseFailed) {
      const contentType = c.req.header("content-type")?.toLowerCase() ?? "";
      if (contentType.startsWith("multipart/")) {
        log.warn("docWrite multipart rejected", { db: state.name, user: principal.name });
        return couchError(
          "not_implemented",
          "Multipart document writes are unsupported for non-admins. Use JSON documents and attachment endpoints.",
          415,
        );
      }
      return couchError("bad_request", "Invalid JSON document.", 400);
    }

    if (bufferedBody !== undefined) {
      return forwardToCouch(c, c.get("config"), {
        body: bufferedBody,
        headers: {
          "Content-Type": c.req.header("content-type") || "application/json",
        },
      });
    }
    await next();
  },

  /** Single-doc delete: 403 if principal lacks delete. */
  async docDelete(c, next) {
    const state = c.get("dbAclState");
    const id = docIdFromParams(c);
    if (!state || !id) {
      await next();
      return;
    }
    if (!validDocumentId(c, id)) {
      logDecision("docDelete", {
        decision: "deny",
        reason: "invalid-doc-id",
        docId: id,
        db: state.name,
      });
      return couchError("not_found", "Unsupported endpoint.", 404);
    }
    await ensureDocRow(c.get("aclCache"), state, id);
    const principal = c.get("principal");
    const allowed = canDelete(state, principal, id);
    logDecision(
      "docDelete",
      {
        decision: allowed ? "allow" : "deny",
        action: "delete",
        db: state.name,
        docId: id,
        user: principal.name,
      },
      allowed ? "verbose" : "debug",
    );
    if (!allowed) {
      return couchError("forbidden", "ACL", 403);
    }
    await next();
  },

  /**
   * Design `_update` handlers can arbitrarily write or delete their target.
   * Require both write and delete so a handler cannot elevate a reader/owner.
   */
  async docUpdate(c, next) {
    const state = c.get("dbAclState");
    const id = docIdFromParams(c);
    if (!state || !id) {
      await next();
      return;
    }
    if (!validDocumentId(c, id)) {
      return couchError("not_found", "Unsupported endpoint.", 404);
    }
    await ensureDocRow(c.get("aclCache"), state, id);
    const principal = c.get("principal");
    const flags = flagsForDoc(state, principal, id);
    if (!flags._r) {
      logDecision(
        "docUpdate",
        {
          decision: "deny",
          reason: "no-read",
          db: state.name,
          docId: id,
          user: principal.name,
          flags,
        },
        "debug",
      );
      return couchError("not_found", "missing", 404);
    }
    if (!flags._w || !flags._d) {
      logDecision(
        "docUpdate",
        {
          decision: "deny",
          reason: "need-write-and-delete",
          db: state.name,
          docId: id,
          user: principal.name,
          flags,
        },
        "debug",
      );
      return couchError("forbidden", "ACL", 403);
    }
    logDecision("docUpdate", {
      decision: "allow",
      db: state.name,
      docId: id,
      user: principal.name,
      flags,
    });
    await next();
  },

  /**
   * COPY: require read on source and write on destination (from Destination header).
   */
  async copy(c) {
    const state = c.get("dbAclState");
    const id = docIdFromParams(c);
    if (!state || !id) return couchError("bad_request", "missing id", 400);
    if (!validDocumentId(c, id)) {
      return couchError("not_found", "Unsupported endpoint.", 404);
    }
    const principal = c.get("principal");
    await ensureDocRow(c.get("aclCache"), state, id);
    if (!canRead(state, principal, id)) {
      logDecision(
        "copy",
        {
          decision: "deny",
          reason: "source-unreadable",
          db: state.name,
          docId: id,
          user: principal.name,
        },
        "debug",
      );
      return couchError("not_found", "missing", 404);
    }
    const destHeader = c.req.header("Destination") || c.req.header("destination");
    if (!destHeader) return couchError("bad_request", "Destination header required", 400);
    const destId = copyDestinationId(destHeader);
    if (!destId || !validDocumentId(c, destId)) {
      return couchError("bad_request", "Invalid COPY destination", 400);
    }
    const queryIndex = destHeader.indexOf("?");
    const destinationPath =
      `/${encodeURIComponent(destId)}` + (queryIndex >= 0 ? destHeader.slice(queryIndex) : "");
    if (!methodAllowed(principal, state.compiledRestrict, "PUT", destinationPath)) {
      logDecision(
        "copy",
        {
          decision: "deny",
          reason: "dest-method-restricted",
          db: state.name,
          docId: id,
          destId,
          user: principal.name,
        },
        "debug",
      );
      return couchError("forbidden", "Method restricted.", 403);
    }
    await ensureDocRow(c.get("aclCache"), state, destId);
    const destFlags = flagsForDoc(state, principal, destId);
    if (!destFlags._w) {
      logDecision(
        "copy",
        {
          decision: "deny",
          reason: "dest-not-writable",
          db: state.name,
          docId: id,
          destId,
          user: principal.name,
          destFlags,
        },
        "debug",
      );
      return couchError("forbidden", "ACL", 403);
    }
    logDecision("copy", {
      decision: "allow",
      db: state.name,
      docId: id,
      destId,
      user: principal.name,
      destFlags,
    });
    return forwardToCouch(c, c.get("config"));
  },

  /** Proxy then filter `_all_docs` / view rows by read ACL. */
  async rows(c) {
    const state = c.get("dbAclState");
    if (!state) return forwardToCouch(c, c.get("config"));

    const config = c.get("config");
    const principal = c.get("principal");
    const isView = c.req.path.includes("/_view/");
    const maxBytes = config.server.maxBodyBytes;

    // POST bodies may carry keys / reduce / group (Couch merges body + query).
    let requestBodyText: string | undefined;
    let requestBodyJson: Record<string, unknown> | undefined;
    if (c.req.method === "POST") {
      try {
        requestBodyText = await readTextLimited(c.req.raw, maxBytes);
      } catch (err) {
        if (err instanceof BodyTooLargeError) {
          return couchError("bad_request", "Request body too large", 413);
        }
        throw err;
      }
      if (requestBodyText) {
        try {
          const parsed = JSON.parse(requestBodyText) as unknown;
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            requestBodyJson = parsed as Record<string, unknown>;
          }
        } catch {
          // Invalid JSON — let Couch return its native error (no ACL rewrite).
          return forwardToCouch(c, config, {
            body: requestBodyText,
            headers: {
              "Content-Type": c.req.header("content-type") || "application/json",
              Accept: "application/json",
            },
          });
        }
      }
    }

    const queryReduce = c.req.query("reduce");
    const queryGroup = c.req.query("group");
    const queryGroupLevel = c.req.query("group_level");
    const bodyReduce = requestBodyJson?.reduce;
    const bodyGroup = requestBodyJson?.group;
    const bodyGroupLevel = requestBodyJson?.group_level;
    const wantsReduce =
      isView &&
      (queryReduce === "true" ||
        queryGroup === "true" ||
        queryGroupLevel != null ||
        bodyReduce === true ||
        bodyReduce === "true" ||
        bodyGroup === true ||
        bodyGroup === "true" ||
        bodyGroupLevel != null);

    // Reduce/group aggregates have no doc ids — reject (never pass through).
    if (wantsReduce && !principal.admin) {
      logDecision(
        "rows",
        {
          decision: "deny",
          reason: "reduce-group-unsupported",
          db: state.name,
          user: principal.name,
          path: c.req.path,
        },
        "debug",
      );
      return couchError(
        "not_implemented",
        "couch-auth-proxy does not support reduce/group over ACL-filtered views. Use reduce=false, or call as admin.",
        501,
      );
    }

    let query: string | undefined;
    let forwardBody = requestBodyText;
    if (isView && !principal.admin) {
      // Couch defaults reduce=true when a reduce fn exists — force map rows.
      const url = new URL(c.req.url);
      url.searchParams.set("reduce", "false");
      url.searchParams.delete("group");
      url.searchParams.delete("group_level");
      query = url.search;
      if (requestBodyJson) {
        const next: Record<string, unknown> = { ...requestBodyJson, reduce: false };
        delete next.group;
        delete next.group_level;
        forwardBody = JSON.stringify(next);
      }
    }

    const upstream = await fetchFromCouch(c, config, {
      headers: {
        Accept: "application/json",
        ...(forwardBody !== undefined
          ? { "Content-Type": c.req.header("content-type") || "application/json" }
          : {}),
      },
      ...(query != null ? { query } : {}),
      ...(forwardBody !== undefined ? { body: forwardBody } : {}),
    });
    if (!upstream.ok) return toClientResponse(upstream);

    let body: RowsResponse;
    try {
      body = JSON.parse(await readResponseTextLimited(upstream, maxBytes)) as RowsResponse;
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return couchError("bad_request", "Response body too large", 413);
      }
      throw err;
    }

    // Only keyed queries may preserve denied slots (client already knows ids).
    // Non-keyed POST must drop rows — placeholders would leak existing ids.
    const hasKeys =
      c.req.query("keys") != null ||
      c.req.query("key") != null ||
      requestBodyJson?.keys != null ||
      requestBodyJson?.key != null;
    const filtered = filterRows(state, principal, body, {
      preserveDenied: hasKeys,
    });
    logDecision("rows", {
      decision: "filter",
      db: state.name,
      user: principal.name,
      path: c.req.path,
      upstreamRows: body.rows?.length ?? 0,
      filteredRows: filtered.rows.length,
      preserveDenied: hasKeys,
    });
    return toClientResponse(upstream, { body: JSON.stringify(filtered) });
  },

  /** Proxy `_changes` and stream-filter by read ACL (all feed styles). */
  async changes(c) {
    const state = c.get("dbAclState");
    if (!state) return forwardToCouch(c, c.get("config"));

    const config = c.get("config");
    const feed = (c.req.query("feed") || "normal").toLowerCase();
    // Unknown feed styles must not fall through to an unfiltered/opaque pipe.
    if (
      feed !== "normal" &&
      feed !== "longpoll" &&
      feed !== "continuous" &&
      feed !== "eventsource"
    ) {
      return couchError("bad_request", "Unsupported _changes feed.", 400);
    }
    const principal = c.get("principal");
    logDecision("changes", {
      decision: "stream-filter",
      db: state.name,
      user: principal.name,
      feed,
    });
    const upstream = await fetchFromCouch(c, config);
    if (!upstream.ok || !upstream.body) return toClientResponse(upstream);

    const filtered = filterChangesStream(upstream.body, state, principal, feed, {
      maxBufferBytes: config.server.maxBodyBytes,
    });
    const response = toClientResponse(upstream, { body: filtered });
    if (!response.headers.has("Content-Type")) {
      response.headers.set("Content-Type", "application/json");
    }
    return response;
  },

  /**
   * `_bulk_docs`: ACL-filter docs, proxy allowed set, merge results into slots.
   * `all_or_nothing` fails the whole transaction if any doc was denied.
   */
  async bulk(c) {
    const state = c.get("dbAclState");
    if (!state) return forwardToCouch(c, c.get("config"));

    let body: BulkDocsBody;
    try {
      body = await readJsonLimited<BulkDocsBody>(c.req.raw, c.get("config").server.maxBodyBytes);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return couchError("bad_request", "Request body too large", 413);
      }
      return couchError("bad_request", "Invalid format.", 400);
    }
    if (!body || typeof body !== "object" || !Array.isArray(body.docs)) {
      return couchError("bad_request", "Invalid format.", 400);
    }

    const cache = c.get("aclCache");
    await ensureDocRows(
      cache,
      state,
      (body.docs ?? [])
        .filter((doc) => doc && typeof doc._id === "string" && validDocumentId(c, doc._id))
        .map((doc) => doc._id!),
    );

    const principal = c.get("principal");
    const filtered = filterBulkDocs(state, principal, body, (id) => validDocumentId(c, id));
    const atomic = String(body.all_or_nothing) === "true";
    logDecision(
      "bulk",
      {
        decision: atomic && filtered.hadDenied ? "deny" : "filter",
        db: state.name,
        user: principal.name,
        requested: body.docs.length,
        allowed: filtered.allowed.length,
        hadDenied: filtered.hadDenied,
        allOrNothing: atomic,
      },
      filtered.hadDenied ? "debug" : "verbose",
    );
    if (atomic && filtered.hadDenied) {
      return couchError("forbidden", "ACL rejected transaction.", 403);
    }
    if (!filtered.allowed.length) {
      return jsonResponse(
        filtered.slots.map((slot) => slot ?? { error: "forbidden", reason: "ACL" }),
        201,
      );
    }

    const upstream = await fetchFromCouch(c, c.get("config"), {
      body: JSON.stringify({ ...filtered.rest, docs: filtered.allowed }),
      headers: { "Content-Type": "application/json", Accept: "application/json" },
    });
    if (!upstream.ok) return toClientResponse(upstream);
    let results = (await upstream.json()) as Array<Record<string, unknown>>;
    if (!Array.isArray(results)) results = [];
    // CouchDB 3.x often returns [] for successful new_edits:false bulk writes.
    // Synthesize ok rows so clients (PouchDB) and ACL-denied slot merging work.
    if (results.length === 0 && filtered.allowed.length > 0) {
      results = filtered.allowed.map((doc) => ({
        ok: true,
        id: doc._id,
        rev: doc._rev,
      }));
    }
    return toClientResponse(upstream, {
      body: JSON.stringify(mergeBulkResults(filtered.slots, results)),
    });
  },

  /** Proxy `_bulk_get` then replace denied results with not_found. */
  async bulkGet(c) {
    const state = c.get("dbAclState");
    if (!state) return forwardToCouch(c, c.get("config"));
    const config = c.get("config");

    let requestBodyText: string;
    try {
      requestBodyText = await readTextLimited(c.req.raw, config.server.maxBodyBytes);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return couchError("bad_request", "Request body too large", 413);
      }
      throw err;
    }
    let requestedIds: string[] = [];
    try {
      const request = JSON.parse(requestBodyText || "null") as {
        docs?: Array<{ id?: unknown }>;
      } | null;
      if (request && Array.isArray(request.docs)) {
        requestedIds = request.docs
          .map((doc) => doc?.id)
          .filter((id): id is string => typeof id === "string" && validDocumentId(c, id));
      }
    } catch {
      // Let Couch return its native malformed-body response.
    }
    const cache = c.get("aclCache");
    await ensureDocRows(cache, state, requestedIds);

    const upstream = await fetchFromCouch(c, config, {
      body: requestBodyText,
      headers: {
        Accept: "application/json",
        "Content-Type": c.req.header("content-type") || "application/json",
      },
    });
    if (!upstream.ok) return toClientResponse(upstream);
    let body: { results?: Array<{ id: string; docs: unknown[] }> };
    try {
      body = JSON.parse(
        await readResponseTextLimited(upstream, config.server.maxBodyBytes),
      ) as typeof body;
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return couchError("bad_request", "Response body too large", 413);
      }
      throw err;
    }
    const principal = c.get("principal");
    const filtered = filterBulkGet(state, principal, body);
    logDecision("bulkGet", {
      decision: "filter",
      db: state.name,
      user: principal.name,
      requested: body.results?.length ?? 0,
      results: filtered.results?.length ?? 0,
    });
    return toClientResponse(upstream, {
      body: JSON.stringify(filtered),
    });
  },

  /** Filter `_revs_diff` / `_missing_revs` keys then proxy. */
  async revs(c) {
    const state = c.get("dbAclState");
    if (!state) return forwardToCouch(c, c.get("config"));
    let body: Record<string, unknown>;
    try {
      body = await readJsonLimited<Record<string, unknown>>(
        c.req.raw,
        c.get("config").server.maxBodyBytes,
      );
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return couchError("bad_request", "Request body too large", 413);
      }
      return couchError("bad_request", "Invalid format.", 400);
    }
    const cache = c.get("aclCache");
    await ensureDocRows(
      cache,
      state,
      Object.keys(body).filter((id) => validDocumentId(c, id)),
    );
    const principal = c.get("principal");
    const filtered = filterRevsObject(state, principal, body, (id) => validDocumentId(c, id));
    logDecision("revs", {
      decision: "filter",
      db: state.name,
      user: principal.name,
      path: c.req.path,
      requestedKeys: Object.keys(body).length,
      allowedKeys: Object.keys(filtered).length,
    });
    const upstream = await fetchFromCouch(c, c.get("config"), {
      body: JSON.stringify(filtered),
      headers: { "Content-Type": "application/json", Accept: "application/json" },
    });
    return toClientResponse(upstream);
  },

  /**
   * `_all_dbs`: hide DBs the principal cannot access via `restrict.*`.
   * Admins see DBs even when ACL ensure fails.
   */
  async dblist(c) {
    const upstream = await fetchFromCouch(c, c.get("config"), {
      headers: { Accept: "application/json" },
    });
    if (!upstream.ok) return toClientResponse(upstream);
    const principal = c.get("principal");
    if (principal.admin) return toClientResponse(upstream);

    let dbs: string[];
    try {
      dbs = JSON.parse(
        await readResponseTextLimited(upstream, c.get("config").server.maxBodyBytes),
      ) as string[];
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return couchError("bad_request", "Response body too large", 413);
      }
      throw err;
    }
    if (!Array.isArray(dbs)) {
      return toClientResponse(upstream, { body: JSON.stringify(dbs) });
    }

    const cache = c.get("aclCache");
    const visible: string[] = [];
    for (const db of dbs) {
      try {
        const policy = await cache.inspectAccessPolicy(db);
        if (dbAccessLevel(principal, policy.compiledRestrict, policy.noacl) > 0) {
          visible.push(db);
        }
      } catch (err) {
        logDecision(
          "dblist",
          { decision: "hide", reason: "inspect-failed", db, err: String(err) },
          "debug",
        );
      }
    }
    logDecision("dblist", {
      decision: "filter",
      user: principal.name,
      upstreamDbs: dbs.length,
      visibleDbs: visible.length,
      visible,
    });
    return toClientResponse(upstream, { body: JSON.stringify(visible) });
  },

  /** Mango `_find` — proxy then drop unread docs. */
  async find(c) {
    const state = c.get("dbAclState");
    if (!state) return forwardToCouch(c, c.get("config"));
    const config = c.get("config");

    let requestBodyText: string;
    try {
      requestBodyText = await readTextLimited(c.req.raw, config.server.maxBodyBytes);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return couchError("bad_request", "Request body too large", 413);
      }
      throw err;
    }

    let forwardBody = requestBodyText;
    let injectedId = false;
    try {
      const requestBody = JSON.parse(requestBodyText || "null") as Record<string, unknown> | null;
      if (
        requestBody &&
        Array.isArray(requestBody.fields) &&
        requestBody.fields.length > 0 &&
        requestBody.fields.every((field) => typeof field === "string") &&
        !requestBody.fields.includes("_id")
      ) {
        forwardBody = JSON.stringify({
          ...requestBody,
          fields: [...requestBody.fields, "_id"],
        });
        injectedId = true;
      }
    } catch {
      // Preserve malformed input so Couch returns its native JSON error.
    }

    const upstream = await fetchFromCouch(c, config, {
      body: forwardBody,
      headers: {
        Accept: "application/json",
        "Content-Type": c.req.header("content-type") || "application/json",
      },
    });
    if (!upstream.ok) return toClientResponse(upstream);
    let body: FindResponse;
    try {
      body = JSON.parse(
        await readResponseTextLimited(upstream, config.server.maxBodyBytes),
      ) as FindResponse;
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return couchError("bad_request", "Response body too large", 413);
      }
      throw err;
    }
    const principal = c.get("principal");
    const filtered = filterFindDocs(state, principal, body);
    logDecision("find", {
      decision: "filter",
      db: state.name,
      user: principal.name,
      upstreamDocs: body.docs?.length ?? 0,
      filteredDocs: filtered.docs.length,
      injectedId,
    });
    if (injectedId) {
      filtered.docs = filtered.docs.map(({ _id: _injectedId, ...doc }) => doc);
    }
    return toClientResponse(upstream, { body: JSON.stringify(filtered) });
  },

  /** Mango index management — admin only. */
  async indexAdmin(c) {
    const principal = c.get("principal");
    if (!principal.admin) {
      logDecision(
        "indexAdmin",
        {
          decision: "deny",
          reason: "not-admin",
          user: principal.name,
          method: c.req.method,
          path: c.req.path,
        },
        "debug",
      );
      return couchError("forbidden", "Index management requires admin.", 403);
    }
    return forwardToCouch(c, c.get("config"));
  },
};
