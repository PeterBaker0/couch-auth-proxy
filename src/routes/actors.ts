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
import { AclUnavailableError, DbMissingError } from "../acl/cache.js";
import { isDatabaseName, isDocumentId } from "../acl/names.js";
import { dbAccessLevel, methodAllowed } from "../acl/restrict.js";
import { canDelete, canRead, ensureDocRow, flagsForDoc } from "../acl/lookup.js";
import { aclRowFromDoc } from "../acl/resolve.js";
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
  normalizeBulkResults,
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

type AppContext = Context<AppEnv>;

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
  return isDocumentId(id, c.get("config").couch.maxIdLength);
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
    return forwardToCouch(c, c.get("config"));
  },

  /** Session endpoints — pipe to Couch; drop cached principal on logout. */
  async session(c) {
    if (c.req.method === "DELETE") {
      c.get("sessions").invalidate(c.req.raw.headers);
    }
    return forwardToCouch(c, c.get("config"));
  },

  /** Server-admin only; everyone else gets 403. */
  async admin(c) {
    if (!c.get("principal").admin) {
      return couchError("forbidden", "Access denied.", 403);
    }
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
      if (c.get("principal").admin) {
        return forwardToCouch(c, c.get("config"));
      }
      return couchError("forbidden", "Access denied.", 403);
    }

    let state;
    try {
      state = await c.get("aclCache").requireReady(db);
    } catch (err) {
      if (err instanceof DbMissingError) {
        // Let Couch return its native missing-db error.
        return forwardToCouch(c, c.get("config"));
      }
      if (err instanceof AclUnavailableError) {
        return couchError("service_unavailable", "ACL cache unavailable", 503);
      }
      // Fail closed on unexpected errors — never open the DB.
      return couchError("service_unavailable", "ACL cache unavailable", 503);
    }

    const principal = c.get("principal");
    const level = dbAccessLevel(principal, state.compiledRestrict, state.noacl);
    if (level === 0) {
      // Hide restricted DBs as not_found (same as missing).
      return couchError("not_found", "ACL", 404);
    }

    const after = urlAfterDb(c, db);
    if (!methodAllowed(principal, state.compiledRestrict, c.req.method, after)) {
      return couchError("forbidden", "Method restricted.", 403);
    }

    if (state.noacl) {
      // Skip per-document ACL actors, but continue so route-level controls
      // such as indexAdmin still run on pass-through/system databases.
      await next();
      return;
    }

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
      if (c.get("principal").admin) return forwardToCouch(c, c.get("config"));
      return couchError("not_found", "Unsupported endpoint.", 404);
    }
    await ensureDocRow(c.get("aclCache"), state, id);
    if (!canRead(state, c.get("principal"), id)) {
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
    let parsedDocument: Record<string, unknown> | undefined;
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
          parsedDocument = parsed as Record<string, unknown>;
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
        if (principal.admin) return forwardToCouch(c, c.get("config"));
        return couchError("not_found", "Unsupported endpoint.", 404);
      }
      await ensureDocRow(c.get("aclCache"), state, id);
      const flags = flagsForDoc(state, principal, id);
      if (deleting ? !flags._d : !flags._w) {
        return couchError("forbidden", "ACL", 403);
      }
    }

    if (bodyParseFailed) {
      const contentType = c.req.header("content-type")?.toLowerCase() ?? "";
      if (contentType.startsWith("multipart/")) {
        return couchError(
          "not_implemented",
          "Multipart document writes are unsupported for non-admins. Use JSON documents and attachment endpoints.",
          415,
        );
      }
      return couchError("bad_request", "Invalid JSON document.", 400);
    }

    if (bufferedBody !== undefined) {
      const config = c.get("config");
      const upstream = await fetchFromCouch(c, config, {
        body: bufferedBody,
        headers: {
          "Content-Type": c.req.header("content-type") || "application/json",
        },
      });
      if (upstream.ok && id && parsedDocument) {
        if (deleting) {
          const retained = state.acl.get(id);
          if (retained) state.acl.set(id, { ...retained, deleted: true });
        } else {
          const aclDoc: Parameters<typeof aclRowFromDoc>[0] = { _id: id };
          if (typeof parsedDocument._rev === "string") aclDoc._rev = parsedDocument._rev;
          for (const field of ["creator", "owners", "acl", "parent"] as const) {
            if (Object.hasOwn(parsedDocument, field)) aclDoc[field] = parsedDocument[field];
          }
          state.acl.set(id, aclRowFromDoc(aclDoc));
        }
      }
      return toClientResponse(upstream, {
        rewriteLocation: {
          fromOrigin: new URL(config.couch.url).origin,
          toOrigin: new URL(c.req.url).origin,
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
      if (c.get("principal").admin) return forwardToCouch(c, c.get("config"));
      return couchError("not_found", "Unsupported endpoint.", 404);
    }
    await ensureDocRow(c.get("aclCache"), state, id);
    if (!canDelete(state, c.get("principal"), id)) {
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
      if (c.get("principal").admin) return forwardToCouch(c, c.get("config"));
      return couchError("not_found", "Unsupported endpoint.", 404);
    }
    await ensureDocRow(c.get("aclCache"), state, id);
    const flags = flagsForDoc(state, c.get("principal"), id);
    if (!flags._r) {
      return couchError("not_found", "missing", 404);
    }
    if (!flags._w || !flags._d) return couchError("forbidden", "ACL", 403);
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
      if (c.get("principal").admin) return forwardToCouch(c, c.get("config"));
      return couchError("not_found", "Unsupported endpoint.", 404);
    }
    await ensureDocRow(c.get("aclCache"), state, id);
    if (!canRead(state, c.get("principal"), id)) {
      return couchError("not_found", "missing", 404);
    }
    const destHeader = c.req.header("Destination") || c.req.header("destination");
    if (!destHeader) return couchError("bad_request", "Destination header required", 400);
    const destId = copyDestinationId(destHeader);
    if (!destId || !validDocumentId(c, destId)) {
      return couchError("bad_request", "Invalid COPY destination", 400);
    }
    await ensureDocRow(c.get("aclCache"), state, destId);
    const destFlags = flagsForDoc(state, c.get("principal"), destId);
    if (!destFlags._w) return couchError("forbidden", "ACL", 403);
    return forwardToCouch(c, c.get("config"));
  },

  /** Proxy then filter `_all_docs` / view rows by read ACL. */
  async rows(c) {
    const state = c.get("dbAclState");
    if (!state) return forwardToCouch(c, c.get("config"));

    const config = c.get("config");
    const principal = c.get("principal");
    const isView = c.req.path.includes("/_view/");
    const isHead = c.req.method === "HEAD";
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
      ...(isHead ? { method: "GET" } : {}),
      stripRequestHeaders: ["if-none-match", "if-modified-since"],
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

    // Only document-id list APIs may preserve denied keyed slots. Custom view
    // keys are arbitrary values and do not prove the caller knows row ids.
    const hasKeys =
      c.req.query("keys") != null ||
      c.req.query("key") != null ||
      requestBodyJson?.keys != null ||
      requestBodyJson?.key != null;
    const filtered = filterRows(state, principal, body, {
      preserveDenied: hasKeys && !isView,
    });
    const response = toClientResponse(upstream, {
      body: isHead ? null : JSON.stringify(filtered),
      stripHeaders: ["etag", "last-modified"],
    });
    response.headers.set("Cache-Control", "private, no-store");
    return response;
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
      feed !== "live" &&
      feed !== "eventsource"
    ) {
      return couchError("bad_request", "Unsupported _changes feed.", 400);
    }
    const upstream = await fetchFromCouch(c, config, {
      stripRequestHeaders: ["if-none-match", "if-modified-since"],
    });
    if (!upstream.ok || !upstream.body) return toClientResponse(upstream);

    const filtered = filterChangesStream(
      upstream.body,
      state,
      c.get("principal"),
      feed === "live" ? "continuous" : feed,
      {
        maxBufferBytes: config.server.maxBodyBytes,
      },
    );
    const response = toClientResponse(upstream, {
      body: filtered,
      stripHeaders: ["etag", "last-modified"],
    });
    response.headers.set("Cache-Control", "private, no-store");
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
    await Promise.all(
      (body.docs ?? [])
        .filter((doc) => doc && typeof doc._id === "string" && validDocumentId(c, doc._id))
        .map((doc) => ensureDocRow(cache, state, doc._id!)),
    );

    const filtered = filterBulkDocs(state, c.get("principal"), body, (id) =>
      validDocumentId(c, id),
    );
    const atomic = String(body.all_or_nothing) === "true";
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
    results = normalizeBulkResults(
      filtered.allowed,
      results,
      String(body.new_edits) === "false",
    );
    for (let i = 0; i < filtered.allowed.length; i++) {
      const doc = filtered.allowed[i];
      const result = results[i];
      if (!doc || typeof doc._id !== "string" || result?.error) continue;
      if (doc._deleted) {
        const retained = state.acl.get(doc._id);
        if (retained) state.acl.set(doc._id, { ...retained, deleted: true });
      } else {
        state.acl.set(
          doc._id,
          aclRowFromDoc(doc as Parameters<typeof aclRowFromDoc>[0]),
        );
      }
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
    const upstream = await fetchFromCouch(c, config, {
      headers: { Accept: "application/json" },
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
    return toClientResponse(upstream, {
      body: JSON.stringify(filterBulkGet(state, c.get("principal"), body)),
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
    await Promise.all(
      Object.keys(body)
        .filter((id) => validDocumentId(c, id))
        .map((id) => ensureDocRow(cache, state, id)),
    );
    const filtered = filterRevsObject(state, c.get("principal"), body, (id) =>
      validDocumentId(c, id),
    );
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
    const principal = c.get("principal");
    if (principal.admin) return forwardToCouch(c, c.get("config"));

    const isHead = c.req.method === "HEAD";
    const upstream = await fetchFromCouch(c, c.get("config"), {
      ...(isHead ? { method: "GET" } : {}),
      stripRequestHeaders: ["if-none-match", "if-modified-since"],
      headers: { Accept: "application/json" },
    });
    if (!upstream.ok) return toClientResponse(upstream);

    const dbs = (await upstream.json()) as string[];
    if (!Array.isArray(dbs)) {
      return toClientResponse(upstream, {
        body: isHead ? null : JSON.stringify(dbs),
        stripHeaders: ["etag", "last-modified"],
      });
    }

    const cache = c.get("aclCache");
    const visible: string[] = [];
    for (const db of dbs) {
      try {
        const policy = await cache.inspectAccessPolicy(db);
        if (dbAccessLevel(principal, policy.compiledRestrict, policy.noacl) > 0) {
          visible.push(db);
        }
      } catch {}
    }
    const response = toClientResponse(upstream, {
      body: isHead ? null : JSON.stringify(visible),
      stripHeaders: ["etag", "last-modified"],
    });
    response.headers.set("Cache-Control", "private, no-store");
    return response;
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
    const filtered = filterFindDocs(state, c.get("principal"), body);
    if (injectedId) {
      filtered.docs = filtered.docs.map(({ _id: _injectedId, ...doc }) => doc);
    }
    return toClientResponse(upstream, { body: JSON.stringify(filtered) });
  },

  /** Mango index management — admin only. */
  async indexAdmin(c) {
    if (!c.get("principal").admin) {
      return couchError("forbidden", "Index management requires admin.", 403);
    }
    return forwardToCouch(c, c.get("config"));
  },
};
