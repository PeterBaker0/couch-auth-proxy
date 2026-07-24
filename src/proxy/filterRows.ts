/**
 * Filter view / `_all_docs` / `_bulk_get` response rows by read ACL.
 *
 * Unauthorized docs are dropped, or (when `preserveDenied`) replaced with
 * `{ id, error: "not_found" }` so keyed POSTs keep positional alignment.
 * Unfiltered corpus metadata is omitted for non-admins.
 */
import type { Principal } from "../auth/types.js";
import type { DbAclState } from "../acl/cache.js";
import { canRead } from "../acl/lookup.js";
import { createLogger, isLevelEnabled } from "../util/log.js";

const log = createLogger("filter-rows");

/** One row from `_all_docs` / a view / similar list endpoints. */
export type CouchRow = {
  id?: string;
  key?: unknown;
  value?: unknown;
  doc?: { _id?: string; [k: string]: unknown };
  error?: string;
  [k: string]: unknown;
};

/** Couch rows response envelope. */
export type RowsResponse = {
  total_rows?: number;
  offset?: number;
  rows: CouchRow[];
  [k: string]: unknown;
};

/**
 * Filter view / `_all_docs` rows by read ACL.
 *
 * When `preserveDenied` (keyed queries only), unauthorized ids become `{id, error:"not_found"}`.
 *
 * Note: after filtering, `limit` may under-deliver rows relative to Couch — same as legacy.
 * Prefer key/keys queries in clients when exact counts matter.
 */
export function filterRows(
  state: DbAclState,
  principal: Principal,
  body: RowsResponse,
  options?: { preserveDenied?: boolean },
): RowsResponse {
  const preserveDenied = options?.preserveDenied ?? false;
  const rows: CouchRow[] = [];
  let dropped = 0;
  let placeholders = 0;
  let idless = 0;
  for (const row of body.rows ?? []) {
    const rowId = row.id ?? row.doc?._id;
    if (!rowId) {
      // Reduce/group aggregates (and other id-less rows) cannot be ACL-checked —
      // drop them. View actor also forces reduce=false for non-admins.
      idless += 1;
      continue;
    }

    // Linked views can return a different document through value._id when
    // include_docs=true: row.id remains the source while row.doc._id is the
    // linked target. Both must be readable before any embedded body is exposed.
    const embeddedId = row.doc?._id;
    const readable =
      canRead(state, principal, String(rowId)) &&
      (embeddedId == null || canRead(state, principal, String(embeddedId)));
    if (readable) {
      rows.push(row);
    } else if (preserveDenied) {
      placeholders += 1;
      rows.push({ id: String(rowId), error: "not_found" });
    } else {
      dropped += 1;
    }
  }
  if (isLevelEnabled("verbose")) {
    log.verbose("filterRows", {
      db: state.name,
      user: principal.name,
      upstream: body.rows?.length ?? 0,
      kept: rows.length - placeholders,
      dropped,
      placeholders,
      idless,
      preserveDenied,
    });
  }
  if (!principal.admin) {
    const { total_rows: _totalRows, offset: _offset, update_seq: _updateSeq, ...safeBody } = body;
    return { ...safeBody, rows };
  }
  return {
    ...body,
    rows,
  };
}

/**
 * Filter `_bulk_get` results: denied ids become a single not_found error doc.
 */
export function filterBulkGet(
  state: DbAclState,
  principal: Principal,
  body: { results?: Array<{ id: string; docs: unknown[] }> },
): typeof body {
  let denied = 0;
  const results = (body.results ?? []).map((result) => {
    if (!canRead(state, principal, result.id)) {
      denied += 1;
      return {
        id: result.id,
        docs: [{ error: { id: result.id, error: "not_found", reason: "missing" } }],
      };
    }
    return result;
  });
  if (isLevelEnabled("verbose")) {
    log.verbose("filterBulkGet", {
      db: state.name,
      user: principal.name,
      upstream: body.results?.length ?? 0,
      denied,
    });
  }
  return { ...body, results };
}
