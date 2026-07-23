/**
 * Filter view / `_all_docs` / `_bulk_get` response rows by read ACL.
 *
 * Unauthorized docs are dropped, or (when `preserveDenied`) replaced with
 * `{ id, error: "not_found" }` so keyed POSTs keep positional alignment.
 * `total_rows` is left as Couch reported it (index size), not the filtered length.
 */
import type { Principal } from "../auth/types.js";
import type { DbAclState } from "../acl/cache.js";
import { canRead } from "../acl/lookup.js";

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
  for (const row of body.rows ?? []) {
    const rowId = row.id ?? row.doc?._id;
    if (!rowId) {
      // Reduce/group aggregates (and other id-less rows) cannot be ACL-checked —
      // drop them. View actor also forces reduce=false for non-admins.
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
      rows.push({ id: String(rowId), error: "not_found" });
    }
  }
  return {
    ...body,
    rows,
    // Keep Couch's total_rows (index size); do not lie that filtered length is total.
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
  const results = (body.results ?? []).map((result) => {
    if (!canRead(state, principal, result.id)) {
      return {
        id: result.id,
        docs: [{ error: { id: result.id, error: "not_found", reason: "missing" } }],
      };
    }
    return result;
  });
  return { ...body, results };
}
