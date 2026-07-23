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
    const id = row.id ?? row.doc?._id;
    if (!id) {
      // Reduce/group aggregates (and other id-less rows) cannot be ACL-checked —
      // drop them. View actor also forces reduce=false for non-admins.
      continue;
    }
    if (canRead(state, principal, String(id))) {
      rows.push(row);
    } else if (preserveDenied) {
      rows.push({ id: String(id), error: "not_found" });
    }
  }
  if (!principal.admin) {
    const { total_rows: _totalRows, offset: _offset, ...safeBody } = body;
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
