/**
 * ACL filtering for write/replication bulk endpoints.
 *
 * - `_bulk_docs`: strip unauthorized docs; keep parallel result slots so denied
 *   entries still appear in the client-facing array
 * - `_revs_diff` / `_missing_revs`: keep keys the principal may read **or**
 *   write/delete (push replication probes new local docs that are not yet readable)
 */
import type { Principal } from "../auth/types.js";
import type { DbAclState } from "../acl/cache.js";
import { canDelete, canRead, canWrite } from "../acl/lookup.js";

export type BulkDoc = {
  _id?: string;
  _deleted?: boolean;
  [k: string]: unknown;
};

export type BulkDocsBody = {
  docs: BulkDoc[];
  all_or_nothing?: boolean;
  new_edits?: boolean;
  [k: string]: unknown;
};

export type BulkFilterResult = {
  /** Docs allowed to be sent upstream */
  allowed: BulkDoc[];
  /** Parallel result slots: null = filled from Couch, or pre-filled error */
  slots: Array<Record<string, unknown> | null>;
  /** True if any doc was rejected by ACL */
  hadDenied: boolean;
  /** Body fields other than docs */
  rest: Omit<BulkDocsBody, "docs">;
};

/**
 * Filter `_bulk_docs` write set by ACL.
 * New docs (no `_id`) are allowed through (Couch assigns id; VDU enforces creator).
 * Deletes require `_d`; updates require `_w`.
 */
export function filterBulkDocs(
  state: DbAclState,
  principal: Principal,
  body: BulkDocsBody,
  isValidId: (id: string) => boolean = () => true,
): BulkFilterResult {
  const docs = Array.isArray(body.docs) ? body.docs : [];
  const { docs: _docs, ...rest } = body;
  const allowed: BulkDoc[] = [];
  const slots: Array<Record<string, unknown> | null> = [];
  let hadDenied = false;

  for (const doc of docs) {
    if (!doc || typeof doc !== "object") {
      slots.push({ error: "error", reason: "Invalid object." });
      hadDenied = true;
      continue;
    }
    if (!doc._id) {
      allowed.push(doc);
      slots.push(null);
      continue;
    }
    const permitted =
      isValidId(doc._id) &&
      (doc._deleted ? canDelete(state, principal, doc._id) : canWrite(state, principal, doc._id));
    if (permitted) {
      allowed.push(doc);
      slots.push(null);
    } else {
      slots.push({ id: doc._id, error: "forbidden", reason: "ACL" });
      hadDenied = true;
    }
  }

  return { allowed, slots, hadDenied, rest };
}

/**
 * Merge Couch `_bulk_docs` response into pre-sized slots.
 * Null slots are filled in order from `couchResults`.
 */
export function mergeBulkResults(
  slots: Array<Record<string, unknown> | null>,
  couchResults: Array<Record<string, unknown>>,
): Array<Record<string, unknown>> {
  const out = slots.slice();
  let couchIndex = 0;
  for (let i = 0; i < out.length; i++) {
    if (out[i] == null) {
      out[i] = couchResults[couchIndex] ?? { error: "error", reason: "missing result" };
      couchIndex += 1;
    }
  }
  return out as Array<Record<string, unknown>>;
}

/**
 * Filter `_revs_diff` / `_missing_revs` request keys by ACL.
 *
 * Include ids the principal may read **or** write/delete. Push replication
 * probes missing revs for new local docs (not yet readable upstream); denying
 * those keys makes PouchDB/Couch clients silently skip the push.
 */
export function filterRevsObject(
  state: DbAclState,
  principal: Principal,
  body: Record<string, unknown>,
  isValidId: (id: string) => boolean = () => true,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [id, val] of Object.entries(body)) {
    if (
      isValidId(id) &&
      (canRead(state, principal, id) ||
        canWrite(state, principal, id) ||
        canDelete(state, principal, id))
    ) {
      out[id] = val;
    }
  }
  return out;
}
