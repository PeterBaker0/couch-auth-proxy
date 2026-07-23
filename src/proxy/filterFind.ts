/**
 * Filter Mango `_find` results by read ACL.
 *
 * Docs without `_id` are dropped (fail closed). After filtering, `limit` may
 * under-deliver relative to the request — same caveat as views.
 */
import type { Principal } from "../auth/types.js";
import type { DbAclState } from "../acl/cache.js";
import { canRead } from "../acl/lookup.js";

export type FindResponse = {
  docs: Array<{ _id?: string; [k: string]: unknown }>;
  bookmark?: string;
  warning?: string;
  execution_stats?: unknown;
  [k: string]: unknown;
};

/**
 * Drop docs the principal cannot read; preserve bookmark / stats fields.
 */
export function filterFindDocs(
  state: DbAclState,
  principal: Principal,
  body: FindResponse,
): FindResponse {
  const docs = (body.docs ?? []).filter((doc) => {
    const id = doc._id;
    if (!id || typeof id !== "string") return false;
    return canRead(state, principal, id);
  });
  return { ...body, docs };
}
