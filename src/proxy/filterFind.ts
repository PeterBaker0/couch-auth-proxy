/**
 * Filter Mango `_find` results by read ACL.
 *
 * Docs without `_id` are dropped (fail closed). After filtering, `limit` may
 * under-deliver relative to the request — same caveat as views.
 */
import type { Principal } from "../auth/types.js";
import type { DbAclState } from "../acl/cache.js";
import { canRead } from "../acl/lookup.js";
import { createLogger, isLevelEnabled } from "../util/log.js";

const log = createLogger("filter-find");

export type FindResponse = {
  docs: Array<{ _id?: string; [k: string]: unknown }>;
  bookmark?: string;
  warning?: string;
  execution_stats?: unknown;
  [k: string]: unknown;
};

/**
 * Drop docs the principal cannot read. Preserve paging fields, but omit
 * unfiltered execution statistics for non-admins.
 */
export function filterFindDocs(
  state: DbAclState,
  principal: Principal,
  body: FindResponse,
): FindResponse {
  const upstream = body.docs?.length ?? 0;
  const docs = (body.docs ?? []).filter((doc) => {
    const id = doc._id;
    if (!id || typeof id !== "string") return false;
    return canRead(state, principal, id);
  });
  if (isLevelEnabled("verbose")) {
    log.verbose("filterFindDocs", {
      db: state.name,
      user: principal.name,
      upstream,
      kept: docs.length,
      dropped: upstream - docs.length,
    });
  }
  if (!principal.admin) {
    const { execution_stats: _executionStats, ...safeBody } = body;
    return { ...safeBody, docs };
  }
  return { ...body, docs };
}
