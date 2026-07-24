/**
 * Synchronous ACL lookups against a ready `DbAclState`.
 *
 * Actors call these after `AclCache.requireReady` (and often `ensureDocRow`)
 * to decide whether a principal may read/write/delete a document. Fail-closed
 * for reads when the row is not yet cached — never briefly open a doc.
 *
 * Verbose logs (`LOG_LEVEL=verbose`) explain missing-row create paths,
 * design-doc denials, and noacl/admin short-circuits.
 */
import type { Principal } from "../auth/types.js";
import { createLogger, isLevelEnabled } from "../util/log.js";
import type { AclCache, DbAclState } from "./cache.js";
import { resolveDocAcl } from "./resolve.js";
import type { AclFlags } from "./types.js";

const log = createLogger("acl-lookup");

/**
 * Resolve r/w/d flags for `docId` from the in-memory ACL cache.
 *
 * Semantics when the row is missing:
 * - `noacl` DB → full access (Couch `_security` only)
 * - `_design/*` → deny all (design docs must be known before access)
 * - other ids → write allowed (create path); read/delete denied until cached
 */
export function flagsForDoc(state: DbAclState, principal: Principal, docId: string): AclFlags {
  const verbose = isLevelEnabled("verbose");

  if (principal.admin || state.noacl) {
    const flags = { _r: true, _w: true, _d: true };
    if (verbose) {
      log.verbose("flagsForDoc", {
        db: state.name,
        docId,
        user: principal.name,
        reason: principal.admin ? "admin" : "noacl",
        flags,
      });
    }
    return flags;
  }
  const row = state.acl.get(docId);
  if (!row) {
    if (docId.startsWith("_design/")) {
      // Design docs must be known before non-admin access (incl. create).
      const flags = { _r: false, _w: false, _d: false };
      if (verbose) {
        log.verbose("flagsForDoc", {
          db: state.name,
          docId,
          user: principal.name,
          reason: "missing-design-row-deny",
          tombstone: state.tombstones?.has(docId) ?? false,
          flags,
        });
      }
      return flags;
    }
    // Create allowed; read/delete denied until the row is known.
    const flags = { _r: false, _w: true, _d: false };
    if (verbose) {
      log.verbose("flagsForDoc", {
        db: state.name,
        docId,
        user: principal.name,
        reason: "missing-row-create-path",
        tombstone: state.tombstones?.has(docId) ?? false,
        flags,
      });
    }
    return flags;
  }
  const parentRow = row.p ? state.acl.get(row.p) : undefined;
  // resolveDocAcl emits its own verbose trail for the row/parent/dbacl path.
  // Deleted tombstones keep retained grants for `_changes` visibility and for
  // recreate authorization by prior writers; they must not become a universal
  // create-path (`_w: true`) or `_revs_diff` would leak foreign deleted ids.
  return resolveDocAcl({
    principal,
    docId,
    row,
    parentRow,
    dbacl: state.dbacl,
    noacl: state.noacl,
  });
}

/** True if the principal may read `docId`. */
export function canRead(state: DbAclState, principal: Principal, docId: string): boolean {
  return flagsForDoc(state, principal, docId)._r;
}

/** True if the principal may write/update `docId` (or create if unknown). */
export function canWrite(state: DbAclState, principal: Principal, docId: string): boolean {
  return flagsForDoc(state, principal, docId)._w;
}

/** True if the principal may delete `docId`. */
export function canDelete(state: DbAclState, principal: Principal, docId: string): boolean {
  return flagsForDoc(state, principal, docId)._d;
}

/**
 * Ensure the ACL row (and parent row, if any) is present before single-doc checks.
 * Fetches missing rows via the admin ACL view — opaque-seq safe (keyed by id).
 */
export async function ensureDocRow(
  cache: AclCache,
  state: DbAclState,
  docId: string,
): Promise<void> {
  if (state.noacl) return;
  const hadRow = state.acl.has(docId);
  if (!hadRow) {
    if (isLevelEnabled("verbose")) {
      log.verbose("ensureDocRow refresh", { db: state.name, docId, reason: "missing-row" });
    }
    await cache.refreshDoc(state.name, docId);
  }
  const row = state.acl.get(docId);
  if (row?.p && !state.acl.has(row.p)) {
    if (isLevelEnabled("verbose")) {
      log.verbose("ensureDocRow refresh", {
        db: state.name,
        docId: row.p,
        reason: "missing-parent",
        childId: docId,
      });
    }
    await cache.refreshDoc(state.name, row.p);
  }
}
