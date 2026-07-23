/**
 * CouchDB name classification helpers.
 *
 * Distinguishes real database/document targets from reserved `/_*` server
 * endpoints so routing never treats e.g. `_membership` as a DB or
 * `_purged_infos_limit` as a document id.
 */

/** Couch system databases that are valid `/:db` targets. */
const SYSTEM_DBS = new Set(["_users", "_replicator", "_global_changes"]);

/**
 * True for Couch system DBs — couch-auth-proxy never auto-installs `_design/acl`
 * into these (pass-through / out-of-band provision only).
 */
export function isSystemDatabase(name: string): boolean {
  return SYSTEM_DBS.has(name);
}

/**
 * True when `name` is a real database name (not a server-level `/_*` endpoint).
 * Unknown underscore names like `_membership` must not be treated as DBs.
 */
export function isDatabaseName(name: string): boolean {
  if (!name || name === "." || name === "..") return false;
  if (name.startsWith("_")) return isSystemDatabase(name);
  return true;
}

/**
 * True when `id` is a normal doc id or a known special prefix (`_design/`, `_local/`).
 * Other underscore ids are reserved Couch endpoints (e.g. `_purged_infos_limit`).
 */
export function isDocumentId(id: string, maxLength = Number.POSITIVE_INFINITY): boolean {
  if (!id || id.length > maxLength) return false;
  if (!id.startsWith("_")) return true;
  return id.startsWith("_design/") || id.startsWith("_local/");
}
