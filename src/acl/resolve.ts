/**
 * Core document ACL resolution (r/w/d) for a principal.
 *
 * Combines:
 * 1. Admin short-circuit
 * 2. Design-doc default (read-only for non-admins when no grants)
 * 3. Document row + optional parent inheritance (most permissive wins)
 * 4. Bucket `dbacl` overlay from `_design/acl`
 *
 * `aclRowFromDoc` mirrors the default map function for unit tests / source of truth.
 */
import type { Principal } from "../auth/types.js";
import type { AclFlags, AclRow, DbAclOverlay } from "./types.js";

/**
 * Resolve r/w/d for a principal against a cached ACL row (+ optional parent + dbacl).
 *
 * When a row exists, flags start denied and tokens from the row/parent grant access.
 * When `noacl` is set, per-doc rows are ignored (pass-through) but `dbacl` still applies
 * if present. Design docs without grants remain non-writable for non-admins.
 */
export function resolveDocAcl(params: {
  principal: Principal;
  docId: string;
  row?: AclRow;
  parentRow?: AclRow;
  dbacl?: DbAclOverlay;
  noacl?: boolean;
}): AclFlags {
  const { principal, docId, row, parentRow, dbacl, noacl } = params;

  if (principal.admin) {
    return { _r: true, _w: true, _d: true };
  }

  // Default open; tightened below when a concrete ACL row is present.
  const acl: AclFlags = { _r: true, _w: true, _d: true };

  if (docId.startsWith("_design/")) {
    acl._w = false;
    acl._d = false;
  }

  if (!noacl) {
    if (row) {
      // Row present → deny-by-default, then union grants from doc + parent.
      acl._r = acl._w = acl._d = false;
      applyTokens(acl, row, principal.aclTokens);
      if (parentRow) applyTokens(acl, parentRow, principal.aclTokens);
    }
  }

  if (dbacl) {
    // Empty docId is used for DB-level checks — start denied then apply overlay.
    if (!docId) {
      acl._r = acl._w = acl._d = false;
    }
    applyDbacl(acl, dbacl, principal.aclTokens);
  }

  return acl;
}

/** OR-in any matching tokens from a compact ACL row onto `acl`. */
function applyTokens(acl: AclFlags, row: AclRow, tokens: string[]): void {
  for (const token of tokens) {
    if (!acl._r && row._r[token]) acl._r = true;
    if (!acl._w && row._w[token]) acl._w = true;
    if (!acl._d && row._d[token]) acl._d = true;
  }
}

/** OR-in matching tokens from the bucket-level `dbacl` overlay. */
function applyDbacl(acl: AclFlags, dbacl: DbAclOverlay, tokens: string[]): void {
  const asSet = (arr?: string[]) => new Set(arr ?? []);
  const readers = asSet(dbacl._r);
  const writers = asSet(dbacl._w);
  const deleters = asSet(dbacl._d);

  for (const token of tokens) {
    if (readers.has(token)) acl._r = true;
    if (writers.has(token)) acl._w = true;
    if (deleters.has(token)) acl._d = true;
  }
}

/**
 * Build an `AclRow` from document fields (same rules as the default map in `_design/acl`).
 *
 * Grant sources (`creator`, `acl`, `owners`):
 * - creator → r/w/d
 * - acl → read only (`_update` uses read, not write)
 * - owners → read + write (not delete)
 * - none of the above → `r-*` open (design docs: read-only `r-*`)
 */
export function aclRowFromDoc(doc: {
  _id: string;
  creator?: string;
  owners?: string[];
  acl?: string[];
  parent?: string;
  _local_seq?: string | number;
}): AclRow {
  const row: AclRow = {
    s: doc._local_seq ?? 0,
    p: typeof doc.parent === "string" ? doc.parent : "",
    _r: {},
    _w: {},
    _d: {},
  };

  let grantSourceCount = 0;
  const asUser = (v: string) => (v.startsWith("u-") || v.startsWith("r-") ? v : `u-${v}`);

  if (typeof doc.creator === "string" && doc.creator) {
    const userToken = asUser(doc.creator);
    row._r[userToken] = row._w[userToken] = row._d[userToken] = 1;
    grantSourceCount += 1;
  }

  if (Array.isArray(doc.acl)) {
    for (const raw of doc.acl) {
      if (typeof raw !== "string") continue;
      const token = raw.startsWith("r-") || raw.startsWith("u-") ? raw : `u-${raw}`;
      row._r[token] = 1;
    }
    grantSourceCount += 1;
  }

  if (Array.isArray(doc.owners)) {
    for (const raw of doc.owners) {
      if (typeof raw !== "string") continue;
      const token = asUser(raw);
      row._r[token] = 1;
      row._w[token] = 1;
    }
    grantSourceCount += 1;
  }

  if (!grantSourceCount) {
    const anyUser = "r-*";
    if (doc._id.startsWith("_design/")) {
      row._r[anyUser] = 1;
    } else {
      row._r[anyUser] = row._w[anyUser] = row._d[anyUser] = 1;
    }
  }

  return row;
}
