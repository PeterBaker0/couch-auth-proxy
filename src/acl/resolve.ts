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
 *
 * With `LOG_LEVEL=verbose`, every resolution emits a structured decision trail
 * (reason, matched tokens, final flags) so permission bugs are diagnosable.
 */
import type { Principal } from "../auth/types.js";
import { createLogger, isLevelEnabled, matchingTokens } from "../util/log.js";
import { unwindTokens } from "./restrict.js";
import type { AclFlags, AclRow, DbAclOverlay } from "./types.js";

const log = createLogger("acl-resolve");

/** Precompiled `dbacl` token sets, cached by overlay object identity. */
type CompiledDbacl = { _r: Set<string>; _w: Set<string>; _d: Set<string> };
const compiledDbaclCache = new WeakMap<DbAclOverlay, CompiledDbacl>();

function compiledDbacl(dbacl: DbAclOverlay): CompiledDbacl {
  let compiled = compiledDbaclCache.get(dbacl);
  if (!compiled) {
    compiled = {
      _r: unwindTokens(dbacl._r),
      _w: unwindTokens(dbacl._w),
      _d: unwindTokens(dbacl._d),
    };
    compiledDbaclCache.set(dbacl, compiled);
  }
  return compiled;
}

/**
 * Resolve r/w/d for a principal against a cached ACL row (+ optional parent + dbacl).
 *
 * When a row exists, flags start denied and tokens from the row/parent grant access.
 * When `noacl` is set, document ACLs and `dbacl` are not enforced because there
 * is no usable ACL map; the database passes through to Couch `_security`.
 * Design docs without grants remain non-writable for non-admins.
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
  const verbose = isLevelEnabled("verbose");

  if (principal.admin) {
    const flags = { _r: true, _w: true, _d: true };
    if (verbose) {
      log.verbose("resolve", {
        docId,
        user: principal.name,
        admin: true,
        reason: "admin",
        flags,
      });
    }
    return flags;
  }

  // Default open; tightened below when a concrete ACL row is present.
  const acl: AclFlags = { _r: true, _w: true, _d: true };
  let reason = "default-open";
  const designDoc = docId.startsWith("_design/");

  if (designDoc) {
    acl._w = false;
    acl._d = false;
    reason = "design-doc-default";
  }

  let matchedRow: { _r: string[]; _w: string[]; _d: string[] } | undefined;
  let matchedParent: { _r: string[]; _w: string[]; _d: string[] } | undefined;
  let matchedDbacl: { _r: string[]; _w: string[]; _d: string[] } | undefined;

  if (!noacl) {
    if (row) {
      // Row present → deny-by-default, then union grants from doc + parent.
      acl._r = acl._w = acl._d = false;
      reason = parentRow && !parentRow.deleted ? "row+parent" : "row";
      applyTokens(acl, row, principal.aclTokens);
      if (verbose) {
        matchedRow = {
          _r: matchingTokens(principal.aclTokens, row._r),
          _w: matchingTokens(principal.aclTokens, row._w),
          _d: matchingTokens(principal.aclTokens, row._d),
        };
      }
      // A deleted parent is retained only so prior readers can receive its
      // tombstone. It no longer exists and cannot grant access to children.
      if (parentRow && !parentRow.deleted) {
        applyTokens(acl, parentRow, principal.aclTokens);
        if (verbose) {
          matchedParent = {
            _r: matchingTokens(principal.aclTokens, parentRow._r),
            _w: matchingTokens(principal.aclTokens, parentRow._w),
            _d: matchingTokens(principal.aclTokens, parentRow._d),
          };
        }
      }
    } else if (verbose) {
      reason = designDoc ? "design-doc-default" : "no-row-default-open";
    }
  } else {
    reason = "noacl-passthrough";
  }

  if (dbacl) {
    // Empty docId is used for DB-level checks — start denied then apply overlay.
    if (!docId) {
      acl._r = acl._w = acl._d = false;
      reason = "dbacl-db-level";
    } else if (reason === "default-open" || reason === "no-row-default-open") {
      reason = "dbacl-overlay";
    } else if (!reason.includes("dbacl")) {
      reason = `${reason}+dbacl`;
    }
    applyDbacl(acl, dbacl, principal.aclTokens);
    if (verbose) {
      matchedDbacl = {
        _r: matchingTokens(principal.aclTokens, dbacl._r ?? []),
        _w: matchingTokens(principal.aclTokens, dbacl._w ?? []),
        _d: matchingTokens(principal.aclTokens, dbacl._d ?? []),
      };
    }
  }

  if (verbose) {
    log.verbose("resolve", {
      docId,
      user: principal.name,
      admin: false,
      noacl: !!noacl,
      reason,
      rowPresent: !!row,
      parentId: row?.p || undefined,
      parentPresent: !!parentRow,
      dbaclPresent: !!dbacl,
      matchedRow,
      matchedParent,
      matchedDbacl,
      flags: { ...acl },
    });
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
  // Match document/restrict semantics: bare grants are usernames, while roles
  // must be explicitly prefixed with `r-`. Sets are compiled once per overlay
  // object so list/_changes filters do not reallocate on every doc.
  const { _r: readers, _w: writers, _d: deleters } = compiledDbacl(dbacl);
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
  _rev?: string;
  creator?: unknown;
  owners?: unknown;
  acl?: unknown;
  parent?: unknown;
  _local_seq?: string | number;
}): AclRow {
  const row: AclRow = {
    s: doc._rev ?? doc._local_seq ?? 0,
    p: typeof doc.parent === "string" ? doc.parent : "",
    _r: {},
    _w: {},
    _d: {},
  };

  const hasCreator = Object.hasOwn(doc, "creator");
  const hasOwners = Object.hasOwn(doc, "owners");
  const hasAcl = Object.hasOwn(doc, "acl");
  const grantSourceCount = Number(hasCreator) + Number(hasOwners) + Number(hasAcl);
  const asUser = (v: string) => (v.startsWith("u-") ? v : `u-${v}`);
  const asUserOrRole = (v: string) => (v.startsWith("u-") || v.startsWith("r-") ? v : `u-${v}`);

  if (hasCreator && typeof doc.creator === "string" && doc.creator) {
    const userToken = asUser(doc.creator);
    row._r[userToken] = row._w[userToken] = row._d[userToken] = 1;
  }

  if (hasAcl && Array.isArray(doc.acl)) {
    for (const raw of doc.acl) {
      if (typeof raw !== "string") continue;
      const token = raw.startsWith("r-") || raw.startsWith("u-") ? raw : `u-${raw}`;
      row._r[token] = 1;
    }
  }

  if (hasOwners && Array.isArray(doc.owners)) {
    for (const raw of doc.owners) {
      if (typeof raw !== "string") continue;
      const token = asUserOrRole(raw);
      row._r[token] = 1;
      row._w[token] = 1;
    }
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
