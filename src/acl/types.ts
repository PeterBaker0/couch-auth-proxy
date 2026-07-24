/**
 * Shared ACL value types used by the cache, resolvers, and filters.
 *
 * Document ACL is stored as compact view rows (`AclRow`). Bucket overlays
 * (`dbacl`, `restrict`) live on `_design/acl` and are applied on top of
 * per-document grants.
 */

/** Per-document read / write / delete capability flags. */
export type AclFlags = {
  _r: boolean;
  _w: boolean;
  _d: boolean;
};

/**
 * Compact ACL row value from `_design/acl/_view/acl`.
 *
 * Token maps use `1`/`true` as set membership (Couch map emit style).
 * Keys are principal tokens: `u-<name>`, `r-<role>`, or `r-*`.
 */
export type AclRow = {
  /**
   * Freshness stamp from the map (`_rev` in v2).
   * MUST NOT be compared to Couch `_changes` seq (opaque / not `_local_seq`).
   */
  s: string | number;
  /** Parent doc id for ACL inheritance; empty string if none. */
  p: string;
  /**
   * Retained tombstone row. Its grants remain usable for the document's own
   * `_changes` tombstone, but must not be inherited by children.
   */
  deleted?: true;
  _r: Record<string, 1 | true>;
  _w: Record<string, 1 | true>;
  _d: Record<string, 1 | true>;
};

/**
 * Database-wide ACL overlay from `_design/acl.dbacl`.
 * Matching tokens grant the corresponding flag on every document in the DB.
 */
export type DbAclOverlay = {
  _r?: string[];
  _w?: string[];
  _d?: string[];
};

/**
 * Path/method access controls from `_design/acl.restrict`.
 *
 * - `*` — who may see/use the DB at all (also hides from `_all_dbs` when set)
 * - `get` / `post` / … — map of path/query fragments → allowed tokens
 *
 * Fragments may use `*` (any chars) and `+` (any chars except `/`).
 */
export type RestrictMap = {
  "*"?: string[];
  get?: Record<string, string[]>;
  post?: Record<string, string[]>;
  put?: Record<string, string[]>;
  delete?: Record<string, string[]>;
  head?: Record<string, string[]>;
  [method: string]: string[] | Record<string, string[]> | undefined;
};
