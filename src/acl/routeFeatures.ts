/**
 * Friendly route feature aliases for `ACL_ROUTE_INCLUDE` / `ACL_ROUTE_EXCLUDE`.
 *
 * Operators configure subsets of the Couch HTTP surface without enumerating
 * every Hono path. Bundles expand to feature sets at compile time.
 *
 * Each restmap `RouteDef` declares one or more of these feature tags.
 */

/** Atomic feature names that may appear on a `RouteDef`. */
export const ROUTE_FEATURES = [
  "root",
  "up",
  "uuids",
  "session",
  "all_dbs",
  "db",
  "docs",
  "attachments",
  "design",
  "local",
  "all_docs",
  "changes",
  "bulk_docs",
  "bulk_get",
  "find",
  "index",
  "views",
  "show",
  "update",
  "copy",
  "revs",
  "partition",
  "admin",
] as const;

export type RouteFeature = (typeof ROUTE_FEATURES)[number];

const FEATURE_SET = new Set<string>(ROUTE_FEATURES);

/**
 * Named bundles for common client profiles.
 * Values are feature names (not nested bundles).
 */
export const ROUTE_BUNDLES: Record<string, readonly RouteFeature[]> = {
  /** Minimal server discovery + auth. */
  server: ["root", "up", "uuids", "session", "all_dbs"],
  /**
   * PouchDB / Couch replication-style sync surface (non-admin).
   * Includes session, DB listing, docs, attachments, changes, bulk, revs, local, design, copy.
   */
  "pouch-sync": [
    "session",
    "all_dbs",
    "db",
    "docs",
    "attachments",
    "all_docs",
    "changes",
    "bulk_docs",
    "bulk_get",
    "revs",
    "local",
    "design",
    "copy",
  ],
  /** Document read/write without Mango/admin/partition. */
  documents: ["db", "docs", "attachments", "design", "local", "copy"],
  /** List/query surfaces commonly used by sync clients. */
  query: ["all_docs", "changes", "find", "views"],
};

/**
 * Expand a route policy entry that names a feature or bundle into feature tags.
 * Returns `null` when the entry is not a feature/bundle name (path/regex form).
 */
export function expandRouteAlias(entry: string): string[] | null {
  const name = entry.trim();
  if (!name || name.startsWith("/") || name.includes(" ")) return null;
  const bundle = ROUTE_BUNDLES[name];
  if (bundle) return [...bundle];
  if (FEATURE_SET.has(name)) return [name];
  return null;
}

/** True when `name` is a known atomic feature. */
export function isRouteFeature(name: string): name is RouteFeature {
  return FEATURE_SET.has(name);
}

/** True when `name` is a known bundle. */
export function isRouteBundle(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(ROUTE_BUNDLES, name);
}
