/**
 * Declarative CouchDB 3.5 route → actor chains (Mango, COPY, partitioned APIs).
 * Each entry lists middleware-style actors that run in order; an actor may
 * short-circuit with a Response or call `next()`.
 *
 * `features` tags feed the opt-in `ACL_ROUTE_INCLUDE` / `ACL_ROUTE_EXCLUDE`
 * env policy (see `acl/routeFeatures.ts` and `acl/envAccessPolicy.ts`).
 *
 * Unsupported: `_list` (returns 501). Unmapped paths are default-denied in
 * `register.ts` (admins may still pipe).
 */

/** Named actors implemented in `actors.ts`. */
export type ActorName =
  | "pipe"
  | "admin"
  | "session"
  | "db"
  | "doc"
  | "docWrite"
  | "docDelete"
  | "docUpdate" // update handler: require read/write/delete
  | "rows"
  | "changes"
  | "bulk"
  | "bulkGet"
  | "revs"
  | "dblist"
  | "list501"
  | "unsupported"
  | "find"
  | "indexAdmin"
  | "copy";

export type HttpMethod = "get" | "post" | "put" | "delete" | "head" | "copy";

export type RouteDef = {
  method: HttpMethod;
  /** Hono path pattern */
  path: string;
  actors: ActorName[];
  /**
   * Friendly feature tags for env route policy.
   * At least one tag should be present for every restmap route.
   */
  features: string[];
};

/**
 * Full route table. Order among overlapping patterns matters for Hono matching;
 * more specific paths (e.g. `/_design/.../_view/...`) are listed before generics.
 */
export const ROUTES: RouteDef[] = [
  // —— Server-level ——
  { method: "get", path: "/", actors: ["pipe"], features: ["root"] },
  { method: "get", path: "/_up", actors: ["pipe"], features: ["up"] },
  { method: "get", path: "/_uuids", actors: ["pipe"], features: ["uuids"] },
  { method: "get", path: "/_session", actors: ["session"], features: ["session"] },
  { method: "post", path: "/_session", actors: ["session"], features: ["session"] },
  { method: "delete", path: "/_session", actors: ["session"], features: ["session"] },
  { method: "get", path: "/_all_dbs", actors: ["dblist"], features: ["all_dbs"] },
  { method: "head", path: "/_all_dbs", actors: ["dblist"], features: ["all_dbs"] },
  { method: "get", path: "/_dbs_info", actors: ["admin"], features: ["admin"] },
  { method: "post", path: "/_dbs_info", actors: ["admin"], features: ["admin"] },
  { method: "get", path: "/_active_tasks", actors: ["admin"], features: ["admin"] },
  { method: "get", path: "/_db_updates", actors: ["admin"], features: ["admin"] },
  { method: "post", path: "/_replicate", actors: ["admin"], features: ["admin"] },
  { method: "get", path: "/_scheduler/:rest{.*}", actors: ["admin"], features: ["admin"] },
  { method: "get", path: "/_node/:rest{.*}", actors: ["admin"], features: ["admin"] },
  { method: "put", path: "/_node/:rest{.*}", actors: ["admin"], features: ["admin"] },
  { method: "get", path: "/_utils", actors: ["admin"], features: ["admin"] },
  { method: "get", path: "/_utils/:rest{.*}", actors: ["admin"], features: ["admin"] },

  // —— Database-level ——
  { method: "get", path: "/:db", actors: ["db", "pipe"], features: ["db"] },
  { method: "head", path: "/:db", actors: ["db", "pipe"], features: ["db"] },
  { method: "put", path: "/:db", actors: ["admin"], features: ["admin"] },
  { method: "delete", path: "/:db", actors: ["admin"], features: ["admin"] },
  { method: "post", path: "/:db", actors: ["db", "docWrite", "pipe"], features: ["docs"] },

  { method: "get", path: "/:db/_all_docs", actors: ["db", "rows"], features: ["all_docs"] },
  { method: "head", path: "/:db/_all_docs", actors: ["db", "rows"], features: ["all_docs"] },
  { method: "post", path: "/:db/_all_docs", actors: ["db", "rows"], features: ["all_docs"] },
  { method: "get", path: "/:db/_design_docs", actors: ["db", "rows"], features: ["all_docs"] },
  { method: "head", path: "/:db/_design_docs", actors: ["db", "rows"], features: ["all_docs"] },
  { method: "post", path: "/:db/_design_docs", actors: ["db", "rows"], features: ["all_docs"] },
  { method: "get", path: "/:db/_local_docs", actors: ["db", "rows"], features: ["all_docs"] },
  { method: "head", path: "/:db/_local_docs", actors: ["db", "rows"], features: ["all_docs"] },
  { method: "post", path: "/:db/_local_docs", actors: ["db", "rows"], features: ["all_docs"] },
  { method: "post", path: "/:db/_bulk_docs", actors: ["db", "bulk"], features: ["bulk_docs"] },
  { method: "post", path: "/:db/_bulk_get", actors: ["db", "bulkGet"], features: ["bulk_get"] },
  { method: "get", path: "/:db/_changes", actors: ["db", "changes"], features: ["changes"] },
  { method: "post", path: "/:db/_changes", actors: ["db", "changes"], features: ["changes"] },
  { method: "post", path: "/:db/_find", actors: ["db", "find"], features: ["find"] },
  {
    method: "post",
    path: "/:db/_index",
    actors: ["db", "indexAdmin"],
    features: ["index", "admin"],
  },
  {
    method: "get",
    path: "/:db/_index",
    actors: ["db", "indexAdmin"],
    features: ["index", "admin"],
  },
  {
    method: "delete",
    path: "/:db/_index/:ddoc/json/:name",
    actors: ["db", "indexAdmin"],
    features: ["index", "admin"],
  },
  // `_explain` can leak index/selector metadata — admin only.
  {
    method: "post",
    path: "/:db/_explain",
    actors: ["db", "indexAdmin"],
    features: ["index", "admin"],
  },
  { method: "post", path: "/:db/_revs_diff", actors: ["db", "revs"], features: ["revs"] },
  { method: "post", path: "/:db/_missing_revs", actors: ["db", "revs"], features: ["revs"] },

  { method: "get", path: "/:db/_security", actors: ["admin"], features: ["admin"] },
  { method: "put", path: "/:db/_security", actors: ["admin"], features: ["admin"] },
  { method: "get", path: "/:db/_revs_limit", actors: ["admin"], features: ["admin"] },
  { method: "put", path: "/:db/_revs_limit", actors: ["admin"], features: ["admin"] },
  { method: "post", path: "/:db/_compact", actors: ["admin"], features: ["admin"] },
  { method: "post", path: "/:db/_compact/:ddoc", actors: ["admin"], features: ["admin"] },
  { method: "post", path: "/:db/_view_cleanup", actors: ["admin"], features: ["admin"] },
  { method: "post", path: "/:db/_purge", actors: ["admin"], features: ["admin"] },
  { method: "post", path: "/:db/_ensure_full_commit", actors: ["admin"], features: ["admin"] },

  // —— Partitioned DB APIs — list/query surfaces filtered; other partition paths admin ——
  {
    method: "get",
    path: "/:db/_partition/:partition",
    actors: ["admin"],
    features: ["partition", "admin"],
  },
  {
    method: "get",
    path: "/:db/_partition/:partition/_all_docs",
    actors: ["db", "rows"],
    features: ["partition", "all_docs"],
  },
  {
    method: "head",
    path: "/:db/_partition/:partition/_all_docs",
    actors: ["db", "rows"],
  },
  {
    method: "post",
    path: "/:db/_partition/:partition/_all_docs",
    actors: ["db", "rows"],
    features: ["partition", "all_docs"],
  },
  {
    method: "post",
    path: "/:db/_partition/:partition/_find",
    actors: ["db", "find"],
    features: ["partition", "find"],
  },
  {
    method: "get",
    path: "/:db/_partition/:partition/_design/:ddoc/_view/:view",
    actors: ["db", "rows"],
    features: ["partition", "views"],
  },
  {
    method: "head",
    path: "/:db/_partition/:partition/_design/:ddoc/_view/:view",
    actors: ["db", "rows"],
  },
  {
    method: "post",
    path: "/:db/_partition/:partition/_design/:ddoc/_view/:view",
    actors: ["db", "rows"],
    features: ["partition", "views"],
  },
  {
    method: "get",
    path: "/:db/_partition/:partition/:rest{.*}",
    actors: ["admin"],
    features: ["partition", "admin"],
  },
  {
    method: "post",
    path: "/:db/_partition/:partition/:rest{.*}",
    actors: ["admin"],
    features: ["partition", "admin"],
  },

  // —— Design docs / views ——
  // Search/Nouveau results can embed hits without ACL rows — admin only.
  {
    method: "get",
    path: "/:db/_design/:ddoc/_search/:index",
    actors: ["admin"],
    features: ["admin"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_search/:index",
    actors: ["admin"],
    features: ["admin"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_search_info/:index",
    actors: ["admin"],
    features: ["admin"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_nouveau/:index",
    actors: ["admin"],
    features: ["admin"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_nouveau/:index",
    actors: ["admin"],
    features: ["admin"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_nouveau_info/:index",
    actors: ["admin"],
    features: ["admin"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_search_disk_size/:index",
    actors: ["admin"],
    features: ["admin"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_view/:view",
    actors: ["db", "rows"],
    features: ["views"],
  },
  {
    method: "head",
    path: "/:db/_design/:ddoc/_view/:view",
    actors: ["db", "rows"],
    features: ["views"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_view/:view",
    actors: ["db", "rows"],
    features: ["views"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_list/:list/:view",
    actors: ["list501"],
    features: ["views"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_list/:list/:view",
    actors: ["list501"],
    features: ["views"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_list/:list/:ddoc2/:view",
    actors: ["list501"],
    features: ["views"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_list/:list/:ddoc2/:view",
    actors: ["list501"],
    features: ["views"],
  },
  // Show/update without a target doc can emit or mutate arbitrarily — reject.
  {
    method: "get",
    path: "/:db/_design/:ddoc/_show/:show",
    actors: ["unsupported"],
    features: ["show"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_show/:show",
    actors: ["unsupported"],
    features: ["show"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_show/:show/:docId",
    actors: ["db", "doc", "pipe"],
    features: ["show"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_show/:show/:docId",
    actors: ["db", "doc", "pipe"],
    features: ["show"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_update/:update",
    actors: ["unsupported"],
    features: ["update"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_update/:update",
    actors: ["unsupported"],
    features: ["update"],
  },
  {
    method: "head",
    path: "/:db/_design/:ddoc/_update/:update",
    actors: ["unsupported"],
    features: ["update"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_update/:update/:docId",
    actors: ["db", "docUpdate", "pipe"],
    features: ["update"],
  },
  {
    method: "head",
    path: "/:db/_design/:ddoc/_update/:update/:docId",
    actors: ["db", "docUpdate", "pipe"],
    features: ["update"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_update/:update/:docId",
    actors: ["db", "docUpdate", "pipe"],
    features: ["update"],
  },
  {
    method: "put",
    path: "/:db/_design/:ddoc/_update/:update/:docId",
    actors: ["db", "docUpdate", "pipe"],
    features: ["update"],
  },
  { method: "get", path: "/:db/_design/:ddoc/_info", actors: ["admin"], features: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_rewrite", actors: ["admin"], features: ["admin"] },
  { method: "post", path: "/:db/_design/:ddoc/_rewrite", actors: ["admin"], features: ["admin"] },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_rewrite/:rest{.*}",
    actors: ["admin"],
    features: ["admin"],
  },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_rewrite/:rest{.*}",
    actors: ["admin"],
    features: ["admin"],
  },

  // Reserved design API roots are never interpreted as attachment names.
  {
    method: "get",
    path: "/:db/_design/:ddoc/_view",
    actors: ["unsupported"],
    features: ["views"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_list",
    actors: ["list501"],
    features: ["views"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_show",
    actors: ["unsupported"],
    features: ["show"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_update",
    actors: ["unsupported"],
    features: ["update"],
  },
  { method: "get", path: "/:db/_design/:ddoc/_search", actors: ["admin"], features: ["admin"] },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_search_info",
    actors: ["admin"],
    features: ["admin"],
  },
  { method: "get", path: "/:db/_design/:ddoc/_nouveau", actors: ["admin"], features: ["admin"] },
  {
    method: "get",
    path: "/:db/_design/:ddoc/_nouveau_info",
    actors: ["admin"],
    features: ["admin"],
  },

  {
    method: "get",
    path: "/:db/_design/:ddoc",
    actors: ["db", "doc", "pipe"],
    features: ["design"],
  },
  {
    method: "head",
    path: "/:db/_design/:ddoc",
    actors: ["db", "doc", "pipe"],
    features: ["design"],
  },
  {
    method: "put",
    path: "/:db/_design/:ddoc",
    actors: ["db", "docWrite", "pipe"],
    features: ["design"],
  },
  {
    method: "delete",
    path: "/:db/_design/:ddoc",
    actors: ["db", "docDelete", "pipe"],
    features: ["design"],
  },
  {
    method: "copy",
    path: "/:db/_design/:ddoc",
    actors: ["db", "copy"],
    features: ["design", "copy"],
  },
  {
    method: "get",
    path: "/:db/_design/:ddoc/:attachment{.+}",
    actors: ["db", "doc", "pipe"],
    features: ["design", "attachments"],
  },
  {
    method: "head",
    path: "/:db/_design/:ddoc/:attachment{.+}",
    actors: ["db", "doc", "pipe"],
    features: ["design", "attachments"],
  },
  {
    method: "put",
    path: "/:db/_design/:ddoc/:attachment{.+}",
    actors: ["db", "docWrite", "pipe"],
    features: ["design", "attachments"],
  },
  {
    method: "delete",
    path: "/:db/_design/:ddoc/:attachment{.+}",
    actors: ["db", "docWrite", "pipe"],
    features: ["design", "attachments"],
  },

  // —— Local docs — pipe after DB gate (Pouch checkpoints; no per-doc ACL rows) ——
  { method: "get", path: "/:db/_local/:docId", actors: ["db", "pipe"], features: ["local"] },
  { method: "put", path: "/:db/_local/:docId", actors: ["db", "pipe"], features: ["local"] },
  { method: "delete", path: "/:db/_local/:docId", actors: ["db", "pipe"], features: ["local"] },

  // —— Regular docs + attachments + COPY ——
  { method: "get", path: "/:db/:docId", actors: ["db", "doc", "pipe"], features: ["docs"] },
  { method: "head", path: "/:db/:docId", actors: ["db", "doc", "pipe"], features: ["docs"] },
  { method: "put", path: "/:db/:docId", actors: ["db", "docWrite", "pipe"], features: ["docs"] },
  {
    method: "delete",
    path: "/:db/:docId",
    actors: ["db", "docDelete", "pipe"],
    features: ["docs"],
  },
  { method: "copy", path: "/:db/:docId", actors: ["db", "copy"], features: ["docs", "copy"] },
  {
    method: "get",
    path: "/:db/:docId/:attachment{.+}",
    actors: ["db", "doc", "pipe"],
    features: ["attachments"],
  },
  {
    method: "head",
    path: "/:db/:docId/:attachment{.+}",
    actors: ["db", "doc", "pipe"],
    features: ["attachments"],
  },
  {
    method: "put",
    path: "/:db/:docId/:attachment{.+}",
    actors: ["db", "docWrite", "pipe"],
    features: ["attachments"],
  },
  {
    method: "delete",
    path: "/:db/:docId/:attachment{.+}",
    actors: ["db", "docWrite", "pipe"],
    features: ["attachments"],
  },
];
