/**
 * Declarative CouchDB 3.5 route → actor chains (Mango, COPY, partitioned APIs).
 * Each entry lists middleware-style actors that run in order; an actor may
 * short-circuit with a Response or call `next()`.
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
};

/**
 * Full route table. Order among overlapping patterns matters for Hono matching;
 * more specific paths (e.g. `/_design/.../_view/...`) are listed before generics.
 */
export const ROUTES: RouteDef[] = [
  // —— Server-level ——
  { method: "get", path: "/", actors: ["pipe"] },
  { method: "get", path: "/_up", actors: ["pipe"] },
  { method: "get", path: "/_uuids", actors: ["pipe"] },
  { method: "get", path: "/_session", actors: ["session"] },
  { method: "post", path: "/_session", actors: ["session"] },
  { method: "delete", path: "/_session", actors: ["session"] },
  { method: "get", path: "/_all_dbs", actors: ["dblist"] },
  { method: "get", path: "/_dbs_info", actors: ["admin"] },
  { method: "post", path: "/_dbs_info", actors: ["admin"] },
  { method: "get", path: "/_active_tasks", actors: ["admin"] },
  { method: "get", path: "/_db_updates", actors: ["admin"] },
  { method: "post", path: "/_replicate", actors: ["admin"] },
  { method: "get", path: "/_scheduler/:rest{.*}", actors: ["admin"] },
  { method: "get", path: "/_node/:rest{.*}", actors: ["admin"] },
  { method: "put", path: "/_node/:rest{.*}", actors: ["admin"] },
  { method: "get", path: "/_utils", actors: ["admin"] },
  { method: "get", path: "/_utils/:rest{.*}", actors: ["admin"] },

  // —— Database-level ——
  { method: "get", path: "/:db", actors: ["db", "pipe"] },
  { method: "head", path: "/:db", actors: ["db", "pipe"] },
  { method: "put", path: "/:db", actors: ["admin"] },
  { method: "delete", path: "/:db", actors: ["admin"] },
  { method: "post", path: "/:db", actors: ["db", "docWrite", "pipe"] },

  { method: "get", path: "/:db/_all_docs", actors: ["db", "rows"] },
  { method: "post", path: "/:db/_all_docs", actors: ["db", "rows"] },
  { method: "get", path: "/:db/_design_docs", actors: ["db", "rows"] },
  { method: "post", path: "/:db/_design_docs", actors: ["db", "rows"] },
  { method: "get", path: "/:db/_local_docs", actors: ["db", "rows"] },
  { method: "post", path: "/:db/_local_docs", actors: ["db", "rows"] },
  { method: "post", path: "/:db/_bulk_docs", actors: ["db", "bulk"] },
  { method: "post", path: "/:db/_bulk_get", actors: ["db", "bulkGet"] },
  { method: "get", path: "/:db/_changes", actors: ["db", "changes"] },
  { method: "post", path: "/:db/_changes", actors: ["db", "changes"] },
  { method: "post", path: "/:db/_find", actors: ["db", "find"] },
  { method: "post", path: "/:db/_index", actors: ["db", "indexAdmin"] },
  { method: "get", path: "/:db/_index", actors: ["db", "indexAdmin"] },
  { method: "delete", path: "/:db/_index/:ddoc/json/:name", actors: ["db", "indexAdmin"] },
  // `_explain` can leak index/selector metadata — admin only.
  { method: "post", path: "/:db/_explain", actors: ["db", "indexAdmin"] },
  { method: "post", path: "/:db/_revs_diff", actors: ["db", "revs"] },
  { method: "post", path: "/:db/_missing_revs", actors: ["db", "revs"] },

  { method: "get", path: "/:db/_security", actors: ["admin"] },
  { method: "put", path: "/:db/_security", actors: ["admin"] },
  { method: "get", path: "/:db/_revs_limit", actors: ["admin"] },
  { method: "put", path: "/:db/_revs_limit", actors: ["admin"] },
  { method: "post", path: "/:db/_compact", actors: ["admin"] },
  { method: "post", path: "/:db/_compact/:ddoc", actors: ["admin"] },
  { method: "post", path: "/:db/_view_cleanup", actors: ["admin"] },
  { method: "post", path: "/:db/_purge", actors: ["admin"] },
  { method: "post", path: "/:db/_ensure_full_commit", actors: ["admin"] },

  // —— Partitioned DB APIs — list/query surfaces filtered; other partition paths admin ——
  { method: "get", path: "/:db/_partition/:partition", actors: ["admin"] },
  {
    method: "get",
    path: "/:db/_partition/:partition/_all_docs",
    actors: ["db", "rows"],
  },
  {
    method: "post",
    path: "/:db/_partition/:partition/_all_docs",
    actors: ["db", "rows"],
  },
  {
    method: "post",
    path: "/:db/_partition/:partition/_find",
    actors: ["db", "find"],
  },
  {
    method: "get",
    path: "/:db/_partition/:partition/_design/:ddoc/_view/:view",
    actors: ["db", "rows"],
  },
  {
    method: "post",
    path: "/:db/_partition/:partition/_design/:ddoc/_view/:view",
    actors: ["db", "rows"],
  },
  {
    method: "get",
    path: "/:db/_partition/:partition/:rest{.*}",
    actors: ["admin"],
  },
  {
    method: "post",
    path: "/:db/_partition/:partition/:rest{.*}",
    actors: ["admin"],
  },

  // —— Design docs / views ——
  // Search/Nouveau results can embed hits without ACL rows — admin only.
  { method: "get", path: "/:db/_design/:ddoc/_search/:index", actors: ["admin"] },
  { method: "post", path: "/:db/_design/:ddoc/_search/:index", actors: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_search_info/:index", actors: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_nouveau/:index", actors: ["admin"] },
  { method: "post", path: "/:db/_design/:ddoc/_nouveau/:index", actors: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_nouveau_info/:index", actors: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_view/:view", actors: ["db", "rows"] },
  { method: "post", path: "/:db/_design/:ddoc/_view/:view", actors: ["db", "rows"] },
  { method: "get", path: "/:db/_design/:ddoc/_list/:list/:view", actors: ["list501"] },
  { method: "post", path: "/:db/_design/:ddoc/_list/:list/:view", actors: ["list501"] },
  { method: "get", path: "/:db/_design/:ddoc/_list/:list/:ddoc2/:view", actors: ["list501"] },
  { method: "post", path: "/:db/_design/:ddoc/_list/:list/:ddoc2/:view", actors: ["list501"] },
  // Show/update without a target doc can emit or mutate arbitrarily — reject.
  { method: "get", path: "/:db/_design/:ddoc/_show/:show", actors: ["unsupported"] },
  { method: "post", path: "/:db/_design/:ddoc/_show/:show", actors: ["unsupported"] },
  { method: "get", path: "/:db/_design/:ddoc/_show/:show/:docId", actors: ["db", "doc", "pipe"] },
  { method: "post", path: "/:db/_design/:ddoc/_show/:show/:docId", actors: ["db", "doc", "pipe"] },
  { method: "post", path: "/:db/_design/:ddoc/_update/:update", actors: ["unsupported"] },
  {
    method: "post",
    path: "/:db/_design/:ddoc/_update/:update/:docId",
    actors: ["db", "docUpdate", "pipe"],
  },
  {
    method: "put",
    path: "/:db/_design/:ddoc/_update/:update/:docId",
    actors: ["db", "docUpdate", "pipe"],
  },
  { method: "get", path: "/:db/_design/:ddoc/_info", actors: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_rewrite", actors: ["admin"] },
  { method: "post", path: "/:db/_design/:ddoc/_rewrite", actors: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_rewrite/:rest{.*}", actors: ["admin"] },
  { method: "post", path: "/:db/_design/:ddoc/_rewrite/:rest{.*}", actors: ["admin"] },

  // Reserved design API roots are never interpreted as attachment names.
  { method: "get", path: "/:db/_design/:ddoc/_view", actors: ["unsupported"] },
  { method: "get", path: "/:db/_design/:ddoc/_list", actors: ["list501"] },
  { method: "get", path: "/:db/_design/:ddoc/_show", actors: ["unsupported"] },
  { method: "get", path: "/:db/_design/:ddoc/_update", actors: ["unsupported"] },
  { method: "get", path: "/:db/_design/:ddoc/_search", actors: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_search_info", actors: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_nouveau", actors: ["admin"] },
  { method: "get", path: "/:db/_design/:ddoc/_nouveau_info", actors: ["admin"] },

  { method: "get", path: "/:db/_design/:ddoc", actors: ["db", "doc", "pipe"] },
  { method: "head", path: "/:db/_design/:ddoc", actors: ["db", "doc", "pipe"] },
  { method: "put", path: "/:db/_design/:ddoc", actors: ["db", "docWrite", "pipe"] },
  { method: "delete", path: "/:db/_design/:ddoc", actors: ["db", "docDelete", "pipe"] },
  { method: "copy", path: "/:db/_design/:ddoc", actors: ["db", "copy"] },
  { method: "get", path: "/:db/_design/:ddoc/:attachment{.+}", actors: ["db", "doc", "pipe"] },
  { method: "head", path: "/:db/_design/:ddoc/:attachment{.+}", actors: ["db", "doc", "pipe"] },
  { method: "put", path: "/:db/_design/:ddoc/:attachment{.+}", actors: ["db", "docWrite", "pipe"] },
  {
    method: "delete",
    path: "/:db/_design/:ddoc/:attachment{.+}",
    actors: ["db", "docDelete", "pipe"],
  },

  // —— Local docs — pipe after DB gate (Pouch checkpoints; no per-doc ACL rows) ——
  { method: "get", path: "/:db/_local/:docId", actors: ["db", "pipe"] },
  { method: "put", path: "/:db/_local/:docId", actors: ["db", "pipe"] },
  { method: "delete", path: "/:db/_local/:docId", actors: ["db", "pipe"] },

  // —— Regular docs + attachments + COPY ——
  { method: "get", path: "/:db/:docId", actors: ["db", "doc", "pipe"] },
  { method: "head", path: "/:db/:docId", actors: ["db", "doc", "pipe"] },
  { method: "put", path: "/:db/:docId", actors: ["db", "docWrite", "pipe"] },
  { method: "delete", path: "/:db/:docId", actors: ["db", "docDelete", "pipe"] },
  { method: "copy", path: "/:db/:docId", actors: ["db", "copy"] },
  { method: "get", path: "/:db/:docId/:attachment{.+}", actors: ["db", "doc", "pipe"] },
  { method: "head", path: "/:db/:docId/:attachment{.+}", actors: ["db", "doc", "pipe"] },
  { method: "put", path: "/:db/:docId/:attachment{.+}", actors: ["db", "docWrite", "pipe"] },
  {
    method: "delete",
    path: "/:db/:docId/:attachment{.+}",
    actors: ["db", "docDelete", "pipe"],
  },
];
