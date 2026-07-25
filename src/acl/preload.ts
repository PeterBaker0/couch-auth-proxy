/**
 * Resolve the set of databases to warm at process boot.
 *
 * Operators may name DBs explicitly (`COUCH_PRELOAD_DBS`) and/or select them
 * via patterns against Couch `GET /_all_dbs` (`COUCH_PRELOAD_DB_INCLUDE`).
 * When both are set, the preload set is their **union**. Empty/unset keeps
 * historical lazy ensure-on-first-request behaviour.
 *
 * Guards:
 * - System DBs (`_users`, `_replicator`, `_global_changes`) never come from
 *   the include patterns (explicit names still warm as noacl pass-through).
 * - `ACL_DB_INCLUDE` / `ACL_DB_EXCLUDE` still apply so preload cannot widen
 *   ACL install beyond the intended DB scope.
 */
import type { AppConfig } from "../config.js";
import type { AdminClient } from "../couch/adminClient.js";
import { allowedByIncludeExclude, compileMatchList, matchListHits } from "./matchList.js";
import { isDatabaseName, isSystemDatabase } from "./names.js";

/**
 * Build the ordered preload DB list from config + live `/_all_dbs`.
 *
 * Throws when `COUCH_PRELOAD_DB_INCLUDE` is set and `/_all_dbs` fails — boot
 * should fail closed rather than silently skip warm-up.
 */
export async function resolvePreloadDbs(admin: AdminClient, config: AppConfig): Promise<string[]> {
  const explicit = config.couch.preloadDbs;
  const includeEntries = config.couch.preloadDbInclude;
  const names = new Set<string>(explicit);

  if (includeEntries.length) {
    const listed = await admin.json<string[]>("/_all_dbs");
    if (!listed.ok) {
      throw new Error(`COUCH_PRELOAD_DB_INCLUDE: GET /_all_dbs failed (${listed.status})`);
    }
    const include = compileMatchList(includeEntries);
    for (const db of listed.body) {
      if (!isDatabaseName(db) || isSystemDatabase(db)) continue;
      if (matchListHits(include, db)) names.add(db);
    }
  }

  const aclInclude = compileMatchList(config.access.dbInclude);
  const aclExclude = compileMatchList(config.access.dbExclude);
  const scoped = [...names].filter((db) => allowedByIncludeExclude(aclInclude, aclExclude, db));

  return scoped.sort((a, b) => a.localeCompare(b));
}
