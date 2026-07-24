/**
 * Hono context wiring: shared services and per-request principal.
 *
 * `AppEnv` types the Variables bag used throughout actors and middleware.
 * `withServices` runs first; `withPrincipal` runs after CORS so identity is
 * available to all restmap actors.
 */
import { createMiddleware } from "hono/factory";
import type { AppConfig } from "../config.js";
import type { AclCache, DbAclState } from "../acl/cache.js";
import type { SessionResolver } from "../auth/session.js";
import type { Principal } from "../auth/types.js";
import { createLogger, isLevelEnabled } from "../util/log.js";

const log = createLogger("context");

/** Hono env typing for couch-auth-proxy request Variables. */
export type AppEnv = {
  Variables: {
    config: AppConfig;
    sessions: SessionResolver;
    aclCache: AclCache;
    principal: Principal;
    /** Set by the `db` actor once ACL state is ready for this request. */
    dbAclState?: DbAclState;
  };
};

/** Inject config / session resolver / ACL cache into every request. */
export function withServices(deps: {
  config: AppConfig;
  sessions: SessionResolver;
  aclCache: AclCache;
}) {
  return createMiddleware<AppEnv>(async (c, next) => {
    c.set("config", deps.config);
    c.set("sessions", deps.sessions);
    c.set("aclCache", deps.aclCache);
    await next();
  });
}

/** Resolve and attach the caller's `Principal` (anonymous if unauthenticated). */
export function withPrincipal() {
  return createMiddleware<AppEnv>(async (c, next) => {
    const sessions = c.get("sessions");
    const principal = await sessions.resolve(c.req.raw.headers);
    c.set("principal", principal);
    if (isLevelEnabled("verbose")) {
      log.verbose("principal attached", {
        method: c.req.method,
        path: c.req.path,
        user: principal.name,
        admin: principal.admin,
        aclTokenCount: principal.aclTokens.length,
      });
    }
    await next();
  });
}
