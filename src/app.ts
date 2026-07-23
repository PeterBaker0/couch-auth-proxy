/**
 * Hono application factory for couch-auth-proxy.
 *
 * Wires middleware (services, logging, rate limit, body limit, CORS, principal),
 * couch-auth-proxy-specific health/ready probes, and the declarative CouchDB route map.
 * Business ACL logic lives in `routes/actors` and `acl/*`; this module only
 * composes the HTTP surface.
 */
import { Hono } from "hono";
import { cors } from "hono/cors";
import { HTTPException } from "hono/http-exception";
import type { AppConfig } from "./config.js";
import { AclCache, AclUnavailableError } from "./acl/cache.js";
import { SessionResolver } from "./auth/session.js";
import { withPrincipal, withServices, type AppEnv } from "./middleware/context.js";
import { rateLimit } from "./middleware/rateLimit.js";
import { requestLog } from "./middleware/requestLog.js";
import { bodyLimit } from "./middleware/bodyLimit.js";
import { registerRoutes } from "./routes/register.js";
import { jsonResponse } from "./proxy/forward.js";

/** Long-lived dependencies shared across all requests. */
export type AppServices = {
  config: AppConfig;
  sessions: SessionResolver;
  aclCache: AclCache;
};

/** Construct session resolver + ACL cache from validated config. */
export function createServices(config: AppConfig): AppServices {
  return {
    config,
    sessions: new SessionResolver(config),
    aclCache: new AclCache(config),
  };
}

/**
 * couch-auth-proxy HTTP app — ACL reverse proxy for CouchDB 3.5+.
 *
 * Request pipeline order (matches product intent):
 * 1. Inject services → 2. request log → 3. rate limit → 4. body CL check
 * → 5. CORS → 6. resolve principal → 7. restmap actors / catch-all.
 */
export function createApp(services: AppServices): Hono<AppEnv> {
  // strict:false → `/db/` matches `/db` (PouchDB always uses trailing slash)
  const app = new Hono<AppEnv>({ strict: false });

  app.use("*", withServices(services));
  app.use("*", requestLog());
  app.use("*", rateLimit());
  app.use("*", bodyLimit());

  app.use(
    "*",
    cors({
      origin: (origin) => {
        const allowed = services.config.cors.origins;
        // Empty allowlist: do not reflect Origin (same-origin / non-CORS only).
        if (!allowed.length) return "";
        if (!origin) return "";
        return allowed.includes(origin) ? origin : "";
      },
      credentials: services.config.cors.allowCredentials,
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "COPY"],
      allowHeaders: [
        "Content-Type",
        "Authorization",
        "Accept",
        "Destination",
        "If-Match",
        "If-None-Match",
        "Range",
        "Content-Range",
        "X-Couch-Full-Commit",
      ],
      exposeHeaders: [
        "Content-Type",
        "Content-Range",
        "Accept-Ranges",
        "Server",
        "ETag",
        "Location",
        "X-Couch-Id",
        "X-Couch-Request-ID",
        "X-Request-Id",
      ],
      maxAge: 86400,
    }),
  );

  app.use("*", withPrincipal());

  /** Liveness: process is up. Body is intentionally non-sensitive. */
  app.get("/_couch-auth-proxy/health", () => jsonResponse({ ok: true }));

  /**
   * Readiness: Couch reachable and preloaded ACL caches healthy.
   * Body is intentionally non-sensitive (`{ ok }` only); details stay in logs.
   * Ad-hoc DBs do not flap the probe when ensure fails.
   */
  app.get("/_couch-auth-proxy/ready", async (c) => {
    const cache = c.get("aclCache");
    const config = c.get("config");
    const couchOk = await cache.adminClient.ping();
    const states = [...cache.all()];
    const preload = config.couch.preloadDbs;
    // Gate on preloaded DBs (ops-critical). One-off ensures must not flap readiness.
    const critical = preload.length
      ? preload.map((name) => states.find((s) => s.name === name)).filter(Boolean)
      : states.filter((s) => s.ready || (!!s.error && !s.missing));
    const criticalReady = critical.every(
      (s) => s && s.ready && !s.error && (s.noacl || s.followerUp),
    );
    const ready = couchOk && criticalReady;
    return jsonResponse({ ok: ready }, ready ? 200 : 503);
  });

  registerRoutes(app);

  // Keyed ACL view failures may happen after the DB gate. Keep their response
  // fail-closed and Couch-shaped instead of exposing a generic Hono 500.
  app.onError((err) => {
    if (err instanceof AclUnavailableError) {
      return jsonResponse({ error: "service_unavailable", reason: "ACL cache unavailable" }, 503);
    }
    if (err instanceof HTTPException) return err.getResponse();
    return jsonResponse({ error: "internal_server_error", reason: "Internal server error" }, 500);
  });

  return app;
}
